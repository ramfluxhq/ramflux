// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Sequential bounded event application with write-ahead output and durable cursor recovery.
use crate::checkpoint::Pending;
use crate::{
    AgentBus, Checkpoint, CheckpointStore, Config, ConversationInput, EngineEvent, EngineInput,
    EngineProvider, Error, Intent, Result, participant,
};
use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
use serde_json::json;

pub struct AgentHost<E> {
    pub(crate) config: Config,
    pub(crate) engine: E,
    pub(crate) store: CheckpointStore,
    pub(crate) state: Checkpoint,
}
struct IntentDelivery<'a> {
    conversation_id: &'a str,
    message_id: &'a str,
    intents: Vec<Intent>,
    seq: u64,
    now_ms: u64,
}
impl<E: EngineProvider> AgentHost<E> {
    /// # Errors
    /// Rejects invalid configuration, corrupt state or exhausted persisted bounds.
    pub fn new(config: Config, mut engine: E) -> Result<Self> {
        config.validate()?;
        let store = CheckpointStore::new(config.state_file.clone())?;
        let state = store.load()?;
        engine.restore(state.engine.as_ref())?;
        if !crate::runner_deferred::valid(&state)
            || !crate::runner_approval::valid(&state)
            || state.handled_actions.len() > 2048
            || state.pending.as_ref().is_some_and(|p| {
                !matches!(
                    p.method.as_str(),
                    "message.submit" | "group.send" | "surface.send" | "surface.resync"
                ) || p.remaining.len() > 95
                    || p.remaining.iter().any(|o| {
                        !matches!(o.method.as_str(), "surface.send" | "message.submit")
                            || o.body["conversation_id"] != p.conversation_id
                    })
                    || p.body["conversation_id"] != p.conversation_id
            })
        {
            return Err(Error::State);
        }
        Ok(Self { config, engine, store, state })
    }
    pub(crate) fn save_state(&mut self) -> Result<()> {
        self.state.engine = self.engine.checkpoint()?;
        self.store.save(&self.state)
    }
    pub(crate) fn save_engine_state_if_changed(&mut self) -> Result<()> {
        let engine = self.engine.checkpoint()?;
        if self.state.engine != engine {
            self.state.engine = engine;
            self.store.save(&self.state)?;
        }
        Ok(())
    }
    #[must_use]
    pub const fn checkpoint(&self) -> &Checkpoint {
        &self.state
    }

    /// Bind the headless identity and replay from the last durably applied cursor.
    /// # Errors
    /// Rejects revoked/human accounts, unavailable snapshots, stream gaps and state I/O failures.
    pub async fn start(&mut self, bus: &mut impl AgentBus) -> Result<()> {
        participant::identity(bus, &mut self.state, &self.config.account_id).await?;
        self.normalize_deferred()?;
        let topics = json!([
            "message.received",
            "group.message.received",
            "conversation.changed",
            "group.changed",
            "device.changed",
            "identity.device_branch.revoked",
            "surface.changed",
            "task.changed",
            "account.locked"
        ]);
        let subscription = bus
            .request("bus.subscribe", json!({"topics":topics,"since_seq":self.state.cursor}), None)
            .await;
        let ack = match subscription {
            Ok(ack) => ack,
            Err(Error::Resync) => {
                // Unavailable history is not replayed as commands. Reload current authorization,
                // capture a fresh head and tail from it; pending output is recovered separately.
                self.state.cursor = None;
                bus.request("bus.subscribe", json!({"topics":topics}), None).await?
            }
            Err(error) => return Err(error),
        };
        if self.state.cursor.is_none() {
            self.state.cursor = Some(ack["head_seq"].as_u64().ok_or(Error::State)?);
        }
        participant::snapshot(bus, "conversation.directory", "conversations").await?;
        participant::snapshot(bus, "group.list", "groups").await?;
        self.save_state()?;
        self.recover_pending(bus).await
    }

    /// Process one event. Sequence jumps are legal because the subscription filters topics.
    /// # Errors
    /// Rejects stream lag, foreign frames, invalid provider outputs, or failed durable delivery.
    pub async fn apply(
        &mut self,
        bus: &mut impl AgentBus,
        event: LocalBusFrame,
        now_ms: u64,
    ) -> Result<()> {
        if event.kind == LocalBusFrameKind::Event && event.method == "stream.lagged" {
            return Err(Error::Resync);
        }
        if event.account_id.as_deref() != Some(&self.config.account_id)
            || event.kind != LocalBusFrameKind::Event
        {
            eprintln!("agent host ignored an unscoped or non-event frame");
            return Ok(());
        }
        let Some(seq) = event.seq else {
            eprintln!("agent host ignored an event without a sequence");
            return Ok(());
        };
        if self.state.cursor.is_some_and(|cursor| seq <= cursor) {
            return Ok(());
        }
        if event.method == "account.locked"
            || event.method == "identity.device_branch.revoked"
                && event.body["device_id"] == self.state.device_id
        {
            for conversation_id in self.engine.active_conversations() {
                self.engine.cancel(&conversation_id).await?;
            }
            self.state.approvals.clear();
            self.save_state()?;
            return Err(Error::IdentityLost);
        }
        self.prune_rate_history(now_ms);
        let result = self.apply_event(bus, &event, seq, now_ms).await;
        self.finish_event(result, &event, seq)
    }
    async fn apply_event(
        &mut self,
        bus: &mut impl AgentBus,
        event: &LocalBusFrame,
        seq: u64,
        now_ms: u64,
    ) -> Result<()> {
        if self.state.pending.is_some() {
            self.recover_pending(bus).await?;
            if self.state.cursor.is_some_and(|cursor| seq <= cursor) {
                return Ok(());
            }
        }
        if matches!(event.method.as_str(), "device.changed" | "identity.device_branch.revoked") {
            participant::identity(bus, &mut self.state, &self.config.account_id).await?;
        }
        if matches!(event.method.as_str(), "message.received" | "group.message.received") {
            self.message(bus, event, seq, now_ms).await?;
        }
        if event.method == "surface.changed" {
            self.surface_action(bus, event, seq, now_ms).await?;
        }
        if matches!(event.method.as_str(), "conversation.changed" | "group.changed") {
            self.cancel_removed_conversations(bus).await?;
        }
        self.state.cursor = Some(seq);
        self.save_state()
    }
    fn is_own_message(&self, message: &serde_json::Value) -> bool {
        message["sender_id"] == self.state.device_id
            || message["sender_id"] == self.state.principal_id
    }
    async fn message(
        &mut self,
        bus: &mut impl AgentBus,
        event: &LocalBusFrame,
        seq: u64,
        now_ms: u64,
    ) -> Result<()> {
        let metadata = &event.body["message"];
        let conversation_id = participant::field(metadata, "conversation_id")?;
        let message_id = participant::field(metadata, "message_id")?;
        if self.is_own_message(metadata) || metadata["deleted"] == true {
            return Ok(());
        }
        participant::identity(bus, &mut self.state, &self.config.account_id).await?;
        let Some(conversation) = participant::conversation(
            bus,
            &self.state,
            conversation_id,
            self.config.max_conversations,
        )
        .await?
        else {
            return Ok(());
        };
        if self.state.last_reply_ms.get(conversation_id).is_some_and(|last| {
            now_ms < last.saturating_add(self.config.per_conversation_interval_ms)
        }) {
            return Err(Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::RateLimited));
        }
        if !self.rate_history_has_capacity(conversation_id) {
            return Err(Error::Limit);
        }
        let read =
            bus.request("message.read", json!({"conversation_id":conversation_id}), None).await?;
        let Some(message) = read["messages"]
            .as_array()
            .and_then(|rows| rows.iter().find(|m| m["message_id"] == message_id))
        else {
            return Ok(());
        };
        if message["deleted"] == true || self.is_own_message(message) {
            return Ok(());
        }
        let Some(text) =
            message["body_utf8"].as_str().filter(|t| t.len() <= crate::config::MAX_TEXT_BYTES)
        else {
            return Ok(());
        };
        let sender_display_name = participant::sender_display_name(bus, message).await?;
        let chat_kind = if conversation["group_id"].is_string() { "group" } else { "direct" };
        let mentioned = message["mentioned"].as_bool().unwrap_or(false);
        let events = self
            .engine
            .submit(
                EngineInput {
                    conversation: ConversationInput { conversation_id, message_id, text },
                    sender_display_name: &sender_display_name,
                    chat_kind,
                    mentioned,
                },
                now_ms,
            )
            .await?;
        self.save_state()?;
        self.handle_engine_events(bus, events, seq, now_ms).await
    }

    pub(crate) async fn handle_engine_events(
        &mut self,
        bus: &mut impl AgentBus,
        events: Vec<EngineEvent>,
        seq: u64,
        now_ms: u64,
    ) -> Result<()> {
        for event in events {
            let acknowledged = event.clone();
            match event {
                EngineEvent::Intents { conversation_id, message_id, intents } => {
                    if intents.is_empty() {
                        self.state.last_reply_ms.insert(conversation_id.clone(), now_ms);
                    } else {
                        self.emit_intents(
                            bus,
                            IntentDelivery {
                                conversation_id: &conversation_id,
                                message_id: &message_id,
                                intents,
                                seq,
                                now_ms,
                            },
                        )
                        .await?;
                    }
                    self.complete_resumed_task(bus, &conversation_id, true).await?;
                }
                EngineEvent::VisibleFailure { conversation_id, message_id } => {
                    self.emit_intents(
                        bus,
                        IntentDelivery {
                            conversation_id: &conversation_id,
                            message_id: &message_id,
                            intents: vec![Intent::ReplyText(
                                "The agent engine could not complete this request.".into(),
                            )],
                            seq,
                            now_ms,
                        },
                    )
                    .await?;
                    self.complete_resumed_task(bus, &conversation_id, false).await?;
                }
                EngineEvent::ApprovalRequired {
                    conversation_id,
                    message_id,
                    decision_id,
                    pending_tool,
                } => {
                    self.complete_resumed_task(bus, &conversation_id, true).await?;
                    let started = self
                        .start_approval(
                            bus,
                            crate::runner_approval::ApprovalRequest {
                                conversation_id,
                                message_id,
                                decision_id,
                                pending_tool,
                                now_ms,
                            },
                        )
                        .await?;
                    if !started {
                        let EngineEvent::ApprovalRequired { conversation_id, message_id, .. } =
                            &acknowledged
                        else {
                            return Err(Error::State);
                        };
                        self.emit_intents(
                            bus,
                            IntentDelivery {
                                conversation_id,
                                message_id,
                                intents: vec![Intent::ReplyText(
                                    "A fresh human approval is required; the operation was not run."
                                        .into(),
                                )],
                                seq,
                                now_ms,
                            },
                        )
                        .await?;
                    }
                }
            }
            self.engine.acknowledge(&acknowledged)?;
            self.save_state()?;
        }
        Ok(())
    }

    async fn cancel_removed_conversations(&mut self, bus: &mut impl AgentBus) -> Result<()> {
        let conversations = self.engine.active_conversations();
        for conversation_id in conversations {
            if participant::conversation(
                bus,
                &self.state,
                &conversation_id,
                self.config.max_conversations,
            )
            .await?
            .is_none()
            {
                self.engine.cancel(&conversation_id).await?;
                self.state.approvals.remove(&conversation_id);
            }
        }
        self.save_state()
    }

    async fn emit_intents(
        &mut self,
        bus: &mut impl AgentBus,
        delivery: IntentDelivery<'_>,
    ) -> Result<()> {
        let IntentDelivery { conversation_id, message_id, intents, seq, now_ms } = delivery;
        participant::identity(bus, &mut self.state, &self.config.account_id).await?;
        let Some(conversation) = participant::conversation(
            bus,
            &self.state,
            conversation_id,
            self.config.max_conversations,
        )
        .await?
        else {
            self.engine.cancel(conversation_id).await?;
            return self.save_state();
        };
        let read =
            bus.request("message.read", json!({"conversation_id":conversation_id}), None).await?;
        let Some(message) = read["messages"]
            .as_array()
            .and_then(|rows| rows.iter().find(|message| message["message_id"] == message_id))
        else {
            return Ok(());
        };
        if message["deleted"] == true || self.is_own_message(message) {
            return Ok(());
        }
        let plan = if matches!(intents.first(), Some(Intent::CreateSurface(_))) {
            match crate::surface_plan::SurfacePlan::new(conversation_id, &intents) {
                Ok(plan) => Some(plan),
                Err(Error::SurfaceRefused(reason)) => {
                    self.state.last_refusal = Some(crate::OutputRefusal {
                        group_reason: None,
                        conversation_id: conversation_id.into(),
                        surface_id: intents
                            .first()
                            .and_then(Intent::command)
                            .map(|command| crate::runner_output::command_id(&command).to_owned()),
                        reason,
                    });
                    self.state.last_reply_ms.insert(conversation_id.into(), now_ms);
                    return self.store.save(&self.state);
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let mut outputs = if let [Intent::ReplyText(text)] = intents.as_slice() {
            if text.is_empty() || text.len() > crate::config::MAX_TEXT_BYTES {
                return Err(Error::Limit);
            }
            participant::reply_outputs(bus, &self.state, &conversation, message, text, 0).await?
        } else {
            if !matches!(intents.first(), Some(Intent::CreateSurface(_))) {
                return Err(Error::State);
            }
            crate::runner_output::surface_outputs(conversation_id, &intents, 1)?
        };
        if serde_json::to_vec(&outputs).map_err(|_| Error::State)?.len() > 262_144 {
            return Err(Error::Limit);
        }
        let first = outputs.remove(0);
        self.state.pending = Some(Pending {
            seq,
            conversation_id: conversation_id.into(),
            method: first.method,
            operation_id: first.operation_id,
            body: first.body,
            remaining: outputs,
            action: None,
            plan,
            needs_rederive: None,
        });
        self.state.last_reply_ms.insert(conversation_id.into(), now_ms);
        self.save_state()?;
        self.recover_pending(bus).await?;
        Ok(())
    }
    /// Receive metadata events and periodically ask rfd to drain its authenticated inbox.
    /// # Errors
    /// Returns on stream loss/revocation so the caller can reconnect or stop without acting.
    pub async fn run(&mut self, bus: &mut impl AgentBus) -> Result<()> {
        let mut tick =
            tokio::time::interval(std::time::Duration::from_millis(self.config.poll_interval_ms));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate interval tick; ordinary events can arrive before the first poll.
        tick.tick().await;
        loop {
            tokio::select! {
                event=bus.next_event()=>self.apply(bus,event?,crate::bus::now_ms()).await?,
                _=tick.tick()=>self.poll(bus, crate::bus::now_ms()).await?,
            }
        }
    }
}
