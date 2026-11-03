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
    pub(crate) store: std::sync::Arc<CheckpointStore>,
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
        let store = std::sync::Arc::new(CheckpointStore::new(config.state_file.clone())?);
        let mut state = store.load()?;
        if let Some(engine) = &config.engine {
            let maximum = crate::bus::now_ms()
                .saturating_add(engine.approval_timeout_s().saturating_mul(1000));
            for bridge in state.approvals.values_mut() {
                bridge.deadline_ms = bridge.deadline_ms.min(maximum);
            }
        }
        engine.restore(state.engine.as_ref())?;
        state.engine = engine.checkpoint()?;
        if !crate::runner_deferred::valid(&state)
            || !crate::runner_approval::valid(&state)
            || state.visible_failures.len() > 64
            || state.visible_failures.values().any(|f| {
                f.conversation_id.is_empty()
                    || f.conversation_id.len() > 1024
                    || f.message_id.is_empty()
                    || f.message_id.len() > 1024
            })
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
        self.store.save(&self.state)?;
        self.engine.persisted()
    }
    pub(crate) fn save_engine_state_if_changed(&mut self) -> Result<()> {
        let engine = self.engine.checkpoint()?;
        if self.state.engine != engine {
            self.state.engine = engine;
            self.store.save(&self.state)?;
        }
        self.engine.persisted()
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
            "message.updated",
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
        self.recover_pending(bus).await?;
        self.recover_visible_failures(bus, crate::bus::now_ms()).await
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
            if let Some(bridge) = self.engine.bridge() {
                bridge.offline(now_ms);
            } else {
                for conversation_id in self.engine.active_conversations() {
                    self.engine.revoke(&conversation_id).await?;
                }
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
        let deletion = self.engine.bridge().is_some()
            && event.method == "message.updated"
            && (event.body["message"]["deleted"] == true
                || event.body["message"]["removed"] == true);
        if deletion {
            self.bridge_update(bus, event, now_ms).await?;
        }
        if self.state.pending.is_some() {
            self.recover_pending(bus).await?;
            if self.state.cursor.is_some_and(|cursor| seq <= cursor) {
                return Ok(());
            }
        }
        if !deletion {
            self.bridge_update(bus, event, now_ms).await?;
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
        if !self.engine.is_busy(conversation_id)
            && self.state.last_reply_ms.get(conversation_id).is_some_and(|last| {
                now_ms < last.saturating_add(self.config.per_conversation_interval_ms)
            })
        {
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
        let sender_display_name = match self.prepare_bridge(bus, &conversation, message).await? {
            Some(name) => name,
            None => participant::sender_display_name(bus, message).await?,
        };
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
                EngineEvent::BridgeWork { .. } => {
                    self.bridge_work(bus).await?;
                    continue;
                }
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
                EngineEvent::VisibleFailure { .. } => {
                    self.emit_engine_failure(bus, &acknowledged, seq, now_ms).await?;
                }
                EngineEvent::ApprovalRequired {
                    conversation_id,
                    message_id,
                    decision_id,
                    approval,
                } => {
                    let start = async {
                        self.complete_resumed_task(bus, &conversation_id, true).await?;
                        self.start_approval(
                            bus,
                            crate::runner_approval::ApprovalRequest {
                                conversation_id,
                                message_id,
                                decision_id,
                                approval,
                                now_ms,
                            },
                        )
                        .await
                    }
                    .await;
                    let started = match start {
                        Ok(started) => started,
                        Err(error) if error.stops_host() => return Err(error),
                        Err(_) => {
                            self.refuse_approval_event(bus, &acknowledged, seq, now_ms).await?;
                            continue;
                        }
                    };
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

    async fn refuse_approval_event(
        &mut self,
        bus: &mut impl AgentBus,
        event: &EngineEvent,
        seq: u64,
        now_ms: u64,
    ) -> Result<()> {
        let EngineEvent::ApprovalRequired { conversation_id, message_id, decision_id, .. } = event
        else {
            return Err(Error::State);
        };
        let failure =
            self.abandon_approval(conversation_id, message_id, decision_id, now_ms).await?;
        // Persist retirement before any output RPC can fail or require reconnect.
        self.engine.acknowledge(event)?;
        self.save_state()?;
        self.emit_engine_failure(bus, &failure, seq, now_ms).await
    }

    async fn emit_engine_failure(
        &mut self,
        bus: &mut impl AgentBus,
        event: &EngineEvent,
        seq: u64,
        now_ms: u64,
    ) -> Result<()> {
        let EngineEvent::VisibleFailure { conversation_id, message_id, reason } = event else {
            return Err(Error::State);
        };
        let notice_key = ramflux_protocol::hash_base64url(
            "ramflux.agent.visible_failure.v1",
            &ramflux_protocol::canonical_json_bytes(&(conversation_id, message_id, reason.reply()))
                .map_err(|_| Error::State)?,
        );
        if !self.state.visible_failures.contains_key(&notice_key)
            && self.state.visible_failures.len() >= 64
        {
            return Err(Error::Bus);
        }
        self.state.visible_failures.insert(
            notice_key.clone(),
            crate::checkpoint::VisibleFailure {
                conversation_id: conversation_id.clone(),
                message_id: message_id.clone(),
                reason: reason.clone(),
            },
        );
        self.save_state()?;
        self.emit_intents(
            bus,
            IntentDelivery {
                conversation_id,
                message_id,
                intents: vec![Intent::ReplyText(reason.reply().into())],
                seq,
                now_ms,
            },
        )
        .await?;
        self.state.visible_failures.remove(&notice_key);
        self.save_state()?;
        if *reason != crate::EngineFailure::Busy {
            self.complete_resumed_task(bus, conversation_id, false).await?;
        }
        Ok(())
    }

    pub(crate) async fn recover_visible_failures(
        &mut self,
        bus: &mut impl AgentBus,
        now_ms: u64,
    ) -> Result<()> {
        let notices = self
            .state
            .visible_failures
            .iter()
            .map(|(k, f)| (k.clone(), f.clone()))
            .collect::<Vec<_>>();
        for (key, failure) in notices {
            self.emit_intents(
                bus,
                IntentDelivery {
                    conversation_id: &failure.conversation_id,
                    message_id: &failure.message_id,
                    intents: vec![Intent::ReplyText(failure.reason.reply().into())],
                    seq: self.state.cursor.unwrap_or(0),
                    now_ms,
                },
            )
            .await?;
            self.state.visible_failures.remove(&key);
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
                self.engine.revoke(&conversation_id).await?;
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
            self.engine.revoke(conversation_id).await?;
            self.state.approvals.remove(conversation_id);
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
        enum Ready {
            Event(Box<Result<LocalBusFrame>>),
            Tick,
            Engine,
            Maintenance,
        }

        let mut tick =
            tokio::time::interval(std::time::Duration::from_millis(self.config.poll_interval_ms));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate interval tick; ordinary events can arrive before the first poll.
        tick.tick().await;
        let bridge = self.engine.bridge().is_some();
        let mut maintenance = tokio::time::interval(std::time::Duration::from_millis(100));
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        maintenance.tick().await;
        loop {
            let ready = tokio::select! {
                event=bus.next_event()=>Ready::Event(Box::new(event)),
                _=tick.tick()=>Ready::Tick,
                ()=self.engine.wake()=>Ready::Engine,
                _=maintenance.tick(), if bridge=>Ready::Maintenance,
            };
            match ready {
                Ready::Event(event) => {
                    let now = bus.now_ms();
                    self.apply(bus, (*event)?, now).await?;
                }
                Ready::Tick => {
                    let now = bus.now_ms();
                    self.poll(bus, now).await?;
                }
                Ready::Engine | Ready::Maintenance => {
                    let now = bus.now_ms();
                    if matches!(ready, Ready::Maintenance) {
                        self.engine.maintenance(now)?;
                    }
                    let events = self.engine.poll(now).await?;
                    if !events.iter().any(|e| matches!(e, EngineEvent::BridgeWork { .. })) {
                        self.save_engine_state_if_changed()?;
                    }
                    self.handle_engine_events(bus, events, self.state.cursor.unwrap_or(0), now)
                        .await?;
                }
            }
        }
    }
}
