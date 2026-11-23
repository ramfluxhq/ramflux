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
    /// Human account that owns this agent, when `account.status` names a different custodian.
    owner_account: Option<String>,
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
        let mut state = store.load()?;
        if let Some(engine) = &config.engine {
            let maximum = crate::bus::now_ms()
                .saturating_add(engine.prx.approval_timeout_s.saturating_mul(1000));
            for bridge in state.approvals.values_mut() {
                bridge.deadline_ms = bridge.deadline_ms.min(maximum);
            }
        }
        engine.restore(state.engine.as_ref())?;
        state.engine = engine.checkpoint()?;
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
        Ok(Self { config, owner_account: None, engine, store, state })
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

    /// The human custodian, when this agent account names one.
    #[must_use]
    pub fn owner_account(&self) -> Option<&str> {
        self.owner_account.as_deref()
    }

    /// Cancels every stored PRX run by its session and run id.
    ///
    /// A locked account makes the next `start` return [`Error::IdentityLost`] before
    /// `account.locked` is applied, so the process exit calls this as well.
    ///
    /// # Errors
    /// Returns a provider or checkpoint error. A remote cancel that cannot be confirmed is not an error.
    pub async fn cancel_live_runs(&mut self) -> Result<()> {
        let conversations = self.engine.active_conversations();
        for conversation_id in &conversations {
            self.engine.cancel(conversation_id).await?;
        }
        self.state.approvals.clear();
        self.save_state()
    }

    /// Posts one owner approval decision. The agent bus is not required.
    ///
    /// # Errors
    /// Returns a transport failure. A coded PRX refusal is `Ok`.
    pub async fn post_owner_decision(&mut self, event: &LocalBusFrame) -> Result<()> {
        crate::runner_run_approval::post_owner_decision(&mut self.engine, event).await
    }

    /// Bind the headless identity and replay from the last durably applied cursor.
    /// # Errors
    /// Rejects revoked/human accounts, unavailable snapshots, stream gaps and state I/O failures.
    pub async fn start(&mut self, bus: &mut impl AgentBus) -> Result<()> {
        self.owner_account =
            participant::identity(bus, &mut self.state, &self.config.account_id).await?;
        self.engine.publish_limits().await?;
        self.normalize_deferred()?;
        let topics = json!([
            "message.received",
            "group.message.received",
            "message.updated",
            "conversation.changed",
            "group.changed",
            "device.changed",
            "identity.device_branch.revoked",
            "surface.changed",
            "task.changed",
            "account.locked",
            "agent.approval"
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
        if event.method == "message.updated" {
            // An edit is not a new turn. Only a deleted row erases the PRX session.
            self.erase_deleted_message(event).await?;
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
        crate::runner_run_approval::forward(bus, &mut self.engine, event).await?;
        self.state.cursor = Some(seq);
        self.save_state()
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
        if metadata["deleted"] == true {
            // One everyone-delete clears the whole PRX session, every agent included.
            self.engine.erase_history(conversation_id).await?;
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
        let Some(message) = crate::message_input::read(bus, conversation_id, message_id).await?
        else {
            return Ok(());
        };
        let text = message["text"].as_str().ok_or(Error::MalformedField("text"))?;
        let sender_display_name = participant::sender_display_name(bus, &message).await?;
        let chat_kind = if conversation["group_id"].is_string() { "group" } else { "direct" };
        let mentioned = participant::mentions_self(bus, &self.state, &message).await?;
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

    async fn erase_deleted_message(&mut self, event: &LocalBusFrame) -> Result<()> {
        let metadata = &event.body["message"];
        if metadata["deleted"] != true {
            return Ok(());
        }
        let conversation_id = participant::field(metadata, "conversation_id")?;
        self.engine.erase_history(conversation_id).await
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
        if *reason != crate::EngineFailure::Busy {
            self.complete_resumed_task(bus, conversation_id, false).await?;
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
                self.engine.erase_history(&conversation_id).await?;
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
            self.state.approvals.remove(conversation_id);
            return self.save_state();
        };
        let Some(message) = crate::message_input::read(bus, conversation_id, message_id).await?
        else {
            return Ok(());
        };
        let plan = if matches!(intents.first(), Some(Intent::CreateSurface(_))) {
            match crate::surface_plan::SurfacePlan::new(conversation_id, &intents) {
                Ok(plan) => Some(plan),
                Err(Error::SurfaceRefused(reason)) => {
                    self.state.last_refusal = Some(crate::OutputRefusal {
                        group_reason: None,
                        conversation_id: conversation_id.into(),
                        surface_id: intents.first().and_then(Intent::surface_id).map(str::to_owned),
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
            participant::reply_outputs(bus, &self.state, &conversation, &message, text, 0).await?
        } else {
            if !matches!(intents.first(), Some(Intent::CreateSurface(_))) {
                return Err(Error::State);
            }
            crate::runner_output::surface_outputs(
                conversation_id,
                &intents,
                &ramflux_protocol::SurfaceState::default(),
            )?
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
        self.run_paired(bus, &mut None::<crate::RfdBus>).await
    }

    /// Same loop as [`Self::run`], plus the human owner's approval journal.
    /// An owner decision is posted on `bus` (the agent), not on the owner socket.
    ///
    /// # Errors
    /// Returns on stream loss or revocation so the caller can reconnect or stop.
    pub async fn run_paired<O: AgentBus>(
        &mut self,
        bus: &mut impl AgentBus,
        owner: &mut Option<O>,
    ) -> Result<()> {
        let mut tick =
            tokio::time::interval(std::time::Duration::from_millis(self.config.poll_interval_ms));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate interval tick; ordinary events can arrive before the first poll.
        tick.tick().await;
        loop {
            tokio::select! {
                event = bus.next_event() => {
                    self.apply(bus, event?, crate::bus::now_ms()).await?;
                }
                event = owner_event(owner) => {
                    if let Some(frame) = event {
                        let frame = frame?;
                        if frame.kind == LocalBusFrameKind::Event && frame.method == "stream.lagged"
                        {
                            return Err(Error::Resync);
                        }
                        crate::runner_run_approval::forward(bus, &mut self.engine, &frame).await?;
                    }
                }
                _ = tick.tick() => self.poll(bus, crate::bus::now_ms()).await?,
            }
        }
    }
}

/// Tails the owner journal from the start so a decision made before this socket attached is posted.
///
/// # Errors
/// Returns a bus failure. A pruned cursor resubscribes at the current head.
pub async fn subscribe_owner(owner: &mut impl AgentBus) -> Result<()> {
    let topics = json!(["agent.approval"]);
    match owner.request("bus.subscribe", json!({"topics": topics, "since_seq": 0}), None).await {
        Ok(_) => Ok(()),
        Err(Error::Resync) => {
            owner.request("bus.subscribe", json!({"topics": topics}), None).await?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn owner_event<O: AgentBus>(owner: &mut Option<O>) -> Option<Result<LocalBusFrame>> {
    if let Some(owner) = owner.as_mut() {
        Some(owner.next_event().await)
    } else {
        std::future::pending::<()>().await;
        None
    }
}
