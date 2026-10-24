// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Sequential bounded event application with write-ahead output and durable cursor recovery.
use crate::checkpoint::Pending;
use crate::{
    AgentBus, Checkpoint, CheckpointStore, Config, ConversationInput, EngineProvider, Error,
    Intent, Result, participant,
};
use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
use serde_json::json;

pub struct AgentHost<E> {
    pub(crate) config: Config,
    pub(crate) engine: E,
    pub(crate) store: CheckpointStore,
    pub(crate) state: Checkpoint,
}
impl<E: EngineProvider> AgentHost<E> {
    /// # Errors
    /// Rejects invalid configuration, corrupt state or exhausted persisted bounds.
    pub fn new(config: Config, engine: E) -> Result<Self> {
        config.validate()?;
        let store = CheckpointStore::new(config.state_file.clone())?;
        let state = store.load()?;
        if state.handled_actions.len() > 2048
            || state.last_reply_ms.len() > config.max_conversations
            || state.pending.as_ref().is_some_and(|p| {
                !matches!(
                    p.method.as_str(),
                    "message.submit" | "group.send" | "surface.send" | "surface.resync"
                ) || p.remaining.len() > 95
                    || p.remaining.iter().any(|o| {
                        o.method != "surface.send" || o.body["conversation_id"] != p.conversation_id
                    })
                    || p.body["conversation_id"] != p.conversation_id
            })
        {
            return Err(Error::State);
        }
        Ok(Self { config, engine, store, state })
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
        let topics = json!([
            "message.received",
            "group.message.received",
            "conversation.changed",
            "group.changed",
            "device.changed",
            "identity.device_branch.revoked",
            "surface.changed",
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
            self.state.cursor = Some(ack["head_seq"].as_u64().ok_or(Error::Bus)?);
        }
        participant::directory(
            bus,
            "conversation.directory",
            "conversations",
            self.config.max_conversations,
        )
        .await?;
        participant::directory(bus, "group.list", "groups", self.config.max_conversations).await?;
        self.store.save(&self.state)?;
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
        if event.account_id.as_deref() != Some(&self.config.account_id)
            || event.kind != LocalBusFrameKind::Event
        {
            return Err(Error::Unauthorized);
        }
        if event.method == "stream.lagged" {
            return Err(Error::Resync);
        }
        let seq = event.seq.ok_or(Error::Bus)?;
        if self.state.cursor.is_some_and(|cursor| seq <= cursor) {
            return Ok(());
        }
        if matches!(event.method.as_str(), "identity.device_branch.revoked" | "account.locked") {
            return Err(Error::Unauthorized);
        }
        if self.state.pending.is_some() {
            self.recover_pending(bus).await?;
            if self.state.cursor.is_some_and(|cursor| seq <= cursor) {
                return Ok(());
            }
        }
        if event.method == "device.changed" {
            participant::identity(bus, &mut self.state, &self.config.account_id).await?;
        }
        if matches!(event.method.as_str(), "message.received" | "group.message.received") {
            self.message(bus, &event, seq, now_ms).await?;
        }
        if event.method == "surface.changed" {
            self.surface_action(bus, &event, seq, now_ms).await?;
        }
        self.state.cursor = Some(seq);
        self.store.save(&self.state)
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
        if metadata["sender_id"] == self.state.device_id || metadata["deleted"] == true {
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
            return Ok(());
        }
        if !self.state.last_reply_ms.contains_key(conversation_id)
            && self.state.last_reply_ms.len() >= self.config.max_conversations
        {
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
        if message["deleted"] == true || message["sender_id"] == self.state.device_id {
            return Ok(());
        }
        let Some(text) =
            message["body_utf8"].as_str().filter(|t| t.len() <= crate::config::MAX_TEXT_BYTES)
        else {
            return Ok(());
        };
        let intents =
            self.engine.intents(&ConversationInput { conversation_id, message_id, text })?;
        if intents.is_empty() {
            return Ok(());
        }
        let plan = if matches!(intents.first(), Some(Intent::CreateSurface(_))) {
            match crate::surface_plan::SurfacePlan::new(conversation_id, &intents) {
                Ok(plan) => Some(plan),
                Err(Error::SurfaceRefused(reason)) => {
                    self.state.last_refusal = Some(crate::OutputRefusal {
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
            let (method, operation_id, body) =
                participant::reply_body(bus, &self.state, &conversation, message, text, 0).await?;
            vec![crate::checkpoint::Output { method, operation_id, body }]
        } else {
            if !matches!(intents.first(), Some(Intent::CreateSurface(_))) {
                return Err(Error::State);
            }
            crate::runner_output::surface_outputs(conversation_id, &intents, 1)?
        };
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
        self.store.save(&self.state)?;
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
        loop {
            tokio::select! {
                event=bus.next_event()=>self.apply(bus,event?,crate::bus::now_ms()).await?,
                _=tick.tick()=>{
                    bus.request("message.receive",json!({"limit":32,"auto_fetch_attachments":false}),None).await?;
                }
            }
        }
    }
}
