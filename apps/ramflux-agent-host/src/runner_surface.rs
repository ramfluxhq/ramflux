// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Only the pinned author executor handles validated actions; conflicts reload current state.
use crate::checkpoint::{ActionWork, Output, Pending};
use crate::{ActionInput, AgentBus, AgentHost, EngineProvider, Error, Result, participant};
use ramflux_sdk::LocalBusFrame;
use serde_json::json;
impl<E: EngineProvider> AgentHost<E> {
    pub(crate) async fn surface_action(
        &mut self,
        bus: &mut impl AgentBus,
        event: &LocalBusFrame,
        seq: u64,
        now_ms: u64,
    ) -> Result<()> {
        if event.body["author_principal_id"] != self.state.principal_id
            || event.body["executor_device_id"] != self.state.device_id
            || event.body["is_action_executor"] != true
        {
            return Ok(());
        }
        if event.body["out_of_sync"] == true && event.body["last_action_id"].as_str().is_none() {
            return self.resync_owned_surface(bus, event, seq, now_ms).await;
        }
        let Some(action) = event.body["last_action_id"].as_str() else {
            return Ok(());
        };
        let reference = participant::field(&event.body, "surface_ref")?;
        let conversation = participant::field(&event.body, "conversation_id")?;
        let key = crate::runner_output::action_key(reference, action);
        if self.state.handled_actions.contains(&key) {
            return Ok(());
        }
        participant::identity(bus, &mut self.state, &self.config.account_id).await?;
        if participant::conversation(bus, &self.state, conversation, self.config.max_conversations)
            .await?
            .is_none()
        {
            return Ok(());
        }
        let ready_at =
            self.state.last_reply_ms.get(conversation).map_or(now_ms, |last| {
                last.saturating_add(self.config.per_conversation_interval_ms)
            });
        if now_ms < ready_at {
            return Err(Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::RateLimited));
        }
        let work =
            ActionWork { surface_ref: reference.into(), action_id: action.into(), attempts: 0 };
        if !self.rate_history_has_capacity(conversation) {
            return Err(Error::Limit);
        }
        self.state.last_reply_ms.insert(conversation.into(), ready_at);
        let original = Pending {
            seq,
            conversation_id: conversation.into(),
            method: String::new(),
            operation_id: String::new(),
            body: json!(null),
            remaining: Vec::new(),
            action: None,
            plan: None,
            needs_rederive: None,
        };
        let outputs = match self.derive_action_outputs(bus, conversation, &work).await {
            Ok(outputs) => outputs,
            Err(Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::OutOfSync)) => {
                let mut original = original;
                original.body =
                    json!({"conversation_id":conversation,"surface_ref":work.surface_ref});
                original.method = "surface.send".into();
                original.action = Some(work);
                self.handle_surface_refusal(
                    bus,
                    &original,
                    ramflux_sdk::SurfaceRefusalCode::OutOfSync,
                )
                .await?;
                return self.recover_pending(bus).await;
            }
            Err(error) => return Err(error),
        };
        if outputs.is_empty() {
            self.remember_action(key);
            return Ok(());
        }
        self.replace_action_pending(&original, outputs, work)?;
        self.recover_pending(bus).await
    }
    async fn resync_owned_surface(
        &mut self,
        bus: &mut impl AgentBus,
        event: &LocalBusFrame,
        seq: u64,
        now_ms: u64,
    ) -> Result<()> {
        let reference = participant::field(&event.body, "surface_ref")?;
        let conversation = participant::field(&event.body, "conversation_id")?;
        participant::identity(bus, &mut self.state, &self.config.account_id).await?;
        if participant::conversation(bus, &self.state, conversation, self.config.max_conversations)
            .await?
            .is_none()
        {
            return Ok(());
        }
        let ready =
            self.state.last_reply_ms.get(conversation).map_or(now_ms, |last| {
                last.saturating_add(self.config.per_conversation_interval_ms)
            });
        if now_ms < ready {
            return Err(Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::RateLimited));
        }
        let id = ramflux_sdk::new_surface_message_id().map_err(|_| Error::State)?;
        let pending = Pending {
            seq,
            conversation_id: conversation.into(),
            method: "surface.resync".into(),
            operation_id: id.clone(),
            body: json!({"conversation_id":conversation,"surface_ref":reference,"message_id":id}),
            remaining: Vec::new(),
            action: None,
            plan: None,
            needs_rederive: None,
        };
        let view = self.current_surface(bus, &pending).await?;
        if view["out_of_sync"] != true {
            return Ok(());
        }
        if !self.rate_history_has_capacity(conversation) {
            return Err(Error::Limit);
        }
        self.state.last_reply_ms.insert(conversation.into(), ready);
        self.state.pending = Some(pending);
        self.store.save(&self.state)?;
        self.recover_pending(bus).await
    }
    pub(crate) fn replace_action_pending(
        &mut self,
        original: &Pending,
        mut outputs: Vec<Output>,
        work: ActionWork,
    ) -> Result<()> {
        if outputs.is_empty() {
            return Err(Error::State);
        }
        let first = outputs.remove(0);
        self.state.pending = Some(Pending {
            seq: original.seq,
            conversation_id: original.conversation_id.clone(),
            method: first.method,
            operation_id: first.operation_id,
            body: first.body,
            remaining: outputs,
            action: Some(work),
            plan: None,
            needs_rederive: None,
        });
        self.store.save(&self.state)
    }
    pub(crate) async fn derive_action_outputs(
        &mut self,
        bus: &mut impl AgentBus,
        conversation: &str,
        work: &ActionWork,
    ) -> Result<Vec<Output>> {
        let view = bus
            .request(
                "surface.get",
                json!({"surface_ref":work.surface_ref,"action_id":work.action_id}),
                None,
            )
            .await?;
        if view["conversation_id"] != conversation
            || view["author_principal_id"] != self.state.principal_id
            || view["executor_device_id"] != self.state.device_id
            || view["is_action_executor"] != true
        {
            return Err(Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::NotActionExecutor));
        }
        if view["out_of_sync"] == true {
            return Err(Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::OutOfSync));
        }
        let Some(row) = view["actions"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == work.action_id))
        else {
            return Ok(Vec::new());
        };
        let wire =
            ramflux_protocol::decode_base64url(row["wire_base64"].as_str().ok_or(Error::State)?)
                .map_err(|_| Error::State)?;
        let action = ramflux_protocol::A2uiSurfaceAction::from_wire_bytes(&wire)
            .map_err(|_| Error::State)?;
        let content: ramflux_protocol::CreateSurfaceCommand =
            serde_json::from_value(view["snapshot"].clone()).map_err(|_| Error::State)?;
        if action.conversation_id() != conversation || action.surface_id() != content.surface_id {
            return Err(Error::Unauthorized);
        }
        let actionable = row["actionable"] == true;
        let intents = self.engine.action(&ActionInput {
            action: &action,
            snapshot: &content,
            closed: view["closed"] == true,
        })?;
        if intents.is_empty() {
            return Ok(Vec::new());
        }
        if !actionable
            && intents.iter().any(|intent| !matches!(intent, crate::Intent::CloseSurface(_)))
        {
            return Ok(Vec::new());
        }
        if intents.iter().any(|intent| {
            matches!(intent, crate::Intent::ReplyText(_) | crate::Intent::CreateSurface(_))
        }) {
            return Err(Error::State);
        }
        if intents.iter().any(|intent| {
            intent.command().is_none_or(|command| {
                crate::runner_output::command_id(&command) != content.surface_id
            })
        }) {
            return Err(Error::State);
        }
        crate::runner_output::surface_outputs(
            conversation,
            &intents,
            view["version"].as_u64().ok_or(Error::State)?.checked_add(1).ok_or(Error::Limit)?,
        )
    }
}
