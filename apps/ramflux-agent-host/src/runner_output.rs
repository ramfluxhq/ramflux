// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Crash-safe typed surface batches and stable logical request retries.
use crate::checkpoint::{Output, Pending};
use crate::{AgentBus, AgentHost, EngineProvider, Error, Intent, Result, participant};
use serde_json::json;
pub(crate) fn surface_outputs(
    conversation: &str,
    intents: &[Intent],
    start: u64,
) -> Result<Vec<Output>> {
    if intents.is_empty() || intents.len() > 96 {
        return Err(Error::Limit);
    }
    let expected = intents.first().and_then(Intent::command).ok_or(Error::State)?;
    let expected_id = command_id(&expected);
    if intents
        .iter()
        .any(|intent| intent.command().is_none_or(|command| command_id(&command) != expected_id))
    {
        return Err(Error::State);
    }
    intents
        .iter()
        .enumerate()
        .map(|(index, intent)| {
            let command = intent.command().ok_or(Error::State)?;
            let version = start
                .checked_add(u64::try_from(index).map_err(|_| Error::Limit)?)
                .ok_or(Error::Limit)?;
            let request = ramflux_sdk::SurfaceSendRequest::event(conversation, version, &command)
                .map_err(|_| Error::Limit)?;
            Ok(Output {
                method: "surface.send".into(),
                operation_id: request.message_id.clone(),
                body: serde_json::to_value(request).map_err(|_| Error::State)?,
            })
        })
        .collect()
}
impl<E: EngineProvider> AgentHost<E> {
    pub(crate) async fn recover_pending(&mut self, bus: &mut impl AgentBus) -> Result<()> {
        while let Some(mut pending) = self.state.pending.clone() {
            if pending.action.as_ref().is_some_and(|work| work.attempts > 2) {
                return Err(Error::Limit);
            }
            participant::identity(bus, &mut self.state, &self.config.account_id).await?;
            let context = participant::conversation(
                bus,
                &self.state,
                &pending.conversation_id,
                self.config.max_conversations,
            )
            .await?;
            let Some(current) = context else {
                self.complete_pending(&pending)?;
                return Ok(());
            };
            if pending.method == "surface.send" {
                let bytes = ramflux_protocol::decode_base64url(
                    pending.body["wire_base64"].as_str().ok_or(Error::State)?,
                )
                .map_err(|_| Error::State)?;
                let event = ramflux_protocol::A2uiConversationEvent::from_wire_bytes(&bytes)
                    .map_err(|_| Error::State)?;
                if event.conversation_id() != pending.conversation_id {
                    return Err(Error::State);
                }
            } else {
                if pending.body["sender_id"] != self.state.device_id {
                    return Err(Error::Unauthorized);
                }
                if pending.method == "group.send" && current["group_id"] != pending.body["group_id"]
                    || pending.method == "message.submit" && !current["group_id"].is_null()
                {
                    self.complete_pending(&pending)?;
                    return Ok(());
                }
            }
            let result = bus
                .request(&pending.method, pending.body.clone(), Some(&pending.operation_id))
                .await?;
            if pending.method == "surface.send" && result["accepted"] != true {
                if let Some(mut work) = pending.action.clone() {
                    if work.attempts >= 2 {
                        work.attempts = 3;
                        pending.action = Some(work);
                        self.state.pending = Some(pending);
                        self.store.save(&self.state)?;
                        return Err(Error::Limit);
                    }
                    work.attempts += 1;
                    let outputs =
                        self.derive_action_outputs(bus, &pending.conversation_id, &work).await?;
                    if outputs.is_empty() {
                        self.complete_pending(&pending)?;
                        return Ok(());
                    }
                    self.replace_action_pending(&pending, outputs, work)?;
                    continue;
                }
                // Reload explicitly before abandoning a conflicting streamed plan. Never replay
                // its old patch/hash against a newly observed state.
                let raw = ramflux_protocol::decode_base64url(
                    pending.body["wire_base64"].as_str().ok_or(Error::State)?,
                )
                .map_err(|_| Error::State)?;
                let event = ramflux_protocol::A2uiConversationEvent::from_wire_bytes(&raw)
                    .map_err(|_| Error::State)?;
                let id = command_id(event.command());
                bus.request("surface.get",json!({"surface_id":id,"conversation_id":pending.conversation_id,"author_principal_id":self.state.principal_id}),None).await?;
                self.complete_pending(&pending)?;
                return Ok(());
            }
            if pending.remaining.is_empty() {
                self.complete_pending(&pending)?;
                return Ok(());
            }
            let next = pending.remaining.remove(0);
            pending.method = next.method;
            pending.operation_id = next.operation_id;
            pending.body = next.body;
            self.state.pending = Some(pending);
            self.store.save(&self.state)?;
        }
        Ok(())
    }
    fn complete_pending(&mut self, pending: &Pending) -> Result<()> {
        if let Some(work) = &pending.action {
            let id = action_key(&work.surface_ref, &work.action_id);
            if !self.state.handled_actions.contains(&id) {
                if self.state.handled_actions.len() >= 2048 {
                    return Err(Error::Limit);
                }
                self.state.handled_actions.push(id);
            }
        }
        self.state.cursor = Some(self.state.cursor.unwrap_or(0).max(pending.seq));
        self.state.pending = None;
        self.store.save(&self.state)
    }
}
pub(crate) fn action_key(reference: &str, id: &str) -> String {
    ramflux_protocol::hash_base64url(
        "ramflux.agent.handled_action.v1",
        format!("{}:{reference}{id}", reference.len()).as_bytes(),
    )
}
pub(crate) fn command_id(command: &ramflux_protocol::A2uiConversationCommand) -> &str {
    use ramflux_protocol::A2uiConversationCommand as C;
    match command {
        C::CreateSurface(c) => &c.surface_id,
        C::UpdateComponents(c) => &c.surface_id,
        C::UpdateDataModel(c) => &c.surface_id,
        C::DeleteSurface(c) => &c.surface_id,
        C::PatchSurface(c) => &c.surface_id,
        C::StreamAppend(c) => &c.surface_id,
    }
}
