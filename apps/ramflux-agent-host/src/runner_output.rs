// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Crash-safe typed surface batches and stable logical request retries.
use crate::checkpoint::{Output, Pending};
use crate::{AgentBus, AgentHost, EngineProvider, Error, Intent, Result, participant};
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
    let outputs = intents
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
        .collect::<Result<Vec<_>>>()?;
    if serde_json::to_vec(&outputs).map_err(|_| Error::State)?.len() > 262_144 {
        return Err(Error::Limit);
    }
    Ok(outputs)
}
impl<E: EngineProvider> AgentHost<E> {
    pub(crate) async fn recover_pending(&mut self, bus: &mut impl AgentBus) -> Result<()> {
        let result = self.recover_outputs(bus).await;
        match result {
            Err(error) if !error.stops_host() && !matches!(error, Error::Bus | Error::Resync) => {
                eprintln!("agent host retired output: {error}");
                if let Some(pending) = self.state.pending.clone() {
                    self.stop_surface_output(&pending, crate::runner_policy::refusal(&error))?;
                }
                Ok(())
            }
            other => other,
        }
    }
    async fn recover_outputs(&mut self, bus: &mut impl AgentBus) -> Result<()> {
        while let Some(mut pending) = self.state.pending.clone() {
            if pending.action.as_ref().is_some_and(|work| work.attempts > 2) {
                self.stop_surface_output(&pending, ramflux_sdk::SurfaceRefusalCode::StaleVersion)?;
                return Ok(());
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
                self.stop_surface_output(&pending, ramflux_sdk::SurfaceRefusalCode::NotPermitted)?;
                return Ok(());
            };
            if let Some(reason) = pending.needs_rederive {
                if self.resume_refused_pending(bus, &pending, reason).await? {
                    continue;
                }
                return Ok(());
            }
            if !output_scope_matches(&self.state, &pending, &current)? {
                self.complete_pending(&pending)?;
                return Ok(());
            }
            let result = bus
                .request(&pending.method, pending.body.clone(), Some(&pending.operation_id))
                .await;
            let (value, refusal) = match result {
                Err(Error::GroupLeaseUnavailable) => {
                    // Retire this intent; only a fresh command after authority refresh may speak.
                    self.stop_surface_output(
                        &pending,
                        ramflux_sdk::SurfaceRefusalCode::NotPermitted,
                    )?;
                    if let Some(refusal) = &mut self.state.last_refusal {
                        refusal.group_reason = Some(crate::GroupRefusal::LeaseUnavailable);
                    }
                    self.store.save(&self.state)?;
                    return Ok(());
                }
                Err(Error::SurfaceRefused(code)) => (serde_json::Value::Null, Some(code)),
                Err(error) => return Err(error),
                Ok(value)
                    if pending.method.starts_with("surface.") && value["accepted"] != true =>
                {
                    let code = serde_json::from_value(value["reason_code"].clone())
                        .unwrap_or(ramflux_sdk::SurfaceRefusalCode::InvalidRequest);
                    (value, Some(code))
                }
                Ok(value) => (value, None),
            };
            if let Some(code) = refusal {
                if self.handle_surface_refusal(bus, &pending, code).await? {
                    continue;
                }
                return Ok(());
            }
            if pending.method == "surface.resync"
                && (pending.action.is_some() || pending.plan.is_some())
            {
                pending.needs_rederive = Some(ramflux_sdk::SurfaceRefusalCode::StaleHash);
                self.state.pending = Some(pending.clone());
                self.store.save(&self.state)?;
                if self
                    .resume_refused_pending(
                        bus,
                        &pending,
                        ramflux_sdk::SurfaceRefusalCode::StaleHash,
                    )
                    .await?
                {
                    continue;
                }
                return Ok(());
            }
            drop(value);
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
    pub(crate) fn complete_pending(&mut self, pending: &Pending) -> Result<()> {
        if let Some(work) = &pending.action {
            let id = action_key(&work.surface_ref, &work.action_id);
            self.remember_action(id);
        }
        self.state.cursor = Some(self.state.cursor.unwrap_or(0).max(pending.seq));
        self.state.pending = None;
        self.store.save(&self.state)
    }
}
fn output_scope_matches(
    state: &crate::Checkpoint,
    pending: &Pending,
    current: &serde_json::Value,
) -> Result<bool> {
    if pending.method == "surface.resync" {
        participant::field(&pending.body, "surface_ref")?;
    } else if pending.method == "surface.send" {
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
        let sender = if pending.method == "group.send" && state.native_account {
            &state.principal_id
        } else {
            &state.device_id
        };
        if pending.body["sender_id"] != *sender {
            return Err(Error::Unauthorized);
        }
        if pending.method == "group.send" && current["group_id"] != pending.body["group_id"]
            || pending.method == "message.submit" && !current["group_id"].is_null()
        {
            return Ok(false);
        }
    }
    Ok(true)
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
