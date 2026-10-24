// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed surface refusals, bounded rederivation, and durable use of the author resync RPC.
use crate::checkpoint::{OutputRefusal, Pending};
use crate::{AgentBus, AgentHost, EngineProvider, Error, Result};
use ramflux_sdk::SurfaceRefusalCode as Code;
use serde_json::{Value, json};
impl<E: EngineProvider> AgentHost<E> {
    pub(crate) fn stop_surface_output(&mut self, pending: &Pending, reason: Code) -> Result<()> {
        let surface_id = pending
            .plan
            .as_ref()
            .map(|plan| plan.target.surface_id.clone())
            .or_else(|| pending.action.as_ref().map(|work| work.surface_ref.clone()));
        self.state.last_refusal = Some(OutputRefusal {
            conversation_id: pending.conversation_id.clone(),
            surface_id,
            reason,
        });
        self.complete_pending(pending)
    }
    pub(crate) async fn current_surface(
        &self,
        bus: &mut impl AgentBus,
        pending: &Pending,
    ) -> Result<Value> {
        let body = if let Some(work) = &pending.action {
            json!({"surface_ref":work.surface_ref,"action_id":work.action_id})
        } else if let Some(reference) = pending.body["surface_ref"].as_str() {
            json!({"surface_ref":reference})
        } else {
            let raw = ramflux_protocol::decode_base64url(
                pending.body["wire_base64"].as_str().ok_or(Error::State)?,
            )
            .map_err(|_| Error::State)?;
            let event = ramflux_protocol::A2uiConversationEvent::from_wire_bytes(&raw)
                .map_err(|_| Error::State)?;
            json!({"surface_id":crate::runner_output::command_id(event.command()),"conversation_id":pending.conversation_id,"author_principal_id":self.state.principal_id})
        };
        let view = bus.request("surface.get", body, None).await?;
        if view.is_null() {
            return Err(Error::SurfaceRefused(Code::NotFound));
        }
        if view["conversation_id"] != pending.conversation_id
            || view["author_principal_id"] != self.state.principal_id
        {
            return Err(Error::Unauthorized);
        }
        Ok(view)
    }
    pub(crate) async fn handle_surface_refusal(
        &mut self,
        bus: &mut impl AgentBus,
        pending: &Pending,
        reason: Code,
    ) -> Result<bool> {
        if !matches!(reason, Code::StaleVersion | Code::StaleHash | Code::OutOfSync)
            || pending.method == "surface.resync"
        {
            self.stop_surface_output(pending, reason)?;
            return Ok(false);
        }
        let mut next = pending.clone();
        if let Some(work) = &mut next.action {
            if work.attempts >= 2 {
                work.attempts = 3;
                self.state.pending = Some(next);
                self.store.save(&self.state)?;
                return Err(Error::Limit);
            }
            work.attempts += 1;
        } else if let Some(plan) = &mut next.plan {
            if plan.attempts >= 2 {
                self.stop_surface_output(pending, reason)?;
                return Ok(false);
            }
            plan.attempts += 1;
        }
        next.needs_rederive = Some(reason);
        self.state.pending = Some(next.clone());
        self.store.save(&self.state)?;
        self.resume_refused_pending(bus, &next, reason).await
    }
    pub(crate) async fn resume_refused_pending(
        &mut self,
        bus: &mut impl AgentBus,
        pending: &Pending,
        reason: Code,
    ) -> Result<bool> {
        let mut next = pending.clone();
        let view = match self.current_surface(bus, &next).await {
            Ok(view) => view,
            Err(Error::SurfaceRefused(code)) => {
                self.stop_surface_output(pending, code)?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if pending.method == "surface.resync" && view["out_of_sync"] == true {
            self.stop_surface_output(pending, Code::OutOfSync)?;
            return Ok(false);
        }
        if reason == Code::OutOfSync || view["out_of_sync"] == true {
            let id = ramflux_sdk::new_surface_message_id().map_err(|_| Error::State)?;
            next.method = "surface.resync".into();
            next.operation_id.clone_from(&id);
            next.body = json!({"conversation_id":next.conversation_id,"surface_ref":crate::participant::field(&view,"surface_ref")?,"message_id":id});
            next.remaining.clear();
            next.needs_rederive = None;
            self.state.pending = Some(next);
            self.store.save(&self.state)?;
            return Ok(true);
        }
        self.rederive_pending(bus, &next, &view, reason).await
    }
    pub(crate) async fn rederive_pending(
        &mut self,
        bus: &mut impl AgentBus,
        pending: &Pending,
        view: &Value,
        reason: Code,
    ) -> Result<bool> {
        let result = if let Some(work) = &pending.action {
            self.derive_action_outputs(bus, &pending.conversation_id, work).await
        } else if let Some(plan) = &pending.plan {
            match plan.rederive(view) {
                Ok(intents) if intents.is_empty() => Ok(Vec::new()),
                Ok(intents) => crate::runner_output::surface_outputs(
                    &pending.conversation_id,
                    &intents,
                    view["version"]
                        .as_u64()
                        .ok_or(Error::State)?
                        .checked_add(1)
                        .ok_or(Error::Limit)?,
                ),
                Err(error) => Err(error),
            }
        } else {
            self.stop_surface_output(pending, reason)?;
            return Ok(false);
        };
        let mut outputs = match result {
            Ok(outputs) => outputs,
            Err(Error::SurfaceRefused(code)) => {
                self.stop_surface_output(pending, code)?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if outputs.is_empty() {
            self.complete_pending(pending)?;
            return Ok(false);
        }
        let first = outputs.remove(0);
        let mut next = pending.clone();
        next.method = first.method;
        next.operation_id = first.operation_id;
        next.body = first.body;
        next.remaining = outputs;
        next.needs_rederive = None;
        self.state.pending = Some(next);
        self.store.save(&self.state)?;
        Ok(true)
    }
}
