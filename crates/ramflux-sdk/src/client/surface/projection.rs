// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signature/author guards, atomic state transitions and durable single-use decisions.
use super::{Carrier, Outcome, Payload, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::SurfaceState;
use serde_json::{Value, json};
impl RamfluxClient {
    pub(crate) fn preflight_surface(&self, carrier: &Carrier) -> Result<Outcome, SdkError> {
        let payload = self.verify_surface_carrier(
            carrier,
            &carrier.sender_principal_id,
            &carrier.sender_device_id,
        )?;
        self.evaluate_surface(carrier, &payload, true)
    }
    pub(super) fn evaluate_surface(
        &self,
        carrier: &Carrier,
        payload: &Payload,
        outbound: bool,
    ) -> Result<Outcome, SdkError> {
        if let Payload::ActionReceipt { original, action } = payload {
            return self.validate_surface_receipt(carrier, original, action);
        }
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let reject = |code: &str| Outcome::rejected(json!({"code":code}));
        // Reject unauthorized updates, stale decisions and consumed decisions before loading
        // the private stream-finality checkpoint.
        if matches!(payload, Payload::Event(_))
            && carrier.sender_principal_id != carrier.author_principal_id
        {
            return Ok(reject("non_author_update"));
        }
        if let Payload::Action(action) = payload {
            let view =
                self.account_db()?.client_record("surface", &carrier.surface_reference()?)?;
            if let Some(view) = view {
                if view["conversation_id"] != carrier.conversation_id
                    || view["author_principal_id"] != carrier.author_principal_id
                {
                    return Ok(reject("surface_author_or_conversation_mismatch"));
                }
                if view["version"] != action.version()
                    || view["surface_hash"] != action.surface_hash()
                {
                    return Ok(Outcome::rejected(
                        json!({"code":"renderer_error","reject":ramflux_protocol::SurfaceReject::Stale}),
                    ));
                }
                let used = super::decision::decision_key(carrier, action)?;
                if self.account_db()?.load_actor_state::<Value>(&used)?.is_some() {
                    return Ok(reject("action_already_used"));
                }
                if local.principal_id == carrier.author_principal_id
                    && view["executor_device_id"] != local.device_id
                    && !outbound
                {
                    let mut pending = Outcome::rejected(json!({"code":"awaiting_action_executor"}));
                    pending.retryable = true;
                    return Ok(pending);
                }
            }
        }
        let saved = self.surface_state_scoped(
            &carrier.conversation_id,
            &carrier.author_principal_id,
            &carrier.surface_id,
        )?;
        if let Some((record, _)) = &saved
            && (record.conversation_id != carrier.conversation_id
                || record.author_principal_id != carrier.author_principal_id)
        {
            return Ok(reject("surface_author_or_conversation_mismatch"));
        }
        match payload {
            Payload::Event(event) => {
                if carrier.sender_principal_id != carrier.author_principal_id {
                    return Ok(reject("non_author_update"));
                }
                match self.next_surface_event(carrier, event)? {
                    Ok(next) => Outcome::accepted(&carrier.author_principal_id, &next),
                    Err(rejected) => Ok(rejected),
                }
            }
            Payload::Action(action) => {
                let Some((record, state)) = saved else {
                    return Ok(reject("unknown_surface"));
                };
                if !outbound && local.principal_id != record.author_principal_id {
                    return Ok(reject("action_not_for_author"));
                }
                if let Err(error) = state.validate_action(action) {
                    return Ok(Outcome::rejected(json!({"code":"renderer_error","reject":error})));
                }
                let used = super::decision::decision_key(carrier, action)?;
                if self.account_db()?.load_actor_state::<Value>(&used)?.is_some() {
                    return Ok(reject("action_already_used"));
                }
                Outcome::accepted(&carrier.author_principal_id, &state)
            }
            Payload::ActionReceipt { .. } => Err(invalid("receipt validation dispatch mismatch")),
        }
    }
    fn next_surface_event(
        &self,
        carrier: &Carrier,
        event: &ramflux_protocol::A2uiConversationEvent,
    ) -> Result<Result<SurfaceState, Outcome>, SdkError> {
        let saved = self.surface_state_scoped(
            &carrier.conversation_id,
            &carrier.author_principal_id,
            &carrier.surface_id,
        )?;
        let state = saved.map_or_else(SurfaceState::default, |(_, state)| state);
        if carrier.snapshot.is_some()
            && (self.surface_is_out_of_sync(&carrier.surface_reference()?)?
                || event.version() > state.version().saturating_add(1))
        {
            return match self.restore_surface_proof(carrier, &state, event.version()) {
                Ok(Some(next)) => Ok(Ok(next)),
                Ok(None) => Ok(Err(Outcome::rejected(json!({"code":"snapshot_required"})))),
                Err(error @ (SdkError::Storage(_) | SdkError::SurfaceCheckpointMismatch)) => {
                    Err(error)
                }
                Err(_) => Ok(Err(Outcome::rejected(json!({"code":"snapshot_rejected"})))),
            };
        }
        let next = state.apply(event).map_err(|error| Outcome::protocol_rejected(&error));
        if let Ok(next) = &next
            && carrier.snapshot.is_some()
        {
            match self.restore_surface_proof(carrier, &state, event.version()) {
                Ok(Some(attested)) if &attested == next => {}
                Err(error @ (SdkError::Storage(_) | SdkError::SurfaceCheckpointMismatch)) => {
                    return Err(error);
                }
                _ => return Ok(Err(Outcome::rejected(json!({"code":"snapshot_rejected"})))),
            }
        }
        Ok(next)
    }
    pub(super) fn apply_surface_payload(
        &self,
        carrier: &Carrier,
        payload: Payload,
        outbound: bool,
        group_epoch: Option<u64>,
    ) -> Result<Outcome, SdkError> {
        let outcome = self.evaluate_surface(carrier, &payload, outbound)?;
        if !outcome.accepted {
            return Ok(outcome);
        }
        let db = self.account_db()?;
        match payload {
            Payload::Event(event) => {
                let previous_version = self
                    .surface_state_ref(&carrier.surface_reference()?)?
                    .map_or(0, |(_, s)| s.version());
                let recovering = carrier.snapshot.is_some()
                    && (self.surface_is_out_of_sync(&carrier.surface_reference()?)?
                        || event.version() > previous_version.saturating_add(1));
                let state = self
                    .next_surface_event(carrier, &event)?
                    .map_err(|_| invalid("surface changed during writer transaction"))?;
                if recovering {
                    db.persist_actor_state(
                        &key("snapshot_floor", &carrier.surface_reference()?),
                        &state.version(),
                    )?;
                    db.delete_surface_state(&key("out_of_sync", &carrier.surface_reference()?))?;
                }
                self.persist_surface_state(carrier, &state)?;
            }
            Payload::Action(action) => {
                let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
                if (!outbound || local.principal_id == carrier.author_principal_id)
                    && self
                        .account_db()?
                        .client_record("surface", &carrier.surface_reference()?)?
                        .is_some_and(|v| v["executor_device_id"] == local.device_id)
                {
                    self.persist_surface_decision(carrier, &action, true, group_epoch)?;
                }
            }
            Payload::ActionReceipt { original, action } => {
                self.persist_surface_decision(&original, &action, false, group_epoch)?;
                self.store_surface_action_attestation(&original, carrier)?;
                self.account_db()?.persist_actor_state(
                    &super::receipt_key(&original)?,
                    &super::Receipt {
                        fingerprint: ramflux_protocol::hash_base64url(
                            "ramflux.surface.delivery.v1",
                            &original.bytes()?,
                        ),
                        result: outcome.clone(),
                    },
                )?;
            }
        }
        Ok(outcome)
    }
    pub(crate) fn surface_error(
        &self,
        conversation: &str,
        message: &str,
        sender: super::SurfaceSender<'_>,
        surface: Option<&str>,
        error: &Value,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let error_id = ramflux_protocol::hash_base64url(
            "ramflux.surface.error.v1",
            &ramflux_protocol::canonical_json_bytes(&(sender.device, sender.envelope_id))?,
        );
        let view =
            surface.map(|reference| db.client_record("surface", reference)).transpose()?.flatten();
        db.persist_client_record("surface_error",&error_id,&json!({"conversation_id":conversation,"message_id":message,"sender_device_id":sender.device,"envelope_id":sender.envelope_id,"surface_ref":surface,"surface_id":view.as_ref().map(|v|&v["surface_id"]),"author_principal_id":view.as_ref().map(|v|&v["author_principal_id"]),"renderer_error":error}))?;
        if let (Some(reference), Some(mut view)) = (surface, view)
            && view["conversation_id"] == conversation
        {
            view["renderer_error"] = error.clone();
            db.persist_client_record("surface", reference, &view)?;
        }
        Ok(())
    }
}
