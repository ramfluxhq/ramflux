// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A creator-device decision ledger with authenticated, non-executable replicas.
use super::{Carrier, Outcome, Payload, PayloadKind, SnapshotProof, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::A2uiSurfaceAction;
use serde_json::{Value, json};
pub(super) fn decision_key(
    carrier: &Carrier,
    action: &A2uiSurfaceAction,
) -> Result<String, SdkError> {
    Ok(format!(
        "{}/{}",
        key("decisions", &carrier.surface_reference()?),
        ramflux_protocol::hash_base64url(
            "ramflux.surface.decision.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                action.version(),
                action.action_id(),
                &carrier.sender_principal_id
            ))?
        )
    ))
}
impl RamfluxClient {
    pub(super) fn validate_surface_receipt(
        &self,
        receipt: &Carrier,
        original: &Carrier,
        action: &A2uiSurfaceAction,
    ) -> Result<Outcome, SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let Some((record, current)) = self.surface_state_ref(&receipt.surface_reference()?)? else {
            let mut pending = Outcome::rejected(json!({"code":"receipt_waiting_for_surface"}));
            pending.retryable = true;
            return Ok(pending);
        };
        if local.principal_id != record.author_principal_id
            || receipt.sender_principal_id != record.author_principal_id
            || receipt.sender_device_id != record.author_device_id
        {
            return Ok(Outcome::rejected(json!({"code":"invalid_action_executor"})));
        }
        let signer = self
            .account_db()?
            .client_record("device", &original.sender_device_id)?
            .ok_or_else(|| invalid("original action signer has no verified device record"))?;
        let principal = signer["principal_id"]
            .as_str()
            .ok_or_else(|| invalid("original action owner missing"))?;
        if !matches!(
            self.verify_surface_carrier(original, principal, &original.sender_device_id)?,
            Payload::Action(_)
        ) {
            return Err(invalid("receipt original action type mismatch"));
        }
        let proof = receipt
            .snapshot
            .as_ref()
            .ok_or_else(|| invalid("action receipt has no state proof"))?;
        let witnessed =
            proof.restore(receipt, &ramflux_protocol::SurfaceState::default(), action.version())?;
        if let Err(error) = witnessed.validate_action(action) {
            return Ok(Outcome::protocol_rejected(&error));
        }
        if let Some(used) =
            self.account_db()?.load_actor_state::<Value>(&decision_key(original, action)?)?
            && used["message_id"] != original.message_id
        {
            return Ok(Outcome::rejected(json!({"code":"action_already_used"})));
        }
        Outcome::accepted(&record.author_principal_id, &current)
    }
    pub(super) fn persist_surface_decision(
        &self,
        original: &Carrier,
        action: &A2uiSurfaceAction,
        actionable: bool,
        group_epoch: Option<u64>,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let reference = original.surface_reference()?;
        if let Some(used) = db.load_actor_state::<Value>(&decision_key(original, action)?)?
            && used["message_id"] != original.message_id
        {
            return Err(invalid("decision changed during writer transaction"));
        }
        db.persist_actor_state(
            &decision_key(original, action)?,
            &json!({"message_id":original.message_id,"version":action.version(),"action_id":action.action_id(),"sender_principal_id":original.sender_principal_id}),
        )?;
        let id = ramflux_protocol::hash_base64url(
            "ramflux.surface.action_delivery.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                &reference,
                &original.sender_principal_id,
                &original.message_id,
            ))?,
        );
        let prefix = key("actions", &reference) + "/";
        let action_key = format!("{prefix}{id}");
        let recorded_actionable = actionable
            || db
                .load_actor_state::<Value>(&action_key)?
                .is_some_and(|row| row["actionable"] == true);
        db.persist_actor_state(&action_key,&json!({"id":id,"message_id":original.message_id,"sender_principal_id":original.sender_principal_id,"sender_device_id":original.sender_device_id,"carrier":original,"version":action.version(),"actionable":recorded_actionable,"group_epoch":group_epoch}))?;
        db.prune_surface_records(&prefix, 128, 4 * 1024 * 1024, &action_key)?;
        if let Some(mut view) = db.client_record("surface", &reference)? {
            view["last_action_id"] = json!(id);
            view["last_action_message_id"] = json!(original.message_id);
            view["renderer_error"] = Value::Null;
            db.persist_client_record("surface", &reference, &view)?;
        }
        if actionable {
            self.queue_surface_receipt(original, &id)?;
        }
        Ok(())
    }
    pub(super) fn store_surface_action_attestation(
        &self,
        original: &Carrier,
        receipt: &Carrier,
    ) -> Result<(), SdkError> {
        let reference = original.surface_reference()?;
        let id = ramflux_protocol::hash_base64url(
            "ramflux.surface.action_delivery.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                &reference,
                &original.sender_principal_id,
                &original.message_id,
            ))?,
        );
        let prefix = key("actions", &reference) + "/";
        let actor_key = format!("{prefix}{id}");
        let db = self.account_db()?;
        let mut row = db
            .load_actor_state::<Value>(&actor_key)?
            .ok_or_else(|| invalid("action attestation row missing"))?;
        row["attestation"] = serde_json::to_value(receipt)?;
        db.persist_actor_state(&actor_key, &row)?;
        db.prune_surface_records(&prefix, 128, 4 * 1024 * 1024, &actor_key)?;
        Ok(())
    }
    fn queue_surface_receipt(&self, original: &Carrier, id: &str) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let (record, state) = self
            .surface_state_ref(&original.surface_reference()?)?
            .ok_or_else(|| invalid("decision surface missing"))?;
        if local.device_id != record.author_device_id {
            return Err(invalid("only the surface creator executes actions"));
        }
        let receipt = self.sign_surface_carrier(Carrier {
            schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
            content_type: "surface".into(),
            payload_kind: PayloadKind::ActionReceipt,
            conversation_id: original.conversation_id.clone(),
            surface_id: original.surface_id.clone(),
            message_id: crate::new_surface_message_id()?,
            sender_principal_id: local.principal_id.clone(),
            sender_device_id: local.device_id.clone(),
            author_principal_id: record.author_principal_id,
            snapshot: Some(SnapshotProof::new(&state, &record.author_device_id)?),
            wire_base64: ramflux_protocol::encode_base64url(original.bytes()?),
            signature: String::new(),
        })?;
        self.store_surface_action_attestation(original, &receipt)?;
        let epoch = self
            .account_db()?
            .client_record("conversation", &original.conversation_id)?
            .and_then(|v| v["group_id"].as_str().map(str::to_owned))
            .map(|id| self.group_state(&id).map(|g| g.group_epoch))
            .transpose()?;
        self.queue_surface_logical("receipt_job", id, &receipt, epoch)
    }
}
