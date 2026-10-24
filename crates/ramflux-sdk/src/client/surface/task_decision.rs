// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Task links to existing surface decisions without issuing executable surface actions.
use super::{Carrier, Payload, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{SurfaceState, TaskDecision, TaskResolve};
use serde_json::Value;
impl RamfluxClient {
    pub(crate) fn task_surface_receipt(
        &self,
        conversation: &str,
        surface: &str,
        author: &str,
        decision_id: &str,
    ) -> Result<String, SdkError> {
        let reference = super::scope::surface_reference(conversation, author, surface)?;
        let row = self
            .account_db()?
            .load_actor_state::<Value>(&format!("{}/{decision_id}", key("actions", &reference)))?
            .ok_or_else(|| SdkError::InboundPending("task surface action not found".into()))?;
        if row["attestation"].is_null() {
            return Err(SdkError::InboundPending(
                "task surface action awaits its creator receipt".into(),
            ));
        }
        let receipt: Carrier = serde_json::from_value(row["attestation"].clone())?;
        Ok(ramflux_protocol::encode_base64url(receipt.bytes()?))
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_task_surface_decision(
        &self,
        conversation: &str,
        surface: &str,
        author: &str,
        requester: &str,
        resolution: &TaskResolve,
        encoded: &str,
        require_stored: bool,
    ) -> Result<String, SdkError> {
        if encoded.len() > 256 * 1024 {
            return Err(invalid("task surface decision byte budget exceeded"));
        }
        let bytes = ramflux_protocol::decode_base64url(encoded)
            .map_err(|_| invalid("invalid task surface receipt"))?;
        let receipt =
            Carrier::decode(&bytes)?.ok_or_else(|| invalid("surface decision receipt missing"))?;
        if receipt.conversation_id != conversation
            || receipt.surface_id != surface
            || receipt.sender_principal_id != author
            || receipt.author_principal_id != author
        {
            return Err(invalid("task surface decision context mismatch"));
        }
        let Payload::ActionReceipt { original, action } =
            self.verify_surface_carrier(&receipt, author, &receipt.sender_device_id)?
        else {
            return Err(invalid("task surface proof must be a creator receipt"));
        };
        if original.sender_principal_id != requester {
            return Err(invalid("task surface action must be signed by requester"));
        }
        if !matches!(
            self.verify_surface_carrier(&original, requester, &original.sender_device_id)?,
            Payload::Action(_)
        ) {
            return Err(invalid("task decision original action missing"));
        }
        let proof = receipt
            .snapshot
            .as_ref()
            .ok_or_else(|| invalid("task surface decision snapshot missing"))?;
        let witnessed = proof.restore(&receipt, &SurfaceState::default(), action.version())?;
        witnessed.validate_action(&action).map_err(|e| invalid(&e.to_string()))?;
        let binding = action
            .task_binding()
            .ok_or_else(|| invalid("task surface action has no task binding"))?;
        if binding.task_id != resolution.task_id || binding.step_id != resolution.step_id {
            return Err(invalid("task surface action belongs to another task or step"));
        }
        let expected = match resolution.decision {
            TaskDecision::Resume => "resume",
            TaskDecision::Deny => "deny",
        };
        if action.values()["decision"] != expected {
            return Err(invalid("task surface action outcome differs from requested resolution"));
        }
        if let Some((record, current)) = self.surface_state_scoped(conversation, author, surface)? {
            if record.author_device_id != receipt.sender_device_id
                || current.version() != action.version()
                || current.hash() != Some(action.surface_hash())
                || current.is_closed()
            {
                return Err(invalid("task surface action is not for the current surface"));
            }
        } else if require_stored {
            return Err(invalid("task decision surface not found"));
        }
        let reference = receipt.surface_reference()?;
        let id = ramflux_protocol::hash_base64url(
            "ramflux.surface.action_delivery.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                &reference,
                &original.sender_principal_id,
                &original.message_id,
            ))?,
        );
        if id != resolution.decision_id {
            return Err(invalid("task surface decision id mismatch"));
        }
        if require_stored {
            let stored = self.task_surface_receipt(conversation, surface, author, &id)?;
            if stored != encoded {
                return Err(invalid("task surface receipt differs from stored decision"));
            }
        }
        Ok(serde_json::to_string(&(reference, action.version(), action.action_id(), requester))?)
    }
}
