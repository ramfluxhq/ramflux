// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant generated Surface Inner conversion (S10a P16).
//! This module neither sends a carrier nor admits a stored event.
use super::generated_content::GeneratedEventStream;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;

/// Encode a generated Surface Inner. Additive candidate API; does not send or persist.
/// # Errors
/// Rejects a missing payload, a failed native check, or invalid Inner.
pub fn validate_generated_surface(surface: &g::Surface) -> Result<(), SdkError> {
    match surface.payload.as_ref() {
        Some(g::surface::Payload::Delivery(delivery)) => validate_delivery(delivery),
        Some(g::surface::Payload::ResyncRequest(request)) => validate_resync(request),
        Some(g::surface::Payload::OwnHistory(export)) => {
            if export.controls.is_empty() && export.checkpoints.is_empty() {
                Err(refused("surface own-history requires controls or checkpoints"))
            } else {
                Ok(())
            }
        }
        None => Err(refused("surface requires delivery, resync or own-history")),
    }
}

/// Original action signer must remain bound on the action carrier and its receipt.
/// # Errors
/// Refuses a missing signature or a sender that is not the original signer.
pub fn authorize_surface_action_signer(
    original_signer: &str,
    carrier: &g::SurfaceCarrier,
) -> Result<(), SdkError> {
    if original_signer.is_empty()
        || carrier.signature.is_empty()
        || carrier.sender_principal_id != original_signer
    {
        return Err(refused("surface action requires the original signer binding"));
    }
    match carrier.payload.as_ref() {
        Some(g::surface_carrier::Payload::Action(_)) => Ok(()),
        Some(g::surface_carrier::Payload::ActionReceipt(inner)) => {
            if !matches!(inner.payload, Some(g::surface_carrier::Payload::Action(_))) {
                return Err(refused("surface action receipt must wrap the original action"));
            }
            authorize_surface_action_signer(original_signer, inner)
        }
        _ => Err(refused("surface action signer applies to action or action receipt")),
    }
}

fn validate_delivery(delivery: &g::SurfaceDelivery) -> Result<(), SdkError> {
    match delivery.kind.as_ref().and_then(|kind| kind.value.as_ref()) {
        Some(g::surface_control_kind::Value::Peer(_) | g::surface_control_kind::Value::Own(_)) => {}
        None => return Err(refused("surface delivery requires peer or own kind")),
    }
    let Some(carrier) = delivery.carrier.as_ref() else {
        return Err(refused("surface delivery requires a carrier"));
    };
    validate_carrier(carrier)
}

fn validate_carrier(carrier: &g::SurfaceCarrier) -> Result<(), SdkError> {
    if carrier.conversation_id.is_empty()
        || carrier.surface_id.is_empty()
        || carrier.sender_principal_id.is_empty()
        || carrier.author_principal_id.is_empty()
        || carrier.signature.is_empty()
    {
        return Err(refused("surface carrier requires ids, sender, author and signature"));
    }
    match carrier.payload.as_ref() {
        Some(g::surface_carrier::Payload::Event(event)) => validate_event(event),
        Some(g::surface_carrier::Payload::Action(action)) => validate_action(action),
        Some(g::surface_carrier::Payload::ActionReceipt(inner)) => {
            if matches!(inner.payload, Some(g::surface_carrier::Payload::ActionReceipt(_))) {
                return Err(refused("surface action receipt is one level only"));
            }
            validate_carrier(inner)?;
            authorize_surface_action_signer(&carrier.sender_principal_id, inner)
        }
        None => Err(refused("surface carrier requires event, action or action receipt")),
    }
}

fn validate_event(event: &g::SurfaceEvent) -> Result<(), SdkError> {
    if event.conversation_id.is_empty() {
        return Err(refused("surface event requires a conversation id"));
    }
    match event.command.as_ref().and_then(|command| command.value.as_ref()) {
        Some(g::surface_command::Value::CreateSurface(body)) => {
            let Some(create) = body.value.as_ref() else {
                return Err(refused("create surface command is missing"));
            };
            if create.surface_id.is_empty() || create.surface_type.is_none() {
                Err(refused("create surface requires id and type"))
            } else {
                Ok(())
            }
        }
        Some(g::surface_command::Value::UpdateComponents(body)) => {
            let Some(update) = body.value.as_ref() else {
                return Err(refused("update components command is missing"));
            };
            require_surface_hashes(
                &update.surface_id,
                &update.base_surface_hash,
                &update.new_surface_hash,
            )
        }
        Some(g::surface_command::Value::UpdateDataModel(body)) => {
            let Some(update) = body.value.as_ref() else {
                return Err(refused("update data model command is missing"));
            };
            require_surface_hashes(
                &update.surface_id,
                &update.base_surface_hash,
                &update.new_surface_hash,
            )
        }
        Some(g::surface_command::Value::DeleteSurface(body)) => {
            let Some(delete) = body.value.as_ref() else {
                return Err(refused("delete surface command is missing"));
            };
            if delete.surface_id.is_empty() || delete.reason.is_none() {
                Err(refused("delete surface requires id and reason"))
            } else {
                Ok(())
            }
        }
        Some(g::surface_command::Value::PatchSurface(body)) => validate_patch(body),
        Some(g::surface_command::Value::StreamAppend(body)) => {
            let Some(append) = body.value.as_ref() else {
                return Err(refused("stream append command is missing"));
            };
            if append.surface_id.is_empty() || append.component_id.is_empty() {
                Err(refused("stream append requires surface and component ids"))
            } else {
                Ok(())
            }
        }
        None => Err(refused("surface event requires a typed command")),
    }
}

fn validate_patch(body: &g::SurfaceCommandPatchSurface) -> Result<(), SdkError> {
    let Some(patch) = body.value.as_ref() else {
        return Err(refused("patch surface command is missing"));
    };
    require_surface_hashes(&patch.surface_id, &patch.base_surface_hash, &patch.new_surface_hash)?;
    if patch.ops.is_empty() {
        return Err(refused("patch surface requires operations"));
    }
    for op in &patch.ops {
        match op.value.as_ref() {
            Some(
                g::surface_patch_op::Value::ReplaceBlock(_)
                | g::surface_patch_op::Value::InsertBlock(_)
                | g::surface_patch_op::Value::RemoveBlock(_)
                | g::surface_patch_op::Value::SetActions(_)
                | g::surface_patch_op::Value::SetFallbackText(_),
            ) => {}
            None => return Err(refused("surface patch op requires a typed arm")),
        }
    }
    Ok(())
}

fn validate_action(action: &g::SurfaceAction) -> Result<(), SdkError> {
    if action.conversation_id.is_empty()
        || action.surface_id.is_empty()
        || action.action_id.is_empty()
        || action.surface_hash.is_empty()
    {
        return Err(refused("surface action requires ids and surface hash"));
    }
    Ok(())
}

fn validate_resync(request: &g::SurfaceResyncRequest) -> Result<(), SdkError> {
    if request.conversation_id.is_empty()
        || request.surface_id.is_empty()
        || request.surface_ref.is_empty()
        || request.author.is_empty()
    {
        return Err(refused("surface resync requires conversation, surface, ref and author"));
    }
    Ok(())
}

fn require_surface_hashes(surface_id: &str, base: &str, next: &str) -> Result<(), SdkError> {
    if surface_id.is_empty() || base.is_empty() || next.is_empty() {
        Err(refused("surface command requires id and hashes"))
    } else {
        Ok(())
    }
}

fn refused(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}

impl RamfluxClient {
    /// Encode a generated Surface Inner. Does not send or persist.
    /// # Errors
    /// Same as [`validate_generated_surface`].
    pub fn encode_generated_surface(
        stream: &mut GeneratedEventStream,
        event_id: Vec<u8>,
        surface: g::Surface,
    ) -> Result<Vec<u8>, SdkError> {
        validate_generated_surface(&surface)?;
        let identity = stream.next(event_id)?;
        Self::encode_generated_inner(
            identity,
            &g::Content { value: Some(g::content::Value::Surface(surface)) },
        )
    }

    /// Candidate Surface native checks. Does not send or persist.
    /// # Errors
    /// Same as [`validate_generated_surface`].
    pub fn validate_generated_surface(surface: &g::Surface) -> Result<(), SdkError> {
        validate_generated_surface(surface)
    }

    /// Candidate original-signer binding for a Surface action or receipt.
    /// # Errors
    /// Same as [`authorize_surface_action_signer`].
    pub fn authorize_generated_surface_action_signer(
        original_signer: &str,
        carrier: &g::SurfaceCarrier,
    ) -> Result<(), SdkError> {
        authorize_surface_action_signer(original_signer, carrier)
    }
}

#[cfg(test)]
mod tests;
