// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant generated Call Inner conversion (S10a P16).
//! This module neither sends a carrier nor admits a stored event.
use super::generated_content::GeneratedEventStream;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;
pub(crate) mod native;

/// Native `CallControl` checks: 13 actions, signer, lease consent/key/rekey.
/// # Errors
/// Refuses a missing control, unsigned action, or incomplete lease/key fields.
pub fn validate_generated_call(call: &g::Call) -> Result<(), SdkError> {
    let Some(control) = call.control.as_ref() else {
        return Err(refused("call requires CallControl"));
    };
    validate_call_control(control)
}

/// Original Call action signer is the authenticated sender plus signature.
/// # Errors
/// Refuses a missing signature or a sender that is not the original signer.
pub fn authorize_call_action_signer(
    original_signer: &str,
    control: &g::CallControl,
) -> Result<(), SdkError> {
    let Some(sender) = control.sender.as_ref() else {
        return Err(refused("call action requires a sender"));
    };
    if original_signer.is_empty()
        || control.signature.is_empty()
        || sender.principal_id != original_signer
    {
        return Err(refused("call action requires the original signer binding"));
    }
    Ok(())
}

/// Native voice lease: consent, key and rekey stay bound to the call.
/// # Errors
/// Refuses missing lease id/expiry/signature or a call-id mismatch.
pub fn validate_voice_lease(consent: &g::VoiceLeaseConsent, call_id: &str) -> Result<(), SdkError> {
    if consent.lease_id.is_empty() || consent.expires_at == 0 || consent.signature.is_empty() {
        return Err(refused("voice lease requires id, expiry and signature"));
    }
    let Some(scope) = consent.scope.as_ref() else {
        return Err(refused("voice lease requires an allocation scope"));
    };
    if scope.call_id.is_empty() || scope.call_id != call_id {
        return Err(refused("voice lease call id must match the Call"));
    }
    Ok(())
}

fn validate_call_control(control: &g::CallControl) -> Result<(), SdkError> {
    if control.call_id.is_empty() || control.conversation_id.is_empty() || control.seq == 0 {
        return Err(refused("call control requires call id, conversation and seq"));
    }
    let Some(from) = control.caller.as_ref() else {
        return Err(refused("call control requires a caller"));
    };
    let Some(peer) = control.callee.as_ref() else {
        return Err(refused("call control requires a callee"));
    };
    let Some(sender) = control.sender.as_ref() else {
        return Err(refused("call control requires a sender"));
    };
    if from.principal_id.is_empty()
        || peer.principal_id.is_empty()
        || sender.principal_id.is_empty()
    {
        return Err(refused("call endpoints require principal ids"));
    }
    if sender.principal_id != from.principal_id && sender.principal_id != peer.principal_id {
        return Err(refused("call sender must be the caller or callee"));
    }
    authorize_call_action_signer(&sender.principal_id, control)?;
    validate_call_action(
        &control.call_id,
        control.body.as_ref().and_then(|body| body.value.as_ref()),
    )
}

fn validate_call_action(
    call_id: &str,
    action: Option<&g::call_action::Value>,
) -> Result<(), SdkError> {
    match action {
        Some(g::call_action::Value::Invite(invite)) => require_key(&invite.base_key, "invite"),
        Some(g::call_action::Value::Answer(answer)) => require_key(&answer.base_key, "answer"),
        Some(g::call_action::Value::Ready(ready)) => {
            let Some(consent) = ready.consent.as_ref() else {
                return Err(refused("call ready requires voice lease consent"));
            };
            validate_voice_lease(consent, call_id)
        }
        Some(g::call_action::Value::Ack(ack)) => {
            let Some(allocation) = ack.allocation.as_ref() else {
                return Err(refused("call ack requires a peer allocation"));
            };
            if allocation.lease_id.is_empty() || allocation.expires_at == 0 {
                Err(refused("call ack allocation requires lease id and expiry"))
            } else {
                Ok(())
            }
        }
        Some(
            g::call_action::Value::Ringing(_)
            | g::call_action::Value::Reject(_)
            | g::call_action::Value::Busy(_)
            | g::call_action::Value::Hangup(_)
            | g::call_action::Value::Timeout(_)
            | g::call_action::Value::Failed(_)
            | g::call_action::Value::AnsweredElsewhere(_),
        ) => Ok(()),
        Some(g::call_action::Value::Rekey(rekey)) => {
            require_rekey(rekey.generation, &rekey.base_key)
        }
        Some(g::call_action::Value::RekeyAck(ack)) => require_rekey(ack.generation, &ack.base_key),
        None => Err(refused("call control requires one of 13 typed actions")),
    }
}

fn require_key(base_key: &str, action: &str) -> Result<(), SdkError> {
    if base_key.is_empty() {
        Err(refused(&format!("call {action} requires a base key")))
    } else {
        Ok(())
    }
}

fn require_rekey(generation: u64, base_key: &str) -> Result<(), SdkError> {
    if generation == 0 || base_key.is_empty() {
        Err(refused("call rekey requires generation and base key"))
    } else {
        Ok(())
    }
}

fn refused(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}

impl RamfluxClient {
    /// Convert the signed native call document through the generated model without changing it.
    /// # Errors
    /// Refuses incomplete native fields or an invalid generated Inner.
    pub fn encode_native_call_inner(
        stream: &mut GeneratedEventStream,
        event_id: Vec<u8>,
        control: &ramflux_protocol::CallControl,
    ) -> Result<Vec<u8>, SdkError> {
        Self::encode_generated_call(stream, event_id, native::from_native(control)?)
    }

    /// Encode a generated Call Inner. Does not send or persist.
    /// # Errors
    /// Same as [`validate_generated_call`].
    pub fn encode_generated_call(
        stream: &mut GeneratedEventStream,
        event_id: Vec<u8>,
        call: g::Call,
    ) -> Result<Vec<u8>, SdkError> {
        validate_generated_call(&call)?;
        let identity = stream.next(event_id)?;
        Self::encode_generated_inner(
            identity,
            &g::Content { value: Some(g::content::Value::Call(call)) },
        )
    }

    /// Candidate Call native checks. Does not send or persist.
    /// # Errors
    /// Same as [`validate_generated_call`].
    pub fn validate_generated_call(call: &g::Call) -> Result<(), SdkError> {
        validate_generated_call(call)
    }

    /// Candidate original-signer binding for a Call action.
    /// # Errors
    /// Same as [`authorize_call_action_signer`].
    pub fn authorize_generated_call_action_signer(
        original_signer: &str,
        control: &g::CallControl,
    ) -> Result<(), SdkError> {
        authorize_call_action_signer(original_signer, control)
    }

    /// Candidate native voice-lease checks. Does not send or persist.
    /// # Errors
    /// Same as [`validate_voice_lease`].
    pub fn validate_generated_voice_lease(
        consent: &g::VoiceLeaseConsent,
        call_id: &str,
    ) -> Result<(), SdkError> {
        validate_voice_lease(consent, call_id)
    }
}

#[cfg(test)]
mod tests;
