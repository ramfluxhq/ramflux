// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lossless typed Call/native bridge. Native signatures and lease consent keep their owners.
use super::{g, refused};
use crate::SdkError;
use ramflux_protocol as n;

fn endpoint(value: &n::CallEndpoint) -> g::CallEndpoint {
    g::CallEndpoint {
        principal_id: value.principal_id.clone(),
        root_public_key: value.root_public_key.clone(),
        device_id: value.device_id.clone(),
    }
}
fn native_endpoint(value: Option<g::CallEndpoint>) -> Result<n::CallEndpoint, SdkError> {
    let value = value.ok_or_else(|| refused("call endpoint missing"))?;
    Ok(n::CallEndpoint {
        principal_id: value.principal_id,
        root_public_key: value.root_public_key,
        device_id: value.device_id,
    })
}
fn consent(value: &n::VoiceLeaseConsent) -> g::VoiceLeaseConsent {
    g::VoiceLeaseConsent {
        scope: Some(g::VoiceAllocationRequest {
            call_id: value.scope.call_id.clone(),
            caller: Some(endpoint(&value.scope.caller)),
            callee: Some(endpoint(&value.scope.callee)),
        }),
        lease_id: value.lease_id.clone(),
        expires_at: value.expires_at,
        signature: value.signature.clone(),
    }
}
fn native_consent(value: g::VoiceLeaseConsent) -> Result<n::VoiceLeaseConsent, SdkError> {
    let scope = value.scope.ok_or_else(|| refused("voice lease scope missing"))?;
    Ok(n::VoiceLeaseConsent {
        scope: n::VoiceAllocationRequest {
            call_id: scope.call_id,
            caller: native_endpoint(scope.caller)?,
            callee: native_endpoint(scope.callee)?,
        },
        lease_id: value.lease_id,
        expires_at: value.expires_at,
        signature: value.signature,
    })
}

pub(crate) fn from_native(value: &n::CallControl) -> g::Call {
    g::Call {
        control: Some(g::CallControl {
            schema: value.schema.clone(),
            call_id: value.call_id.clone(),
            conversation_id: value.conversation_id.clone(),
            caller: Some(endpoint(&value.caller)),
            callee: Some(endpoint(&value.callee)),
            sender: Some(endpoint(&value.sender)),
            seq: value.seq,
            created_at: value.created_at,
            body: Some(g::CallAction { value: Some(action(&value.body)) }),
            signature: value.signature.clone(),
        }),
    }
}

pub(crate) fn to_native(value: g::Call) -> Result<n::CallControl, SdkError> {
    super::validate_generated_call(&value)?;
    let control = value.control.ok_or_else(|| refused("call control missing"))?;
    let action =
        control.body.and_then(|body| body.value).ok_or_else(|| refused("call action missing"))?;
    Ok(n::CallControl {
        schema: control.schema,
        call_id: control.call_id,
        conversation_id: control.conversation_id,
        caller: native_endpoint(control.caller)?,
        callee: native_endpoint(control.callee)?,
        sender: native_endpoint(control.sender)?,
        seq: control.seq,
        created_at: control.created_at,
        body: native_action(action)?,
        signature: control.signature,
    })
}

fn action(value: &n::CallAction) -> g::call_action::Value {
    use g::call_action::Value as G;
    use n::CallAction as N;
    match value {
        N::Invite { base_key } => G::Invite(g::CallActionInvite { base_key: base_key.clone() }),
        N::Ringing => G::Ringing(g::CallActionRinging {}),
        N::Answer { base_key } => G::Answer(g::CallActionAnswer { base_key: base_key.clone() }),
        N::Ack { allocation } => G::Ack(g::CallActionAck {
            allocation: Some(g::VoicePeerAllocation {
                lease_id: allocation.lease_id.clone(),
                endpoint: allocation.endpoint.clone(),
                expires_at: allocation.expires_at,
                hard_expires_at: allocation.hard_expires_at,
            }),
        }),
        N::Ready { consent: value } => {
            G::Ready(g::CallActionReady { consent: Some(consent(value)) })
        }
        N::Reject => G::Reject(g::CallActionReject {}),
        N::Busy => G::Busy(g::CallActionBusy {}),
        N::Hangup => G::Hangup(g::CallActionHangup {}),
        N::Timeout => G::Timeout(g::CallActionTimeout {}),
        N::Failed => G::Failed(g::CallActionFailed {}),
        N::AnsweredElsewhere => G::AnsweredElsewhere(g::CallActionAnsweredElsewhere {}),
        N::Rekey { generation, base_key } => {
            G::Rekey(g::CallActionRekey { generation: *generation, base_key: base_key.clone() })
        }
        N::RekeyAck { generation, base_key } => G::RekeyAck(g::CallActionRekeyAck {
            generation: *generation,
            base_key: base_key.clone(),
        }),
    }
}

fn native_action(value: g::call_action::Value) -> Result<n::CallAction, SdkError> {
    use g::call_action::Value as G;
    use n::CallAction as N;
    Ok(match value {
        G::Invite(value) => N::Invite { base_key: value.base_key },
        G::Ringing(_) => N::Ringing,
        G::Answer(value) => N::Answer { base_key: value.base_key },
        G::Ack(value) => {
            let allocation = value.allocation.ok_or_else(|| refused("voice allocation missing"))?;
            N::Ack {
                allocation: Box::new(n::VoicePeerAllocation {
                    lease_id: allocation.lease_id,
                    endpoint: allocation.endpoint,
                    expires_at: allocation.expires_at,
                    hard_expires_at: allocation.hard_expires_at,
                }),
            }
        }
        G::Ready(value) => N::Ready {
            consent: Box::new(native_consent(
                value.consent.ok_or_else(|| refused("voice consent missing"))?,
            )?),
        },
        G::Reject(_) => N::Reject,
        G::Busy(_) => N::Busy,
        G::Hangup(_) => N::Hangup,
        G::Timeout(_) => N::Timeout,
        G::Failed(_) => N::Failed,
        G::AnsweredElsewhere(_) => N::AnsweredElsewhere,
        G::Rekey(value) => N::Rekey { generation: value.generation, base_key: value.base_key },
        G::RekeyAck(value) => {
            N::RekeyAck { generation: value.generation, base_key: value.base_key }
        }
    })
}
