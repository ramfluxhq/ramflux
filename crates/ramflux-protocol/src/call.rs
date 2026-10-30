// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-to-one voice signaling and opaque relay allocation wire contracts.
use serde::{Deserialize, Serialize};

/// A device bound to its account root, rather than an unqualified device label.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallEndpoint {
    pub principal_id: String,
    pub root_public_key: String,
    pub device_id: String,
}
/// Stable machine-readable source for a call that ended with `end_reason = "failed"`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceCallFailureReason {
    AuthorityUnavailable,
    AuthorityRefused,
    RelayUnavailable,
    MediaLeaseExpired,
    DaemonRestarted,
    #[default]
    SignalingUnavailable,
}
/// Authenticated signaling action carried inside a pair-session control envelope.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallAction {
    Invite {
        base_key: String,
    },
    Ringing,
    Answer {
        base_key: String,
    },
    Ack {
        allocation: Box<VoicePeerAllocation>,
    },
    Ready {
        consent: Box<VoiceLeaseConsent>,
    },
    Reject,
    Busy,
    Hangup,
    Timeout,
    Failed {
        #[serde(default)]
        reason: VoiceCallFailureReason,
    },
    AnsweredElsewhere,
    Rekey {
        generation: u64,
        base_key: String,
    },
    RekeyAck {
        generation: u64,
        base_key: String,
    },
}
/// No `Debug`: actions contain media secrets and allocation bearer credentials.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallControl {
    pub schema: String,
    pub call_id: String,
    pub conversation_id: String,
    pub caller: CallEndpoint,
    pub callee: CallEndpoint,
    pub sender: CallEndpoint,
    pub seq: u64,
    pub created_at: i64,
    pub body: CallAction,
    pub signature: String,
}
/// Issuance scope signed by a live authenticated caller session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceAllocationRequest {
    pub call_id: String,
    pub caller: CallEndpoint,
    pub callee: CallEndpoint,
}
/// One participant's credentials, issued only over that participant's authenticated gateway.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceAllocation {
    pub lease_id: String,
    pub endpoint: String,
    pub side: u8,
    pub token: String,
    pub rebind_key: String,
    pub expires_at: u64,
    pub hard_expires_at: u64,
}
/// Public lease advertisement; no credential crosses the peer signaling channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VoicePeerAllocation {
    pub lease_id: String,
    pub endpoint: String,
    pub expires_at: u64,
    pub hard_expires_at: u64,
}
/// Callee-device signature authorizing exactly one immutable lease scope and deadline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceLeaseConsent {
    pub scope: VoiceAllocationRequest,
    pub lease_id: String,
    pub expires_at: u64,
    pub signature: String,
}
/// Domain-separated consent bytes; never include media key material or conversation identifiers.
/// # Errors
/// Returns protocol serialization errors.
pub fn voice_lease_consent_bytes(
    consent: &VoiceLeaseConsent,
) -> Result<Vec<u8>, crate::ProtocolError> {
    crate::canonical_json_bytes(&(
        "ramflux.voice.lease-consent.v1",
        &consent.scope,
        &consent.lease_id,
        consent.expires_at,
    ))
}
impl VoiceAllocation {
    #[must_use]
    pub fn for_callee(&self) -> VoicePeerAllocation {
        VoicePeerAllocation {
            lease_id: self.lease_id.clone(),
            endpoint: self.endpoint.clone(),
            expires_at: self.expires_at,
            hard_expires_at: self.hard_expires_at,
        }
    }
}
impl std::fmt::Debug for VoiceAllocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoiceAllocation")
            .field("lease_id", &self.lease_id)
            .field("side", &self.side)
            .finish_non_exhaustive()
    }
}
/// Daemon-owned public call state, shared by list, mutation replies and journal events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallRow {
    pub call_id: String,
    pub conversation_id: String,
    pub peer_id: String,
    pub direction: String,
    pub state: String,
    pub end_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<VoiceCallFailureReason>,
    pub seq: u64,
    pub created_at: i64,
    pub answered_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub media_generation: u64,
}

/// A node-mesh lease mutation; UDP keepalives cannot renew authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum VoiceLeaseRequest {
    Allocate { scope: VoiceAllocationRequest },
    Accept { consent: Box<VoiceLeaseConsent> },
    Renew { consent: Box<VoiceLeaseConsent> },
    Release { scope: VoiceAllocationRequest },
}
/// Secret-free lease mutation acknowledgment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VoiceLeaseStatus {
    pub expires_at: u64,
}

/// Authenticated client request, bound to the live gateway session and exact lease mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceLeaseFrame {
    pub signed_request: crate::SignedRequest,
    pub body: VoiceLeaseRequest,
}
/// Redacted response variants, shared by both gateway transports.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum VoiceLeaseResponse {
    Allocation { allocation: VoiceAllocation },
    Status { status: VoiceLeaseStatus },
    Refused { reason: VoiceCallFailureReason },
}

impl Drop for VoiceAllocation {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
        self.rebind_key.zeroize();
    }
}
impl Drop for CallAction {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::Invite { base_key }
            | Self::Answer { base_key }
            | Self::Rekey { base_key, .. }
            | Self::RekeyAck { base_key, .. } => base_key.zeroize(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CallAction, VoiceCallFailureReason};

    #[test]
    fn legacy_failed_control_defaults_to_a_typed_signaling_failure() -> serde_json::Result<()> {
        let action: CallAction = serde_json::from_value(serde_json::json!({"action":"failed"}))?;
        assert!(matches!(
            action,
            CallAction::Failed { reason: VoiceCallFailureReason::SignalingUnavailable }
        ));
        Ok(())
    }
}
