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
/// Authenticated signaling action carried inside a pair-session control envelope.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallAction {
    Invite { base_key: String },
    Ringing,
    Answer { base_key: String },
    Ack { allocation: Box<VoicePeerAllocation> },
    Reject,
    Busy,
    Hangup,
    Timeout,
    Failed,
    AnsweredElsewhere,
    Rekey { generation: u64, base_key: String },
    RekeyAck { generation: u64, base_key: String },
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
/// Both endpoint credentials; only the matching credential is exposed to each media engine.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceAllocation {
    pub endpoint: String,
    pub caller_token: String,
    pub callee_token: String,
    pub expires_at: u64,
}
/// Only the callee's credential crosses the encrypted call-control channel.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VoicePeerAllocation {
    pub endpoint: String,
    pub token: String,
    pub expires_at: u64,
}
impl VoiceAllocation {
    #[must_use]
    pub fn for_callee(&self) -> VoicePeerAllocation {
        VoicePeerAllocation {
            endpoint: self.endpoint.clone(),
            token: self.callee_token.clone(),
            expires_at: self.expires_at,
        }
    }
}
impl Drop for VoicePeerAllocation {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
    }
}
/// Redacted diagnostics prevent accidental bearer-token disclosure in frame logging.
impl std::fmt::Debug for VoiceAllocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoiceAllocation").field("endpoint", &self.endpoint).finish_non_exhaustive()
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
    Renew { scope: VoiceAllocationRequest },
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
}

impl Drop for VoiceAllocation {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.caller_token.zeroize();
        self.callee_token.zeroize();
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
