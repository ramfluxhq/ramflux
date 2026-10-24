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
    Ack { allocation: Box<VoiceAllocation> },
    Reject,
    Busy,
    Hangup,
    Timeout,
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
/// An issuer-certified, short-lived relay bearer capability, never a media key.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceToken {
    pub schema: String,
    pub call_id: String,
    pub caller: CallEndpoint,
    pub callee: CallEndpoint,
    pub side: u8,
    pub allocation_id: String,
    pub relay_endpoint: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub certificate: crate::GatewayIssuerCertificate,
    pub signature: String,
}
/// Both endpoint credentials; only the matching credential is exposed to each media engine.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceAllocation {
    pub endpoint: String,
    pub caller_token: VoiceToken,
    pub callee_token: VoiceToken,
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
