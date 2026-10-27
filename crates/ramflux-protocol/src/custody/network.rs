// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Framed born-v3 registration/session requests; these never carry a legacy branch proof.

use super::{
    BindingMode, BranchChallenge, BranchProofV3, DeviceRef, DeviceSet, Envelope,
    NodeIdentityRecord, RelayAcceptance,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_CUSTODY_FRAME_BYTES: usize = 5 * 1024 * 1024;
pub const CUSTODY_RPC_PATH: &str = "/v3/custody/rpc";
pub const CUSTODY_REQUEST_PATH: &str = "/v3/custody/session";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub record: Envelope<DeviceSet>,
    pub compacted_ids: Option<Vec<String>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodyProofAction {
    Publish { publication: Box<Publication> },
    Register { prekey_bundle: Value },
    OpenSession,
}
impl CustodyProofAction {
    #[must_use]
    pub const fn capability(&self) -> &'static str {
        match self {
            Self::Publish { .. } | Self::Register { .. } => "register",
            Self::OpenSession => "message",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodySessionAction {
    Lookup { device_ref: DeviceRef },
    Submit { envelope: Box<crate::Envelope> },
    Inbox { after_seq: u64, limit: u32 },
    Ack { ack: Box<crate::Ack> },
    Close,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodyClientFrame {
    CustodyOpen { binding_mode: BindingMode },
    NodeIdentity { record_hash: Option<String> },
    Challenge { device_ref: DeviceRef, action: CustodyProofAction },
    Prove { action: CustodyProofAction, proof: Box<Envelope<BranchProofV3>> },
    Request { session_id: String, request: Box<crate::SignedRequest>, action: CustodySessionAction },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyRefusal {
    Unsupported,
    InvalidInput,
    AuthorityUnavailable,
    PrincipalIdTaken,
    ChallengeUnknown,
    ChallengeExpired,
    Replay,
    BindingRefused,
    SessionRequired,
    SessionExpired,
    UpdateRequired,
    Capacity,
    PersistenceUnavailable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodySession {
    pub session_id: String,
    pub device_ref: DeviceRef,
    pub target_delivery_id: String,
    pub record_hash: String,
    pub proof_hash: String,
    pub binding_mode: BindingMode,
    pub expires_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyPeer {
    pub publication: Publication,
    pub custodian_publication: Option<Publication>,
    pub device_ref: DeviceRef,
    pub target_delivery_id: String,
    pub prekey_bundle: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodyServerFrame {
    NodeIdentity {
        record: Box<Envelope<NodeIdentityRecord>>,
        audience: String,
        binding_mode: BindingMode,
        proxy_key_custody: Option<String>,
    },
    Challenge {
        challenge: BranchChallenge,
    },
    Published {
        record_hash: String,
    },
    Registered {
        device_ref: DeviceRef,
        target_delivery_id: String,
    },
    SessionEstablished {
        session: CustodySession,
    },
    Peer {
        peer: Box<CustodyPeer>,
    },
    Submitted {
        envelope_id: String,
        outcome: String,
    },
    Inbox {
        entries: Vec<Value>,
    },
    Acked {
        inbox_seq: u64,
    },
    Closed,
    Refused {
        code: CustodyRefusal,
    },
}
/// Authenticated internal mesh request. Direct-exporter evidence is deliberately
/// absent: only the listener holding the actual TLS connection may supply it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodyMeshRequest {
    Disconnect {
        connection_id: String,
    },
    NodeIdentity {
        record_hash: Option<String>,
    },
    Challenge {
        device_ref: DeviceRef,
        action: CustodyProofAction,
        binding_mode: BindingMode,
        client_source: String,
        connection_id: String,
    },
    Prove {
        action: CustodyProofAction,
        proof: Box<Envelope<BranchProofV3>>,
        receipt: Option<Box<Envelope<RelayAcceptance>>>,
        connection_id: String,
    },
    Request {
        connection_id: String,
        session_id: String,
        request: Box<crate::SignedRequest>,
        action: CustodySessionAction,
    },
}

impl std::fmt::Display for CustodyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CustodyRefusal {}
/// Hash the complete operation before issuing its one-use challenge.
/// # Errors
/// Rejects canonical serialization failure.
pub fn custody_action_hash(action: &CustodyProofAction) -> Result<String, crate::ProtocolError> {
    super::framed_hash("ramflux.identity.custody_action.v1", action)
}
/// Hash the complete per-session operation for its signed request.
/// # Errors
/// Rejects canonical serialization failure.
pub fn custody_session_action_hash(
    action: &CustodySessionAction,
) -> Result<String, crate::ProtocolError> {
    super::framed_hash("ramflux.identity.custody_session_action.v1", action)
}
