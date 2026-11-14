// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Correlated account/session and node-service carriers for unified contact reach.
use super::{
    Admission, Challenge, ChallengeRequest, Cost, DeliveryReach, Placement, ReachPolicy,
    StateManifest, StatePage, Submission, actor, digest, directory, invalid, node, safe,
};
use crate::custody::{CustodyAuthority, DeviceRef, Envelope as Signed};
use serde::{Deserialize, Serialize};

pub const CAPABILITY: &str = "contact_reach.v1";
pub const SNAPSHOT_DOMAIN: &str = "ramflux.contact.foreign_snapshot.v1";
pub const QUERY_HASH_DOMAIN: &str = "ramflux.contact.foreign_query.v1";
pub const PAYLOAD_HASH_DOMAIN: &str = "ramflux.contact.foreign_payload.v1";
pub const NOTICE_DOMAIN: &str = "ramflux.contact.notice.v1";
pub const MAX_FRAME_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;
pub const RECIPIENT_PATH: &str = "/internal/contact/recipient/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerKind {
    Owner,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientRequest {
    pub kind: OwnerKind,
    pub request_id: String,
    pub remaining_ms: u64,
    pub recipient_root: String,
    pub actor: DeviceRef,
    pub operation: Operation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerResultKind {
    OwnerResult,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientResponse {
    pub kind: OwnerResultKind,
    pub request_id: String,
    pub result: OperationResult,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayReachKind {
    ContactForeign,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReachRequest {
    pub frame_type: GatewayReachKind,
    pub request: Request,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeBase {
    pub epoch: u64,
    pub hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub version: u32,
    pub source_node: String,
    pub target_node: String,
    pub account_anchor: String,
    pub card_hash: Option<String>,
    pub nonce: String,
    pub base: Option<HomeBase>,
    pub device_ref: Option<DeviceRef>,
}
impl Query {
    /// Validate exact anchor/device/correlation and source/target names before any dial.
    /// # Errors
    /// Refuses malformed selectors, unsafe base floors and oversized requests.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        node(&self.source_node)?;
        node(&self.target_node)?;
        digest(&self.account_anchor)?;
        digest(&self.nonce)?;
        if let Some(hash) = &self.card_hash {
            digest(hash)?;
        }
        if let Some(base) = &self.base {
            safe(base.epoch)?;
            digest(&base.hash)?;
        }
        if let Some(reference) = &self.device_ref {
            actor(reference)?;
            if reference.account_anchor != self.account_anchor {
                return Err(invalid("query device anchor mismatch"));
            }
        }
        if self.version != 1 || crate::canonical_json_bytes(self)?.len() > 4096 {
            return Err(invalid("query version or byte budget"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub source_node: String,
    pub target_node: String,
    pub account_anchor: String,
    pub request_nonce: String,
    pub request_hash: String,
    pub payload_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalCustodian {
    pub record_hash: String,
    pub authority: CustodyAuthority,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryBinding {
    pub binding: Signed<directory::Binding>,
    pub receipt: Signed<directory::IndexReceipt>,
}
/// Existing service/SDK documents retain their original schemas and signatures.
/// Consumers decode and validate these nested values with their owning codecs;
/// the complete values, including explicit nulls, are covered by `payload_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub client: crate::WellKnownClientRecord,
    pub server: serde_json::Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPayload {
    pub home: crate::home_migration::ResolveResult,
    pub discovery: Discovery,
    pub manifest: serde_json::Value,
    pub prekey: Option<serde_json::Value>,
    pub node_continuity: Vec<serde_json::Value>,
    pub reach: Signed<ReachPolicy>,
    pub profile: Option<Signed<directory::Profile>>,
    pub custodian_history: Vec<HistoricalCustodian>,
    pub directory: Option<DirectoryBinding>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerReply {
    pub snapshot: Signed<Snapshot>,
    pub payload: SnapshotPayload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeCode {
    FirstContact,
    IdentityStatus,
    NodeKeyChanged,
    NodeKeyRotated,
    NodeCertificateChanged,
    NodeFork,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeSource {
    Card,
    Directory,
    InboundRequest,
    Group,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeContinuity {
    FirstSeen,
    Continuous,
    Rotated,
    Changed,
    Forked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonVerification {
    Unverified,
    AuthenticCard,
    OutOfBand,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notice {
    pub code: NoticeCode,
    pub source: NoticeSource,
    pub source_locator: Option<String>,
    pub recipient_root: String,
    pub peer_root: String,
    pub account_safety_fingerprint: String,
    pub safety_algorithm: u32,
    pub safety_number: [String; 12],
    pub node_id: String,
    pub node_fingerprint: String,
    pub old_node_fingerprint: Option<String>,
    pub first_seen: bool,
    pub node_continuity: NodeContinuity,
    pub person_verification: PersonVerification,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Query {
        query: Box<Query>,
    },
    Submit {
        target_node_id: String,
        submission: Box<Submission>,
    },
    Policy {
        update: Signed<ReachPolicy>,
    },
    Admission {
        update: Signed<Admission>,
        peer_evidence: Option<Box<PeerReply>>,
        notice: Option<Box<Notice>>,
    },
    Start {
        update: Signed<Admission>,
        peer_evidence: Box<PeerReply>,
        notice: Box<Notice>,
        target_node_id: String,
        submission: Box<Submission>,
    },
    Reply {
        update: Signed<Admission>,
        peer_evidence: Box<PeerReply>,
        notice: Box<Notice>,
        target_node_id: String,
        submission: Box<Submission>,
    },
    Strangers {
        after_seq: u64,
        limit: u64,
        ack_seqs: Vec<u64>,
    },
    ReachState {
        known_revision: u64,
        snapshot_id: Option<String>,
        page: u64,
    },
    Cost {
        request: ChallengeRequest,
        target_node_id: String,
    },
    UsernameMutate {
        operation: Box<Signed<directory::NameOperation>>,
        cost: Option<Cost>,
    },
    UsernameStatus {
        account_anchor: String,
        operation_id: String,
        operation_hash: String,
    },
    UsernameResolve {
        name: String,
        nonce: String,
    },
    ProfilePublish {
        operation_id: String,
        expected_epoch: u64,
        update: Signed<directory::Profile>,
    },
    GroupRoster {
        operation_id: String,
        roster: Box<super::GroupRoster>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
    pub session_id: String,
    pub session_generation: u64,
    pub remaining_ms: u64,
    pub operation: Operation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Applied {
    Applied,
    Duplicate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmitOutcome {
    Submitted,
    Spooled,
    Quarantined,
    Duplicate,
    Refused,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationResult {
    Query { reply: Box<PeerReply> },
    Submit { envelope_id: String, outcome: SubmitOutcome, reason: Option<Reason> },
    Policy { revision: u64, outcome: Applied },
    Admission { revision: u64, outcome: Applied },
    GroupRoster { group_epoch: u64, outcome: Applied },
    Start { revision: u64, outcome: Applied, submission: Box<OperationResult> },
    Reply { revision: u64, outcome: Applied, submission: Box<OperationResult> },
    Strangers { entries: Vec<StrangerEntry>, next_seq: u64 },
    ReachState { manifest: Signed<StateManifest>, page: StatePage },
    Challenge { challenge: Signed<Challenge> },
    UsernameMutate { receipt: Signed<directory::IndexReceipt> },
    UsernameStatus { receipt: Signed<directory::IndexReceipt> },
    UsernameResolve { resolve: Signed<directory::IndexResolve> },
    ProfilePublish { epoch: u64, profile_hash: String, outcome: Applied },
    Error { reason: Reason, retry_after_ms: Option<u64>, current_revision: Option<u64> },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub request_id: String,
    pub session_id: String,
    pub session_generation: u64,
    pub result: OperationResult,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrangerEntry {
    pub seq: u64,
    pub peer_node: String,
    pub source_root: String,
    pub received_at: u64,
    pub retain_until: u64,
    pub envelope: crate::Envelope,
    pub reach: DeliveryReach,
    pub conversation_id: String,
    pub placement: Placement,
    pub policy_revision: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    FeatureDisabled,
    UnsupportedAccountMode,
    ForeignInvalidFrame,
    ForeignPayloadTooLarge,
    ForeignEndpointRefused,
    ForeignCapabilityMissing,
    ForeignBootstrapFailed,
    ForeignReadRefused,
    ForeignSnapshotInvalid,
    ForeignSnapshotExpired,
    ForeignNodeKeyChanged,
    ForeignNodeKeyRollback,
    ForeignNodeFork,
    ForeignPolicyDenied,
    ForeignRequestBlocked,
    ForeignSpamLimited,
    ForeignUnavailable,
    ForeignCapacity,
    ForeignRateLimited,
    ForeignStorageUnavailable,
    HomeEvidenceRequired,
    HomeRollback,
    HomeFork,
    InvalidCard,
    CardExpired,
    CardSignatureInvalid,
    NodeFingerprintMismatch,
    AnchorMismatch,
    RootConflict,
    CustodyRefused,
    AdmissionRevisionConflict,
    IdempotencyConflict,
    ContactConfirmationRequired,
    ReachRevisionConflict,
    ReachPolicyRequired,
    ConversationGrantExpired,
    ReachRouteInvalid,
    CostRequired,
    CostInvalid,
    CentrePinRequired,
    CentreKeyChanged,
    UsernameHomeMismatch,
    UsernameSignerRevoked,
    GroupEpochStale,
    ReachCommandExpired,
}

mod validation;

mod query;
pub use query::*;

mod submit;
pub use submit::{SourceSubmitKind, SourceSubmitRequest};
mod submit_response;
pub use submit_response::{
    MAX_SUBMIT_RESPONSE_BYTES, SourceSubmitResponse, SourceSubmitResponseKind,
};

mod forward_result;
pub use forward_result::{ForwardResult, ForwardResultKind, validate_receiving_result};

mod cost;
pub use cost::*;
