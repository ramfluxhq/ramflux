// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed, role-bound migration messages; nullable wire fields remain explicit.
use crate::{custody::DeviceRef, domain};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Management,
    Actor,
    Node,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignerKey {
    MasterCertifiedCustody {
        account_anchor: String,
        master_certificate_hash: String,
        authority_record_hash: String,
        public_key: String,
    },
    BranchV3 {
        device_ref: DeviceRef,
        branch_certificate_hash: String,
        public_key: String,
    },
    Node {
        node_id: String,
        public_key: String,
    },
}
impl SignerKey {
    #[must_use]
    pub fn public_key(&self) -> &str {
        match self {
            Self::MasterCertifiedCustody { public_key, .. }
            | Self::BranchV3 { public_key, .. }
            | Self::Node { public_key, .. } => public_key,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    pub role: Role,
    pub key: SignerKey,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub schema: String,
    pub domain: String,
    pub body: T,
    pub signers: Vec<Signer>,
    pub signatures: Vec<String>,
}

mod sealed {
    pub trait Sealed {}
}
/// Only the closed migration message family may select a signing domain/role order.
pub trait Message: sealed::Sealed + Serialize {
    const DOMAIN: &'static str;
    const ROLES: &'static [Role];
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Attest,
    Prepare,
    Seal,
    Commit,
    Activate,
    Status,
    Abort,
    Resolve,
    Fence,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Sealed,
    CommitPending,
    CommitOutcomeUnknown,
    Committed,
    Active,
    Aborted,
    Expired,
    Forwarding,
    Complete,
    NeedsAttention,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    V3Required,
    CustodyApprovalRequired,
    AuthorityUpdateRequired,
    ActorRevoked,
    MigrationInProgress,
    CustodyUserPresenceUnavailable,
    PinMismatch,
    ChannelBindingRequired,
    BaseMismatch,
    HomeFork,
    IdempotencyConflict,
    AdmissionExpired,
    CommitExpired,
    CommitOutcomeUnknown,
    PreviousWindowActive,
    HomeGenesisRequired,
    HomeCheckpointRequired,
    BacklogIncomplete,
    BacklogEvidenceRequired,
    CapacityRefused,
    PeeringUnavailable,
    EvidenceRequired,
    RateLimited,
    StorageUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub version: u32,
    pub migration_id: String,
    pub account_anchor: String,
    pub actor: DeviceRef,
    pub authority_record_hash: String,
    pub branch_certificate_hash: String,
    pub previous_home_hash: String,
    pub previous_home_epoch: u64,
    pub old_node: String,
    pub destination_node: String,
    pub destination_key: String,
    pub discovery_hash: String,
    pub delivery_map_hash: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl sealed::Sealed for Prepare {}
impl Message for Prepare {
    const DOMAIN: &'static str = domain::HOME_PREPARE;
    const ROLES: &'static [Role] = &[Role::Actor];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub version: u32,
    pub migration_id: String,
    pub account_anchor: String,
    pub prepare_hash: String,
    pub authority_record_hash: String,
    pub previous_home_hash: String,
    pub next_home_epoch: u64,
    pub old_node: String,
    pub destination_node: String,
    pub destination_key: String,
    pub discovery_hash: String,
    pub server_record_hash: String,
    pub gateway_tcp_addr: String,
    pub federation_endpoint: String,
    pub delivery_map_hash: String,
    pub admission_id: String,
    pub nonce: String,
    pub issued_at: u64,
    pub accept_until: u64,
    pub max_commit_delay: u64,
    pub forward_seconds: u64,
}
impl sealed::Sealed for Offer {}
impl Message for Offer {
    const DOMAIN: &'static str = domain::HOME_ROUTE_OFFER;
    const ROLES: &'static [Role] = &[Role::Node];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub version: u32,
    pub migration_id: String,
    pub account_anchor: String,
    pub actor: DeviceRef,
    pub authority_record_hash: String,
    pub management_certificate_hash: String,
    pub previous_home_hash: String,
    pub next_home_epoch: u64,
    pub old_node: String,
    pub destination_node: String,
    pub destination_key: String,
    pub gateway_tcp_addr: String,
    pub offer_hash: String,
    pub delivery_map_hash: String,
    pub nonce: String,
    pub issued_at: u64,
    pub seal_until: u64,
    pub max_commit_delay: u64,
    pub forward_seconds: u64,
}
impl sealed::Sealed for Authorization {}
impl Message for Authorization {
    const DOMAIN: &'static str = domain::HOME_AUTHORIZATION;
    const ROLES: &'static [Role] = &[Role::Management, Role::Actor];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub version: u32,
    pub account_anchor: String,
    pub home_epoch: u64,
    pub home_node: String,
    pub home_node_key: String,
    pub custody_record_hash: String,
    pub registered_at: u64,
}
impl sealed::Sealed for Genesis {}
impl Message for Genesis {
    const DOMAIN: &'static str = domain::HOME_GENESIS;
    const ROLES: &'static [Role] = &[Role::Node];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub version: u32,
    pub action: Action,
    pub audience_node: String,
    pub migration_id: String,
    pub requester: DeviceRef,
    pub authority_record_hash: String,
    pub payload_hash: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl sealed::Sealed for Control {}
impl Message for Control {
    const DOMAIN: &'static str = domain::HOME_CONTROL;
    const ROLES: &'static [Role] = &[Role::Actor];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: u32,
    pub action: Action,
    pub migration_id: String,
    pub account_anchor: String,
    pub node_id: String,
    pub request_hash: String,
    pub request_nonce: String,
    pub authorization_hash: Option<String>,
    pub seal_hash: Option<String>,
    pub home_record_hash: Option<String>,
    pub phase: Phase,
    pub state_version: u64,
    pub sealed_at: Option<u64>,
    pub commit_deadline: Option<u64>,
    pub commit_proof_hash: Option<String>,
    pub response_payload_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub reason_code: Option<Refusal>,
}
impl sealed::Sealed for Receipt {}
impl Message for Receipt {
    const DOMAIN: &'static str = domain::HOME_RECEIPT;
    const ROLES: &'static [Role] = &[Role::Node];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitProof {
    pub version: u32,
    pub migration_id: String,
    pub account_anchor: String,
    pub old_node: String,
    pub destination_node: String,
    pub destination_key: String,
    pub previous_home_hash: String,
    pub next_home_epoch: u64,
    pub authority_record_hash: String,
    pub authorization_hash: String,
    pub offer_hash: String,
    pub seal_hash: String,
    pub commit_deadline: u64,
    pub committed_at: u64,
    pub forward_until: u64,
    pub backlog_manifest_hash: String,
}
impl sealed::Sealed for CommitProof {}
impl Message for CommitProof {
    const DOMAIN: &'static str = domain::HOME_COMMIT;
    const ROLES: &'static [Role] = &[Role::Node];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCommitDelivery {
    pub version: u32,
    pub migration_id: String,
    pub account_anchor: String,
    pub source_node: String,
    pub audience_node: String,
    pub authorization_hash: String,
    pub offer_hash: String,
    pub seal_hash: String,
    pub admission_evidence_hash: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl sealed::Sealed for NodeCommitDelivery {}
impl Message for NodeCommitDelivery {
    const DOMAIN: &'static str = domain::HOME_COMMIT_DELIVERY;
    const ROLES: &'static [Role] = &[Role::Node];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeAttestation {
    pub version: u32,
    pub account_anchor: String,
    pub audience_node: String,
    pub previous_home_hash: String,
    pub authority_record_hash: String,
    pub device_set_epoch: u64,
    pub delivery_map_hash: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl sealed::Sealed for HomeAttestation {}
impl Message for HomeAttestation {
    const DOMAIN: &'static str = domain::HOME_ADMISSION_ATTESTATION;
    const ROLES: &'static [Role] = &[Role::Node];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoncommitFence {
    pub version: u32,
    pub migration_id: String,
    pub authorization_hash: String,
    pub seal_hash: Option<String>,
    pub fenced_at: u64,
}
impl sealed::Sealed for NoncommitFence {}
impl Message for NoncommitFence {
    const DOMAIN: &'static str = domain::HOME_NONCOMMIT_FENCE;
    const ROLES: &'static [Role] = &[Role::Node];
}

/// Destination's authenticated terminal query; neither expiry nor abort grants routing authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerStatus {
    pub version: u32,
    pub account_anchor: String,
    pub migration_id: String,
    pub authorization_hash: String,
    pub audience_node: String,
    pub destination_node: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl sealed::Sealed for PeerStatus {}
impl Message for PeerStatus {
    const DOMAIN: &'static str = domain::HOME_PEER_STATUS;
    const ROLES: &'static [Role] = &[Role::Node];
}
