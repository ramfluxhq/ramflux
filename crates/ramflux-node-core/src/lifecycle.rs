// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::NodeCoreError;
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountLifecycleState {
    Active,
    Deactivated,
    DeletePending,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityLifecycleTombstone {
    pub tombstone_id: String,
    pub target_id: String,
    pub target_kind: String,
    pub actor_device_id: String,
    pub actor_public_key: String,
    pub reason: String,
    pub created_at: u64,
    pub causal_event_id: String,
    pub signature: String,
    pub tombstone_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityDeletionProof {
    pub principal_id: String,
    pub tombstone_hash: String,
    pub finalized_at: u64,
    pub deleted_metadata_count: u64,
    pub retained_legal_hold_count: u64,
    pub proof_hash: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountLifecycleRecord {
    pub principal_id: String,
    pub state: AccountLifecycleState,
    pub lifecycle_epoch: u64,
    pub causal_event_id: String,
    pub updated_at: u64,
    pub timelock_until: Option<u64>,
    pub tombstone_hash: Option<String>,
    pub deletion_proof: Option<IdentityDeletionProof>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp7LifecycleRequest {
    pub principal_id: String,
    pub event_id: String,
    pub event_type: String,
    pub actor_device_id: String,
    pub lifecycle_epoch: u64,
    pub now: u64,
    pub reason_code: String,
    #[serde(default)]
    pub timelock_seconds: Option<u64>,
    #[serde(default)]
    pub recovery_quorum: Option<ramflux_protocol::RecoveryQuorumConfigured>,
    #[serde(default)]
    pub recovery_quorum_proof: Option<ramflux_protocol::RecoveryQuorumProof>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp7LifecycleResponse {
    pub record: AccountLifecycleRecord,
    pub metadata_present: bool,
    pub deleted_metadata_count: u64,
    pub tombstone: Option<IdentityLifecycleTombstone>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp7LifecycleFinalizeRequest {
    pub principal_id: String,
    pub now: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp7LifecycleCancelRequest {
    pub principal_id: String,
    pub now: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestMvp7MetadataSummary {
    pub principal_id: String,
    pub metadata_present: bool,
    pub root_key_present: bool,
    pub device_count: usize,
    pub prekey_count: usize,
    pub session_bound: bool,
    pub pending_inbox_count: usize,
    pub tombstone_hash: Option<String>,
    pub deletion_proof_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederatedLifecycleTombstoneRequest {
    pub source_node_id: String,
    pub target_delivery_id: String,
    pub lifecycle_state: AccountLifecycleState,
    pub tombstone: Option<IdentityLifecycleTombstone>,
    pub deletion_proof: Option<IdentityDeletionProof>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederatedLifecycleTombstoneResponse {
    pub accepted: bool,
    pub lifecycle_state: AccountLifecycleState,
    pub target_delivery_id: String,
    pub tombstone_hash: Option<String>,
}

pub const DEFAULT_DELETE_TIMELOCK_SECONDS: u64 = 7 * 24 * 60 * 60;

pub(crate) fn lifecycle_tombstone_hash(
    tombstone: &IdentityLifecycleTombstone,
) -> Result<String, NodeCoreError> {
    let mut canonical = tombstone.clone();
    canonical.signature.clear();
    canonical.tombstone_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url("ramflux.identity_lifecycle_tombstone.v1", &bytes))
}

/// # Errors
/// Returns an error when the tombstone hash or signature is invalid.
pub fn verify_lifecycle_tombstone(
    tombstone: &IdentityLifecycleTombstone,
) -> Result<(), NodeCoreError> {
    let expected_hash = lifecycle_tombstone_hash(tombstone)?;
    if expected_hash != tombstone.tombstone_hash {
        return Err(NodeCoreError::ItestHttp("invalid lifecycle tombstone hash".to_owned()));
    }
    let signed_bytes = ramflux_protocol::signed_bytes(tombstone)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    ramflux_crypto::verify_canonical_signature(
        &signed_bytes,
        &tombstone.signature,
        &tombstone.actor_public_key,
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))
}

/// # Errors
/// Returns an error when a recovery quorum proof does not meet the configured member, signature,
/// threshold, member-kind, or timelock policy.
pub fn verify_recovery_quorum_proof(
    quorum: &ramflux_protocol::RecoveryQuorumConfigured,
    proof: &ramflux_protocol::RecoveryQuorumProof,
    now: u64,
) -> Result<(), NodeCoreError> {
    if quorum.threshold == 0 || quorum.total == 0 || quorum.threshold > quorum.total {
        return Err(NodeCoreError::Unauthorized("invalid recovery quorum threshold".to_owned()));
    }
    if usize::from(quorum.total) != quorum.members.len() {
        return Err(NodeCoreError::Unauthorized("invalid recovery quorum member count".to_owned()));
    }
    if let Some(timelock_until) = proof.context.timelock_until
        && now < timelock_until
    {
        return Err(NodeCoreError::Unauthorized("recovery quorum timelock active".to_owned()));
    }
    let members_by_key = quorum
        .members
        .iter()
        .map(|member| (member.signing_key_id.as_str(), member))
        .collect::<BTreeMap<_, _>>();
    if members_by_key.len() != quorum.members.len() {
        return Err(NodeCoreError::Unauthorized("duplicate recovery quorum member".to_owned()));
    }
    let signed_bytes = ramflux_protocol::signed_bytes(&proof.context)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    let mut approved_member_ids = BTreeSet::new();
    let mut has_non_guardian = false;
    for approval in &proof.approvals {
        if approval.signature_alg != ramflux_protocol::SignatureAlg::Ed25519 {
            return Err(NodeCoreError::Unauthorized(
                "recovery approval signature algorithm rejected".to_owned(),
            ));
        }
        let member = members_by_key.get(approval.signing_key_id.as_str()).ok_or_else(|| {
            NodeCoreError::Unauthorized("recovery approval member is not configured".to_owned())
        })?;
        if member.member_kind != approval.member_kind {
            return Err(NodeCoreError::Unauthorized(
                "recovery approval member kind mismatch".to_owned(),
            ));
        }
        if !approved_member_ids.insert(approval.signing_key_id.as_str()) {
            continue;
        }
        ramflux_crypto::verify_canonical_signature(
            &signed_bytes,
            &approval.signature,
            &member.public_key_base64url,
        )
        .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))?;
        has_non_guardian |=
            member.member_kind != ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare;
    }
    if approved_member_ids.len() < usize::from(quorum.threshold) {
        return Err(NodeCoreError::Unauthorized("recovery quorum threshold not met".to_owned()));
    }
    if !has_non_guardian {
        return Err(NodeCoreError::Unauthorized(
            "guardian-only recovery quorum rejected".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn identity_deletion_proof(
    principal_id: &str,
    tombstone_hash: &str,
    finalized_at: u64,
    deleted_metadata_count: u64,
    retained_legal_hold_count: u64,
) -> Result<IdentityDeletionProof, NodeCoreError> {
    let proof_material = serde_json::json!({
        "principal_id": principal_id,
        "tombstone_hash": tombstone_hash,
        "finalized_at": finalized_at,
        "deleted_metadata_count": deleted_metadata_count,
        "retained_legal_hold_count": retained_legal_hold_count,
    });
    let proof_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.identity_deletion_proof.v1",
        serde_json::to_vec(&proof_material)
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?
            .as_slice(),
    );
    let mut proof = IdentityDeletionProof {
        principal_id: principal_id.to_owned(),
        tombstone_hash: tombstone_hash.to_owned(),
        finalized_at,
        deleted_metadata_count,
        retained_legal_hold_count,
        proof_hash,
        signature: String::new(),
    };
    proof.signature = ramflux_crypto::sign_protocol_object(&proof)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(proof)
}
