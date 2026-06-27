// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{NodeCoreError, RETENTION_STATE_KEY, RETENTION_STATE_TABLE};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const IDENTITY_DELETION_TOMBSTONE_RETENTION_SECONDS: u64 = 24 * 31 * 24 * 60 * 60;
const LEGAL_HOLD_REVIEW_MAX_SECONDS: u64 = 180 * 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecurityIncident {
    pub incident_id: String,
    pub incident_class: String,
    pub source_service_id: String,
    pub subject_hash: String,
    pub severity: IncidentSeverity,
    pub occurred_at: u64,
    pub expires_at: u64,
    pub retention_policy_id: String,
    pub metadata_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RateLimitAbuseMetadata {
    pub bucket_id: String,
    pub source_service_id: String,
    pub abuse_signal: String,
    pub subject_hash: String,
    pub attempt_count: u64,
    pub window_started_at: u64,
    pub window_expires_at: u64,
    pub retention_policy_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetentionMetadataRecord {
    pub record_id: String,
    pub subject_hash: String,
    pub metadata_class: String,
    pub source_service_id: String,
    pub retention_policy_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_after_ack: Option<u64>,
    pub legal_hold: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold_next_review_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold_actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold_created_at: Option<u64>,
    pub metadata_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionIdentityDeleteStatus {
    Deleted,
    DeletePendingVerification,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetentionIdentityLifecycleTombstone {
    pub subject_hash: String,
    pub status: RetentionIdentityDeleteStatus,
    pub identity_lifecycle_tombstone_hash: String,
    pub deletion_proof_hash: Option<String>,
    pub deletion_proof: Option<ramflux_protocol::IdentityDeletionProof>,
    pub created_at: u64,
    pub expires_at: u64,
    pub security_incident_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetentionNodeSigner {
    pub node_id: String,
    pub node_epoch: u64,
    pub signing_key_id: String,
    pub signing_seed: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetentionIdentityDeleteContext {
    pub subject_hash: String,
    pub lifecycle_epoch: u64,
    pub identity_deleted_event_id: String,
    pub identity_lifecycle_tombstone_hash: String,
    pub retention_policy_id: String,
    pub finalized_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestRetentionRecordRequest {
    pub record: RetentionMetadataRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestRetentionGcRequest {
    pub now: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestRetentionIdentityDeleteRequest {
    pub subject_hash: String,
    #[serde(default)]
    pub lifecycle_epoch: u64,
    #[serde(default)]
    pub identity_deleted_event_id: String,
    #[serde(default)]
    pub identity_lifecycle_tombstone_hash: String,
    #[serde(default)]
    pub retention_policy_id: String,
    #[serde(default)]
    pub finalized_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestRetentionGcResponse {
    pub deleted_record_ids: Vec<String>,
    pub retained_legal_hold_ids: Vec<String>,
    pub remaining_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItestRetentionIdentityDeleteResponse {
    pub deleted_record_ids: Vec<String>,
    pub retained_legal_hold_ids: Vec<String>,
    pub remaining_count: usize,
    pub status: RetentionIdentityDeleteStatus,
    pub deletion_scope: Vec<String>,
    pub deletion_proof_hash: Option<String>,
    pub deletion_proof: Option<ramflux_protocol::IdentityDeletionProof>,
    pub security_incident_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetentionGcSweepRequest {
    pub owner_service: String,
    pub sweep_id: String,
    pub now: u64,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetentionGcSweepResponse {
    pub owner_service: String,
    pub sweep_id: String,
    pub accepted: bool,
    pub deleted_count: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetentionState {
    incidents_by_id: BTreeMap<String, SecurityIncident>,
    rate_limit_by_bucket: BTreeMap<String, RateLimitAbuseMetadata>,
    #[serde(default)]
    metadata_by_id: BTreeMap<String, RetentionMetadataRecord>,
    #[serde(default)]
    identity_tombstones_by_subject: BTreeMap<String, RetentionIdentityLifecycleTombstone>,
}

impl RetentionState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn report_incident(&mut self, incident: SecurityIncident) {
        self.incidents_by_id.insert(incident.incident_id.clone(), incident);
    }

    pub fn record_rate_limit_abuse(&mut self, metadata: RateLimitAbuseMetadata) {
        self.rate_limit_by_bucket.insert(metadata.bucket_id.clone(), metadata);
    }

    /// # Errors
    /// Returns an error when the record lacks retention policy, expiry, or legal-hold metadata.
    pub fn record_metadata(
        &mut self,
        record: RetentionMetadataRecord,
    ) -> Result<(), NodeCoreError> {
        validate_retention_record(&record)?;
        self.metadata_by_id.insert(record.record_id.clone(), record);
        Ok(())
    }

    #[must_use]
    pub fn incident(&self, incident_id: &str) -> Option<&SecurityIncident> {
        self.incidents_by_id.get(incident_id)
    }

    #[must_use]
    pub fn rate_limit_metadata(&self, bucket_id: &str) -> Option<&RateLimitAbuseMetadata> {
        self.rate_limit_by_bucket.get(bucket_id)
    }

    #[must_use]
    pub fn incident_count(&self) -> usize {
        self.incidents_by_id.len()
    }

    #[must_use]
    pub fn metadata_record(&self, record_id: &str) -> Option<&RetentionMetadataRecord> {
        self.metadata_by_id.get(record_id)
    }

    #[must_use]
    pub fn metadata_count(&self) -> usize {
        self.metadata_by_id.len()
    }

    pub fn gc_expired(&mut self, now: u64) -> ItestRetentionGcResponse {
        let mut deleted_record_ids = Vec::new();
        let mut retained_legal_hold_ids = Vec::new();
        self.metadata_by_id.retain(|record_id, record| {
            if record.legal_hold {
                if record.expires_at <= now {
                    retained_legal_hold_ids.push(record_id.clone());
                }
                true
            } else if record_effective_expires_at(record) <= now {
                deleted_record_ids.push(record_id.clone());
                false
            } else {
                true
            }
        });
        ItestRetentionGcResponse {
            deleted_record_ids,
            retained_legal_hold_ids,
            remaining_count: self.metadata_by_id.len(),
        }
    }

    pub fn finalize_identity_delete(
        &mut self,
        context: &RetentionIdentityDeleteContext,
        signer: &RetentionNodeSigner,
    ) -> ItestRetentionIdentityDeleteResponse {
        let mut deleted_record_ids = Vec::new();
        let mut retained_legal_hold_ids = Vec::new();
        let mut deleted_rows = Vec::new();
        let mut retained_rows = Vec::new();
        self.metadata_by_id.retain(|record_id, record| {
            if record.subject_hash != context.subject_hash {
                return true;
            }
            if record.legal_hold {
                retained_legal_hold_ids.push(record_id.clone());
                retained_rows.push(record.clone());
                true
            } else {
                deleted_record_ids.push(record_id.clone());
                deleted_rows.push(record.clone());
                false
            }
        });

        match identity_deletion_proof_from_rows(context, signer, &deleted_rows, &retained_rows) {
            Ok((proof, proof_hash, deletion_scope)) => {
                self.identity_tombstones_by_subject.insert(
                    context.subject_hash.clone(),
                    RetentionIdentityLifecycleTombstone {
                        subject_hash: context.subject_hash.clone(),
                        status: RetentionIdentityDeleteStatus::Deleted,
                        identity_lifecycle_tombstone_hash: context
                            .identity_lifecycle_tombstone_hash
                            .clone(),
                        deletion_proof_hash: Some(proof_hash.clone()),
                        deletion_proof: Some(proof.clone()),
                        created_at: context.finalized_at,
                        expires_at: context
                            .finalized_at
                            .saturating_add(IDENTITY_DELETION_TOMBSTONE_RETENTION_SECONDS),
                        security_incident_id: None,
                    },
                );
                ItestRetentionIdentityDeleteResponse {
                    deleted_record_ids,
                    retained_legal_hold_ids,
                    remaining_count: self.metadata_by_id.len(),
                    status: RetentionIdentityDeleteStatus::Deleted,
                    deletion_scope,
                    deletion_proof_hash: Some(proof_hash),
                    deletion_proof: Some(proof),
                    security_incident_id: None,
                }
            }
            Err(error) => {
                let incident_id = format!("retention_delete_proof_failed:{}", context.subject_hash);
                self.report_incident(SecurityIncident {
                    incident_id: incident_id.clone(),
                    incident_class: "identity_deletion_proof_generation_failed".to_owned(),
                    source_service_id: "ramflux-retention".to_owned(),
                    subject_hash: context.subject_hash.clone(),
                    severity: IncidentSeverity::High,
                    occurred_at: context.finalized_at,
                    expires_at: context
                        .finalized_at
                        .saturating_add(IDENTITY_DELETION_TOMBSTONE_RETENTION_SECONDS),
                    retention_policy_id: context.retention_policy_id.clone(),
                    metadata_hash: ramflux_crypto::blake3_256_base64url(
                        ramflux_protocol::domain::IDENTITY_DELETION_PROOF_TOMBSTONE,
                        error.to_string().as_bytes(),
                    ),
                });
                self.identity_tombstones_by_subject.insert(
                    context.subject_hash.clone(),
                    RetentionIdentityLifecycleTombstone {
                        subject_hash: context.subject_hash.clone(),
                        status: RetentionIdentityDeleteStatus::DeletePendingVerification,
                        identity_lifecycle_tombstone_hash: context
                            .identity_lifecycle_tombstone_hash
                            .clone(),
                        deletion_proof_hash: None,
                        deletion_proof: None,
                        created_at: context.finalized_at,
                        expires_at: context
                            .finalized_at
                            .saturating_add(IDENTITY_DELETION_TOMBSTONE_RETENTION_SECONDS),
                        security_incident_id: Some(incident_id.clone()),
                    },
                );
                ItestRetentionIdentityDeleteResponse {
                    deleted_record_ids,
                    retained_legal_hold_ids,
                    remaining_count: self.metadata_by_id.len(),
                    status: RetentionIdentityDeleteStatus::DeletePendingVerification,
                    deletion_scope: Vec::new(),
                    deletion_proof_hash: None,
                    deletion_proof: None,
                    security_incident_id: Some(incident_id),
                }
            }
        }
    }

    #[must_use]
    pub fn identity_tombstone(
        &self,
        subject_hash: &str,
    ) -> Option<&RetentionIdentityLifecycleTombstone> {
        self.identity_tombstones_by_subject.get(subject_hash)
    }
}

fn validate_retention_record(record: &RetentionMetadataRecord) -> Result<(), NodeCoreError> {
    if record.retention_policy_id.trim().is_empty() {
        return Err(NodeCoreError::ItestHttp(
            "retention metadata missing retention_policy_id".to_owned(),
        ));
    }
    if record.expires_at == 0 {
        return Err(NodeCoreError::ItestHttp("retention metadata missing expires_at".to_owned()));
    }
    if record.legal_hold {
        let next_review = record.legal_hold_next_review_at.ok_or_else(|| {
            NodeCoreError::ItestHttp("legal hold missing legal_hold_next_review_at".to_owned())
        })?;
        if next_review > record.created_at.saturating_add(LEGAL_HOLD_REVIEW_MAX_SECONDS) {
            return Err(NodeCoreError::ItestHttp("legal hold next review exceeds 180d".to_owned()));
        }
        if record.legal_basis.as_deref().unwrap_or_default().trim().is_empty()
            || record.legal_hold_actor.as_deref().unwrap_or_default().trim().is_empty()
            || record.legal_hold_created_at.is_none()
        {
            return Err(NodeCoreError::ItestHttp(
                "legal hold missing legal_basis, actor, or created_at".to_owned(),
            ));
        }
    }
    Ok(())
}

fn record_effective_expires_at(record: &RetentionMetadataRecord) -> u64 {
    record
        .delete_after_ack
        .map_or(record.expires_at, |delete_after_ack| delete_after_ack.min(record.expires_at))
}

#[derive(Serialize)]
struct DeletedMetadataLeaf<'a> {
    domain: &'static str,
    metadata_class: &'a str,
    primary_id: &'a str,
    retention_policy_id: &'a str,
    expires_at: u64,
    deleted_at: u64,
    deletion_reason: &'static str,
    row_payload_hash_before_delete: &'a str,
}

#[derive(Serialize)]
struct DeletedMetadataParent<'a> {
    domain: &'static str,
    left: &'a str,
    right: &'a str,
}

#[derive(Serialize)]
struct RetainedSummaryRow<'a> {
    metadata_class: &'a str,
    primary_id: &'a str,
    retention_policy_id: &'a str,
    expires_at: u64,
    legal_hold_id: &'a str,
    legal_basis: &'a str,
    legal_hold_actor: &'a str,
    legal_hold_created_at: u64,
    legal_hold_next_review_at: u64,
    row_payload_hash_before_delete: &'a str,
}

#[derive(Serialize)]
struct RetainedSummary<'a> {
    domain: &'static str,
    rows: Vec<RetainedSummaryRow<'a>>,
}

fn identity_deletion_proof_from_rows(
    context: &RetentionIdentityDeleteContext,
    signer: &RetentionNodeSigner,
    deleted_rows: &[RetentionMetadataRecord],
    retained_rows: &[RetentionMetadataRecord],
) -> Result<(ramflux_protocol::IdentityDeletionProof, String, Vec<String>), NodeCoreError> {
    let mut deleted_rows = deleted_rows.iter().collect::<Vec<_>>();
    deleted_rows.sort_by(|left, right| {
        (left.metadata_class.as_str(), left.record_id.as_str())
            .cmp(&(right.metadata_class.as_str(), right.record_id.as_str()))
    });
    let mut scope = deleted_rows
        .iter()
        .map(|record| record.metadata_class.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let deleted_metadata_hash = deleted_metadata_merkle_root(&deleted_rows, context.finalized_at)?;
    let retained_summary_hash = retained_summary_hash(retained_rows)?;
    let mut proof = ramflux_protocol::IdentityDeletionProof {
        schema: ramflux_protocol::domain::IDENTITY_DELETION_PROOF.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::IDENTITY_DELETION_PROOF.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: signer.signing_key_id.clone(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        proof_id: format!("identity_deletion:{}:{}", context.subject_hash, context.finalized_at),
        identity_commitment: context.subject_hash.clone(),
        lifecycle_epoch: context.lifecycle_epoch,
        identity_deleted_event_id: context.identity_deleted_event_id.clone(),
        identity_lifecycle_tombstone_hash: context.identity_lifecycle_tombstone_hash.clone(),
        deletion_scope: scope.clone(),
        deleted_metadata_hash,
        retained_summary_hash,
        retention_policy_id: context.retention_policy_id.clone(),
        legal_hold_ids: retained_rows.iter().map(|record| record.record_id.clone()).collect(),
        node_id: signer.node_id.clone(),
        node_epoch: signer.node_epoch,
        finalized_at: i64::try_from(context.finalized_at).unwrap_or(i64::MAX),
        completed_at: i64::try_from(context.finalized_at).unwrap_or(i64::MAX),
        nonce: ramflux_protocol::encode_base64url(
            ramflux_crypto::blake3_256(
                ramflux_protocol::domain::IDENTITY_DELETION_PROOF,
                format!("{}:{}", context.subject_hash, context.finalized_at).as_bytes(),
            )
            .as_slice(),
        ),
    };
    proof.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&proof, signer.signing_seed)
            .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    let signed_bytes = ramflux_protocol::signed_bytes(&proof)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    let proof_hash = ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::IDENTITY_DELETION_PROOF,
        &signed_bytes,
    );
    scope.sort();
    Ok((proof, proof_hash, scope))
}

fn deleted_metadata_merkle_root(
    rows: &[&RetentionMetadataRecord],
    deleted_at: u64,
) -> Result<String, NodeCoreError> {
    if rows.is_empty() {
        return Ok(ramflux_protocol::hash_base64url(
            ramflux_protocol::domain::IDENTITY_DELETION_PROOF_DELETED_METADATA_EMPTY,
            &[],
        ));
    }
    let mut level = rows
        .iter()
        .map(|record| {
            let leaf = DeletedMetadataLeaf {
                domain: ramflux_protocol::domain::IDENTITY_DELETION_PROOF_DELETED_METADATA_LEAF,
                metadata_class: &record.metadata_class,
                primary_id: &record.record_id,
                retention_policy_id: &record.retention_policy_id,
                expires_at: record.expires_at,
                deleted_at,
                deletion_reason: "identity_delete_finalized",
                row_payload_hash_before_delete: &record.metadata_hash,
            };
            canonical_hash_base64url(
                ramflux_protocol::domain::IDENTITY_DELETION_PROOF_DELETED_METADATA_LEAF,
                &leaf,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0].clone());
            } else {
                let parent = DeletedMetadataParent {
                    domain:
                        ramflux_protocol::domain::IDENTITY_DELETION_PROOF_DELETED_METADATA_PARENT,
                    left: &pair[0],
                    right: &pair[1],
                };
                next.push(canonical_hash_base64url(
                    ramflux_protocol::domain::IDENTITY_DELETION_PROOF_DELETED_METADATA_PARENT,
                    &parent,
                )?);
            }
        }
        level = next;
    }
    Ok(level.remove(0))
}

fn retained_summary_hash(rows: &[RetentionMetadataRecord]) -> Result<String, NodeCoreError> {
    let mut rows = rows.iter().collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        (left.metadata_class.as_str(), left.record_id.as_str())
            .cmp(&(right.metadata_class.as_str(), right.record_id.as_str()))
    });
    let summary = RetainedSummary {
        domain: ramflux_protocol::domain::IDENTITY_DELETION_PROOF_RETAINED_SUMMARY,
        rows: rows
            .into_iter()
            .map(|record| RetainedSummaryRow {
                metadata_class: &record.metadata_class,
                primary_id: &record.record_id,
                retention_policy_id: &record.retention_policy_id,
                expires_at: record.expires_at,
                legal_hold_id: &record.record_id,
                legal_basis: record.legal_basis.as_deref().unwrap_or(""),
                legal_hold_actor: record.legal_hold_actor.as_deref().unwrap_or(""),
                legal_hold_created_at: record.legal_hold_created_at.unwrap_or(0),
                legal_hold_next_review_at: record.legal_hold_next_review_at.unwrap_or(0),
                row_payload_hash_before_delete: &record.metadata_hash,
            })
            .collect(),
    };
    canonical_hash_base64url(
        ramflux_protocol::domain::IDENTITY_DELETION_PROOF_RETAINED_SUMMARY,
        &summary,
    )
}

fn canonical_hash_base64url<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, NodeCoreError> {
    let canonical = ramflux_protocol::canonical_json_bytes(value)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(ramflux_protocol::hash_base64url(domain, &canonical))
}

/// # Errors
/// Returns an error when the proof is not bound to the expected lifecycle tombstone.
pub fn verify_identity_deletion_proof_tombstone(
    proof: &ramflux_protocol::IdentityDeletionProof,
    expected_tombstone_hash: &str,
) -> Result<(), NodeCoreError> {
    if proof.identity_lifecycle_tombstone_hash != expected_tombstone_hash {
        return Err(NodeCoreError::ItestHttp(
            "identity deletion proof tombstone hash mismatch".to_owned(),
        ));
    }
    Ok(())
}

impl From<ItestRetentionIdentityDeleteResponse> for ItestRetentionGcResponse {
    fn from(value: ItestRetentionIdentityDeleteResponse) -> Self {
        Self {
            deleted_record_ids: value.deleted_record_ids,
            retained_legal_hold_ids: value.retained_legal_hold_ids,
            remaining_count: value.remaining_count,
        }
    }
}

impl Default for RetentionNodeSigner {
    fn default() -> Self {
        let signing_seed = ramflux_crypto::blake3_256(
            "ramflux.retention.dev_node_signing_seed.v1",
            b"fallback-dev-seed",
        );
        Self {
            node_id: "localhost".to_owned(),
            node_epoch: 1,
            signing_key_id: "localhost#node".to_owned(),
            signing_seed,
        }
    }
}

impl ItestRetentionIdentityDeleteRequest {
    #[must_use]
    pub fn into_context(self, now: u64) -> RetentionIdentityDeleteContext {
        RetentionIdentityDeleteContext {
            subject_hash: self.subject_hash.clone(),
            lifecycle_epoch: if self.lifecycle_epoch == 0 { 1 } else { self.lifecycle_epoch },
            identity_deleted_event_id: if self.identity_deleted_event_id.is_empty() {
                format!("identity.deleted:{}", self.subject_hash)
            } else {
                self.identity_deleted_event_id
            },
            identity_lifecycle_tombstone_hash: if self.identity_lifecycle_tombstone_hash.is_empty()
            {
                ramflux_crypto::blake3_256_base64url(
                    ramflux_protocol::domain::IDENTITY_DELETION_PROOF_TOMBSTONE,
                    self.subject_hash.as_bytes(),
                )
            } else {
                self.identity_lifecycle_tombstone_hash
            },
            retention_policy_id: if self.retention_policy_id.is_empty() {
                "identity_lifecycle_tombstone.default_24_months".to_owned()
            } else {
                self.retention_policy_id
            },
            finalized_at: if self.finalized_at == 0 { now } else { self.finalized_at },
        }
    }
}

/// # Errors
/// Returns an error when a non-retention peer or non-GC path attempts retention GC sweep.
pub fn authorize_retention_gc_sweep(
    local_service_id: &str,
    allowed_service_ids: &BTreeSet<String>,
    peer_spiffe_uri: Option<&str>,
    path: &str,
) -> Result<crate::MeshPeerIdentity, NodeCoreError> {
    if path != "/internal/retention/gc_sweep" {
        return Err(NodeCoreError::ItestHttp(
            "retention peer is only authorized for gc_sweep".to_owned(),
        ));
    }
    let peer = crate::authorize_mesh_peer(local_service_id, allowed_service_ids, peer_spiffe_uri)?;
    if peer.service_id != "ramflux-retention" {
        return Err(NodeCoreError::MeshPeerUnauthorized {
            local_service_id: local_service_id.to_owned(),
            peer_spiffe_uri: peer.spiffe_uri,
        });
    }
    Ok(peer)
}

impl RetentionGcSweepRequest {
    #[must_use]
    pub fn response(&self, deleted_count: u64) -> RetentionGcSweepResponse {
        RetentionGcSweepResponse {
            owner_service: self.owner_service.clone(),
            sweep_id: self.sweep_id.clone(),
            accepted: true,
            deleted_count,
        }
    }
}

impl RetentionState {
    #[must_use]
    pub fn finalize_identity_delete_legacy(
        &mut self,
        subject_hash: &str,
    ) -> ItestRetentionGcResponse {
        let context = ItestRetentionIdentityDeleteRequest {
            subject_hash: subject_hash.to_owned(),
            lifecycle_epoch: 1,
            identity_deleted_event_id: String::new(),
            identity_lifecycle_tombstone_hash: String::new(),
            retention_policy_id: String::new(),
            finalized_at: 1_760_000_000,
        }
        .into_context(1_760_000_000);
        self.finalize_identity_delete(&context, &RetentionNodeSigner::default()).into()
    }
}

pub struct RetentionRedbStore {
    db: redb::Database,
}

impl RetentionRedbStore {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| NodeCoreError::StoreDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let db = redb::Database::create(path)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let write_txn =
            db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let _table = write_txn
                .open_table(RETENTION_STATE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(Self { db })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn save_state(&self, state: &RetentionState) -> Result<(), NodeCoreError> {
        let snapshot = serde_json::to_vec(state)
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(RETENTION_STATE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            table
                .insert(RETENTION_STATE_KEY, snapshot.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn load_state(&self) -> Result<Option<RetentionState>, NodeCoreError> {
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = read_txn
            .open_table(RETENTION_STATE_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let Some(snapshot) = table
            .get(RETENTION_STATE_KEY)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?
        else {
            return Ok(None);
        };
        let state = serde_json::from_slice(snapshot.value())
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        Ok(Some(state))
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn report_incident(&self, incident: SecurityIncident) -> Result<(), NodeCoreError> {
        let mut state = self.load_state()?.unwrap_or_default();
        state.report_incident(incident);
        self.save_state(&state)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn record_rate_limit_abuse(
        &self,
        metadata: RateLimitAbuseMetadata,
    ) -> Result<(), NodeCoreError> {
        let mut state = self.load_state()?.unwrap_or_default();
        state.record_rate_limit_abuse(metadata);
        self.save_state(&state)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn record_metadata(&self, record: RetentionMetadataRecord) -> Result<(), NodeCoreError> {
        let mut state = self.load_state()?.unwrap_or_default();
        state.record_metadata(record)?;
        self.save_state(&state)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn gc_expired(&self, now: u64) -> Result<ItestRetentionGcResponse, NodeCoreError> {
        let mut state = self.load_state()?.unwrap_or_default();
        let response = state.gc_expired(now);
        self.save_state(&state)?;
        Ok(response)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn finalize_identity_delete(
        &self,
        context: &RetentionIdentityDeleteContext,
        signer: &RetentionNodeSigner,
    ) -> Result<ItestRetentionIdentityDeleteResponse, NodeCoreError> {
        let mut state = self.load_state()?.unwrap_or_default();
        let response = state.finalize_identity_delete(context, signer);
        self.save_state(&state)?;
        Ok(response)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn finalize_identity_delete_legacy(
        &self,
        subject_hash: &str,
    ) -> Result<ItestRetentionGcResponse, NodeCoreError> {
        let mut state = self.load_state()?.unwrap_or_default();
        let response = state.finalize_identity_delete_legacy(subject_hash);
        self.save_state(&state)?;
        Ok(response)
    }
}
