// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]

use crate::{NodeCoreError, RetentionMetadataRecord};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FrankingReportStatus {
    Verified,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FrankingEvidenceKind {
    ReceiverAttestedDm,
    SenderBoundGroup,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedFrankingEvidence {
    pub evidence_kind: FrankingEvidenceKind,
    pub plaintext_excerpt: String,
    pub opening_key: String,
    pub commitment_key: String,
    pub sender_device_id_hash: String,
    pub msg_event_id: String,
    pub canonical_header_bytes: String,
    pub associated_data: String,
    pub ciphertext: String,
    pub header_hash: String,
    pub associated_data_hash: String,
    pub ciphertext_hash: String,
    pub franking_commitment: String,
    pub commitment: String,
    pub franking_tag: String,
    pub franking_timestamp: u64,
    #[serde(default)]
    pub group_header_signature: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseReportRequest {
    pub report_id: String,
    pub reporter_identity: String,
    pub reported_identity: String,
    pub reported_node: String,
    pub selected_evidence: SelectedFrankingEvidence,
    pub submitted_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseReportRecord {
    pub report_id: String,
    pub reporter_identity: String,
    pub reported_identity: String,
    pub reported_node: String,
    pub status: FrankingReportStatus,
    pub reason: String,
    pub verified_commitment: Option<String>,
    pub evidence_hash: String,
    pub retention_policy_id: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseReportResponse {
    pub report: AbuseReportRecord,
    pub retention_record: RetentionMetadataRecord,
}

pub(crate) fn selected_evidence_hash(
    evidence: &SelectedFrankingEvidence,
) -> Result<String, NodeCoreError> {
    let bytes = serde_json::to_vec(evidence)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url("ramflux.selected_evidence.v1", &bytes))
}

pub(crate) fn verify_selected_franking_evidence(
    evidence: &SelectedFrankingEvidence,
) -> Result<String, String> {
    let opening_key = decode_key32(&evidence.opening_key, "opening_key")?;
    let commitment_key = decode_key32(&evidence.commitment_key, "commitment_key")?;
    let sender_device_id_hash =
        decode_evidence_bytes(&evidence.sender_device_id_hash, "sender_device_id_hash")?;
    let canonical_header_bytes =
        decode_evidence_bytes(&evidence.canonical_header_bytes, "canonical_header_bytes")?;
    let associated_data = decode_evidence_bytes(&evidence.associated_data, "associated_data")?;
    let ciphertext = decode_evidence_bytes(&evidence.ciphertext, "ciphertext")?;
    let commitment =
        ramflux_crypto::franking_commitment(&ramflux_crypto::FrankingCommitmentInput {
            plaintext: evidence.plaintext_excerpt.as_bytes(),
            sender_device_id_hash: &sender_device_id_hash,
            message_event_id: &evidence.msg_event_id,
            canonical_header_bytes: &canonical_header_bytes,
            associated_data: &associated_data,
            ciphertext: &ciphertext,
            opening_key: &opening_key,
            commitment_key: &commitment_key,
        });
    if commitment.header_hash != evidence.header_hash {
        return Err("header hash mismatch".to_owned());
    }
    if commitment.associated_data_hash != evidence.associated_data_hash {
        return Err("associated data hash mismatch".to_owned());
    }
    if commitment.ciphertext_hash != evidence.ciphertext_hash {
        return Err("ciphertext hash mismatch".to_owned());
    }
    if commitment.franking_commitment != evidence.franking_commitment
        || commitment.commitment != evidence.commitment
    {
        return Err("franking commitment mismatch".to_owned());
    }
    let expected_tag = ramflux_crypto::franking_node_tag(
        &commitment.commitment,
        &commitment.ciphertext_hash,
        evidence.franking_timestamp,
    );
    if expected_tag != evidence.franking_tag {
        return Err("node franking tag mismatch".to_owned());
    }
    if evidence.evidence_kind == FrankingEvidenceKind::SenderBoundGroup
        && evidence.group_header_signature.as_deref().unwrap_or_default().is_empty()
    {
        return Err("missing sender-bound group header signature".to_owned());
    }
    Ok(commitment.commitment)
}

fn decode_key32(value: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = decode_evidence_bytes(value, field)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| format!("{field} must be 32 bytes"))
}

fn decode_evidence_bytes(value: &str, field: &str) -> Result<Vec<u8>, String> {
    ramflux_protocol::decode_base64url(value)
        .map_err(|source| format!("{field} base64url decode failed: {source}"))
}
