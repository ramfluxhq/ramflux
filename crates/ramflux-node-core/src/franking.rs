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
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub envelope_id: String,
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
    let _verified = verify_selected_franking_commitment(evidence)?;
    Err("node franking public key unavailable".to_owned())
}

/// # Errors
/// Returns an error when the evidence commitment does not match, the node id or envelope id is
/// missing, the node public key cannot be parsed, or the Ed25519 franking tag fails verification.
pub fn verify_selected_franking_evidence_with_node_public_key(
    evidence: &SelectedFrankingEvidence,
    node_public_key_base64url: &str,
) -> Result<String, String> {
    if evidence.node_id.is_empty() {
        return Err("missing node id for franking tag verification".to_owned());
    }
    if evidence.envelope_id.is_empty() {
        return Err("missing envelope id for franking tag verification".to_owned());
    }
    let verified = verify_selected_franking_commitment(evidence)?;
    let verifying_key = ramflux_crypto::verifying_key_from_base64url(node_public_key_base64url)
        .map_err(|source| format!("node franking public key rejected: {source}"))?;
    let preimage = ramflux_crypto::franking_node_tag_preimage(
        &evidence.node_id,
        &evidence.envelope_id,
        &evidence.msg_event_id,
        &verified.sender_device_id_hash,
        &verified.commitment.commitment,
        &verified.commitment.ciphertext_hash,
        evidence.franking_timestamp,
    );
    ramflux_crypto::verify_franking_node_tag(&preimage, &evidence.franking_tag, &verifying_key)
        .map_err(|source| format!("node franking tag mismatch: {source}"))?;
    Ok(verified.commitment.commitment)
}

struct VerifiedSelectedFrankingCommitment {
    commitment: ramflux_crypto::FrankingCommitment,
    sender_device_id_hash: Vec<u8>,
}

fn verify_selected_franking_commitment(
    evidence: &SelectedFrankingEvidence,
) -> Result<VerifiedSelectedFrankingCommitment, String> {
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
    if evidence.evidence_kind == FrankingEvidenceKind::SenderBoundGroup
        && evidence.group_header_signature.as_deref().unwrap_or_default().is_empty()
    {
        return Err("missing sender-bound group header signature".to_owned());
    }
    Ok(VerifiedSelectedFrankingCommitment { commitment, sender_device_id_hash })
}

fn decode_key32(value: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = decode_evidence_bytes(value, field)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| format!("{field} must be 32 bytes"))
}

fn decode_evidence_bytes(value: &str, field: &str) -> Result<Vec<u8>, String> {
    ramflux_protocol::decode_base64url(value)
        .map_err(|source| format!("{field} base64url decode failed: {source}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeFrankingTagInput, NodeServiceSigningKey};

    #[test]
    fn selected_franking_evidence_verifies_real_node_tag_and_rejects_wrong_key() {
        let node_key = NodeServiceSigningKey::from_seed([0x61; 32]);
        let wrong_key = NodeServiceSigningKey::from_seed([0x62; 32]);
        let evidence = signed_evidence(&node_key);

        assert_eq!(
            verify_selected_franking_evidence_with_node_public_key(
                &evidence,
                node_key.public_key_base64url(),
            ),
            Ok(evidence.commitment.clone())
        );
        assert!(matches!(
            verify_selected_franking_evidence_with_node_public_key(
                &evidence,
                wrong_key.public_key_base64url(),
            ),
            Err(message) if message.contains("node franking tag mismatch")
        ));
        assert_eq!(
            verify_selected_franking_evidence(&evidence),
            Err("node franking public key unavailable".to_owned())
        );
    }

    #[test]
    fn selected_franking_evidence_rejects_tampered_signed_fields() {
        let node_key = NodeServiceSigningKey::from_seed([0x63; 32]);
        let mut evidence = signed_evidence(&node_key);
        evidence.envelope_id = "env-tampered".to_owned();

        assert!(matches!(
            verify_selected_franking_evidence_with_node_public_key(
                &evidence,
                node_key.public_key_base64url(),
            ),
            Err(message) if message.contains("node franking tag mismatch")
        ));
    }

    fn signed_evidence(node_key: &NodeServiceSigningKey) -> SelectedFrankingEvidence {
        let opening_key = [0x11; 32];
        let commitment_key = [0x22; 32];
        let sender_device_id_hash = [0x33; 32];
        let plaintext = b"selected excerpt";
        let canonical_header_bytes = b"canonical-header";
        let associated_data = b"associated-data";
        let ciphertext = b"ciphertext";
        let message_event_id = "msg-franking-real";
        let commitment =
            ramflux_crypto::franking_commitment(&ramflux_crypto::FrankingCommitmentInput {
                plaintext,
                sender_device_id_hash: &sender_device_id_hash,
                message_event_id,
                canonical_header_bytes,
                associated_data,
                ciphertext,
                opening_key: &opening_key,
                commitment_key: &commitment_key,
            });
        let franking_timestamp = 1_760_000_000_456;
        let franking_tag = node_key.sign_franking_node_tag(NodeFrankingTagInput {
            node_id: "node-franking-real",
            envelope_id: "env-franking-real",
            message_event_id,
            sender_device_id_hash: &sender_device_id_hash,
            commitment: &commitment.commitment,
            ciphertext_hash: &commitment.ciphertext_hash,
            accepted_at_unix_ms: franking_timestamp,
        });
        SelectedFrankingEvidence {
            evidence_kind: FrankingEvidenceKind::ReceiverAttestedDm,
            node_id: "node-franking-real".to_owned(),
            envelope_id: "env-franking-real".to_owned(),
            plaintext_excerpt: "selected excerpt".to_owned(),
            opening_key: ramflux_protocol::encode_base64url(opening_key),
            commitment_key: ramflux_protocol::encode_base64url(commitment_key),
            sender_device_id_hash: ramflux_protocol::encode_base64url(sender_device_id_hash),
            msg_event_id: message_event_id.to_owned(),
            canonical_header_bytes: ramflux_protocol::encode_base64url(canonical_header_bytes),
            associated_data: ramflux_protocol::encode_base64url(associated_data),
            ciphertext: ramflux_protocol::encode_base64url(ciphertext),
            header_hash: commitment.header_hash,
            associated_data_hash: commitment.associated_data_hash,
            ciphertext_hash: commitment.ciphertext_hash,
            franking_commitment: commitment.franking_commitment,
            commitment: commitment.commitment,
            franking_tag,
            franking_timestamp,
            group_header_signature: None,
        }
    }
}
