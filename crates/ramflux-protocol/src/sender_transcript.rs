// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One checked v2 sender transcript for live ciphertext and ciphertext-free origin evidence.
use crate::{ProtocolError, canonical_json_bytes, decode_base64url, domain, encode_base64url};
use serde::Serialize;
use serde_json::{Map, Value};

pub const SENDER_TRANSCRIPT_PREFIX: &[u8] = b"ramflux.envelope.sig.v2\0";
/// Only the origin-evidence verifier may use `Evidence`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SenderTranscriptMode {
    WithCiphertext,
    Evidence,
}
/// The flag describes this transcript, not a claim about plaintext or absent ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SenderTranscript {
    pub bytes: Vec<u8>,
    pub ciphertext_bound: bool,
}

fn object<T: Serialize>(envelope: &T) -> Result<Map<String, Value>, ProtocolError> {
    let Value::Object(value) = serde_json::to_value(envelope)? else {
        return Err(ProtocolError::NotObject);
    };
    Ok(value)
}
fn remove_node_fields(value: &mut Map<String, Value>) {
    value.remove("node_report_receipt");
    if let Some(ext) = value.get_mut("ext").and_then(Value::as_object_mut) {
        ext.remove("source_device_authority");
        ext.remove("home_node_migration_forward_count");
        if let Some(franking) = ext.get_mut("franking").and_then(Value::as_object_mut) {
            for key in ["franking_tag", "node_id", "accepted_at"] {
                franking.remove(key);
            }
        }
    }
}
const FIELDS: &[&str] = &[
    "schema",
    "version",
    "domain",
    "signing_key_id",
    "signature_alg",
    "signature",
    "envelope_id",
    "source_principal_id",
    "source_device_id",
    "target_delivery_id",
    "routing_set_id",
    "delivery_class",
    "priority",
    "ttl",
    "created_at",
    "payload_hash",
    "delivery_mode",
    "collapse_tag",
    "report_commitment",
    "encrypted_payload",
    "ext",
    "node_report_receipt",
];
fn check_profile(value: &Map<String, Value>) -> Result<(), ProtocolError> {
    if value.get("schema").and_then(Value::as_str) != Some("ramflux.envelope.v2")
        || value.get("version").and_then(Value::as_u64) != Some(2)
        || value.get("domain").and_then(Value::as_str) != Some("ramflux.envelope.v2")
    {
        return Err(ProtocolError::SenderTranscriptProfile);
    }

    if value.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(ProtocolError::SenderTranscriptProfile);
    }
    for field in FIELDS.iter().filter(|field| {
        !matches!(
            **field,
            "ext" | "routing_set_id" | "node_report_receipt" | "encrypted_payload" | "signature"
        )
    }) {
        if !value.contains_key(*field) {
            return Err(ProtocolError::SenderTranscriptProfile);
        }
    }
    for field in ["payload_hash", "collapse_tag", "report_commitment"] {
        let encoded = value
            .get(field)
            .and_then(Value::as_str)
            .ok_or(ProtocolError::SenderTranscriptProfile)?;
        let bytes =
            decode_base64url(encoded).map_err(|_| ProtocolError::SenderTranscriptProfile)?;
        if bytes.len() != 32 || encode_base64url(bytes) != encoded {
            return Err(ProtocolError::SenderTranscriptProfile);
        }
    }
    if value.get("signature_alg").and_then(Value::as_str) != Some("ed25519") {
        return Err(ProtocolError::UnsupportedSignatureAlgorithm);
    }
    Ok(())
}
fn check_ciphertext(value: &Map<String, Value>) -> Result<(), ProtocolError> {
    let text = value
        .get("encrypted_payload")
        .and_then(Value::as_str)
        .ok_or(ProtocolError::PayloadHashMismatch)?;
    if text.is_empty() || text.len() > crate::message::outer::MAX_CIPHERTEXT_B64_CHARS {
        return Err(ProtocolError::PayloadHashMismatch);
    }
    let decoded = decode_base64url(text).map_err(|_| ProtocolError::PayloadHashMismatch)?;
    if encode_base64url(decoded) != text {
        return Err(ProtocolError::PayloadHashMismatch);
    }
    // Existing payload hash grammar is intentionally unchanged: raw v1 domain + ASCII text.
    let expected = crate::hash_base64url(domain::ENVELOPE, text.as_bytes());
    if value.get("payload_hash").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err(ProtocolError::PayloadHashMismatch);
    }
    Ok(())
}

/// Build the sole v2 sender transcript, validating ciphertext before any bytes are returned.
/// # Errors
/// Refuses wrong profile, malformed ciphertext, hash mismatch or ciphertext present in evidence.
pub fn sender_signed_transcript<T: Serialize>(
    envelope: &T,
    mode: SenderTranscriptMode,
) -> Result<SenderTranscript, ProtocolError> {
    let mut value = object(envelope)?;
    check_profile(&value)?;
    crate::canonical_json::reject_unknown_critical_ext(&value)?;
    match mode {
        SenderTranscriptMode::WithCiphertext => check_ciphertext(&value)?,
        SenderTranscriptMode::Evidence if value.contains_key("encrypted_payload") => {
            return Err(ProtocolError::EvidenceContainsCiphertext);
        }
        SenderTranscriptMode::Evidence => (),
    }
    value.remove("encrypted_payload");
    value.remove("signature");
    remove_node_fields(&mut value);
    let mut bytes = SENDER_TRANSCRIPT_PREFIX.to_vec();
    bytes.extend_from_slice(&canonical_json_bytes(&value)?);
    Ok(SenderTranscript { bytes, ciphertext_bound: mode == SenderTranscriptMode::WithCiphertext })
}

/// Verify the sender signature through the checked transcript; ciphertext hash is checked first.
/// # Errors
/// Refuses profile/encoding/hash/signature mismatch. Evidence success is not ciphertext proof.
pub fn verify_sender_signature<T: Serialize>(
    envelope: &T,
    mode: SenderTranscriptMode,
    public_key: &str,
) -> Result<SenderTranscript, ProtocolError> {
    let transcript = sender_signed_transcript(envelope, mode)?;
    let value = object(envelope)?;
    let signature = value
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(ProtocolError::MissingSignatureField("signature"))?;
    crate::verify_canonical_signature(&transcript.bytes, signature, public_key)?;
    Ok(transcript)
}

/// Export signed outer origin evidence with ciphertext and node additions absent.
/// # Errors
/// Requires a valid v2 live hash binding and returns canonical serialization errors.
pub fn sender_origin_evidence<T: Serialize>(envelope: &T) -> Result<Vec<u8>, ProtocolError> {
    sender_signed_transcript(envelope, SenderTranscriptMode::WithCiphertext)?;
    let mut value = object(envelope)?;
    value.remove("encrypted_payload");
    remove_node_fields(&mut value);
    canonical_json_bytes(&value)
}

#[cfg(test)]
#[path = "sender_transcript_tests.rs"]
mod tests;
