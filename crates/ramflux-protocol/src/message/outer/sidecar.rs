// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Strict candidate sidecar: typed nested objects and per-field design caps.

use super::{
    MAX_CIPHERTEXT_BYTES, MAX_ENCRYPTED_HEADER_BYTES, MAX_IDENTIFIER_BYTES, OuterProfileError,
};
use serde::Deserialize;
use serde_json::Value;

/// Nested SDK envelope carried as the compact `CryptoBox` sidecar.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code, reason = "typed schema: unknown fields and caps, not field use")]
struct CandidateSidecar {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    version: u32,
    #[serde(default)]
    source_principal_commitment: Option<String>,
    #[serde(default)]
    x3dh: Option<CandidateX3dh>,
    #[serde(default)]
    ciphertext: Option<CandidateCiphertext>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code, reason = "typed schema: unknown fields and caps, not field use")]
struct CandidateCiphertext {
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    counter: u64,
    #[serde(default)]
    nonce: Option<[u8; 12]>,
    #[serde(default)]
    ciphertext: Vec<u8>,
    #[serde(default)]
    ratchet_public_key: Option<[u8; 32]>,
    #[serde(default)]
    previous_chain_length: u64,
    #[serde(default)]
    sender_device_id_hash: Option<[u8; 32]>,
    #[serde(default)]
    recipient_device_id_hash: Option<[u8; 32]>,
    #[serde(default)]
    device_epoch: u64,
    #[serde(default)]
    message_event_id: String,
    #[serde(default)]
    canonical_header_bytes: Vec<u8>,
    #[serde(default)]
    header_hash: String,
    #[serde(default)]
    key_commitment: String,
    #[serde(default)]
    franking_commitment: String,
    #[serde(default)]
    commitment: String,
    #[serde(default)]
    ciphertext_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code, reason = "typed schema: unknown fields and caps, not field use")]
struct CandidateX3dh {
    #[serde(default)]
    bootstrap_ordering_version: Option<u32>,
    #[serde(default)]
    bootstrap_sequence: Option<u64>,
    #[serde(default)]
    bootstrap_envelope_id: Option<String>,
    #[serde(default)]
    initiator_identity_public: Option<[u8; 32]>,
    #[serde(default)]
    initiator_ephemeral_public: Option<[u8; 32]>,
    #[serde(default)]
    initiator_device_id_hash: Option<[u8; 32]>,
    #[serde(default)]
    recipient_device_id_hash: Option<[u8; 32]>,
    #[serde(default)]
    recipient_device_id: String,
    #[serde(default)]
    recipient_signed_prekey_id: String,
    #[serde(default)]
    recipient_one_time_prekey_id: Option<String>,
    #[serde(default)]
    prekey_bundle_hash: Option<[u8; 32]>,
    #[serde(default)]
    bootstrap_transcript_hash: Option<[u8; 32]>,
    #[serde(default)]
    session_id: String,
}

/// Decode candidate sidecar JSON through I-JSON, then typed nested objects.
///
/// # Errors
/// Unknown nested fields, identifier overflow, or malformed JSON.
pub fn decode_candidate_sidecar(bytes: &[u8]) -> Result<(), OuterProfileError> {
    decode_candidate_sidecar_in(bytes, false)
}

fn decode_candidate_sidecar_in(bytes: &[u8], compact: bool) -> Result<(), OuterProfileError> {
    let value: Value = crate::parse_i_json(bytes).map_err(|_| OuterProfileError::Malformed)?;
    decode_sidecar_value(&value, compact)
}

/// Decode a compact-form sidecar: strict like [`decode_candidate_sidecar`], and the
/// legacy `ciphertext.ciphertext` field must be empty (the raw AEAD bytes ride outside).
///
/// # Errors
/// Everything [`decode_candidate_sidecar`] refuses, plus
/// [`OuterProfileError::CompactCiphertextField`] for a non-empty field.
pub fn decode_compact_candidate_sidecar(bytes: &[u8]) -> Result<(), OuterProfileError> {
    decode_candidate_sidecar_in(bytes, true)
}

pub(super) fn decode_sidecar_value(value: &Value, compact: bool) -> Result<(), OuterProfileError> {
    let sidecar: CandidateSidecar =
        serde_json::from_value(value.clone()).map_err(|error| map_strict_decode(&error))?;
    sidecar.check_caps()?;
    if compact
        && sidecar.ciphertext.as_ref().is_some_and(|ciphertext| !ciphertext.ciphertext.is_empty())
    {
        return Err(OuterProfileError::CompactCiphertextField);
    }
    Ok(())
}

fn map_strict_decode(error: &serde_json::Error) -> OuterProfileError {
    if error.to_string().starts_with("unknown field") {
        OuterProfileError::UnknownField
    } else {
        OuterProfileError::Malformed
    }
}

fn cap_id(value: &str) -> Result<(), OuterProfileError> {
    if value.len() > MAX_IDENTIFIER_BYTES { Err(OuterProfileError::Identifier) } else { Ok(()) }
}

impl CandidateSidecar {
    fn check_caps(&self) -> Result<(), OuterProfileError> {
        cap_id(&self.schema)?;
        if let Some(commitment) = &self.source_principal_commitment {
            cap_id(commitment)?;
        }
        if let Some(ciphertext) = &self.ciphertext {
            ciphertext.check_caps()?;
        }
        if let Some(x3dh) = &self.x3dh {
            x3dh.check_caps()?;
        }
        Ok(())
    }
}

impl CandidateCiphertext {
    fn check_caps(&self) -> Result<(), OuterProfileError> {
        cap_id(&self.session_id)?;
        cap_id(&self.message_event_id)?;
        cap_id(&self.header_hash)?;
        cap_id(&self.key_commitment)?;
        cap_id(&self.franking_commitment)?;
        cap_id(&self.commitment)?;
        cap_id(&self.ciphertext_hash)?;
        if self.ciphertext.len() > MAX_CIPHERTEXT_BYTES
            || self.canonical_header_bytes.len() > MAX_ENCRYPTED_HEADER_BYTES
        {
            return Err(OuterProfileError::PayloadTooLarge);
        }
        Ok(())
    }
}

impl CandidateX3dh {
    fn check_caps(&self) -> Result<(), OuterProfileError> {
        cap_id(&self.session_id)?;
        cap_id(&self.recipient_device_id)?;
        cap_id(&self.recipient_signed_prekey_id)?;
        if let Some(envelope_id) = &self.bootstrap_envelope_id {
            cap_id(envelope_id)?;
        }
        if let Some(prekey_id) = &self.recipient_one_time_prekey_id {
            cap_id(prekey_id)?;
        }
        Ok(())
    }
}
