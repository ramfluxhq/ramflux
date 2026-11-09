// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compact candidate `CryptoBox`: raw AEAD bytes once, then a small JSON sidecar.

use super::OuterProfileError;
use super::sidecar::decode_sidecar_value;
use crate::schema_profile::schema_v1_live;
use serde_json::Value;

/// Magic prefix of a candidate compact `CryptoBox` (`RF1C`).
pub const COMPACT_CRYPTOBOX_MAGIC: [u8; 4] = *b"RF1C";
const COMPACT_VERSION: u8 = 1;

/// Compact on-wire `CryptoBox`: AEAD ciphertext plus the remaining nested JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactCryptobox<'a> {
    pub ciphertext: &'a [u8],
    pub sidecar: &'a [u8],
}

/// Encode raw AEAD bytes and a sidecar (nested JSON with ciphertext emptied).
///
/// # Errors
/// [`OuterProfileError::PayloadTooLarge`] when a section exceeds `u32`.
pub fn encode_compact_cryptobox(
    ciphertext: &[u8],
    sidecar: &[u8],
) -> Result<Vec<u8>, OuterProfileError> {
    let ct_len = u32::try_from(ciphertext.len()).map_err(|_| OuterProfileError::PayloadTooLarge)?;
    let side_len = u32::try_from(sidecar.len()).map_err(|_| OuterProfileError::PayloadTooLarge)?;
    let mut out = Vec::new();
    out.extend_from_slice(&COMPACT_CRYPTOBOX_MAGIC);
    out.push(COMPACT_VERSION);
    out.extend_from_slice(&ct_len.to_be_bytes());
    out.extend_from_slice(ciphertext);
    out.extend_from_slice(&side_len.to_be_bytes());
    out.extend_from_slice(sidecar);
    Ok(out)
}

/// Split a compact `CryptoBox` into AEAD ciphertext and sidecar.
///
/// # Errors
/// [`OuterProfileError::Malformed`] when the prefix, version, or lengths do not fit.
pub fn decode_compact_cryptobox(bytes: &[u8]) -> Result<CompactCryptobox<'_>, OuterProfileError> {
    if bytes.len() < 9 || bytes[..4] != COMPACT_CRYPTOBOX_MAGIC || bytes[4] != COMPACT_VERSION {
        return Err(OuterProfileError::Malformed);
    }
    let ct_len =
        u32::from_be_bytes(bytes[5..9].try_into().map_err(|_| OuterProfileError::Malformed)?)
            as usize;
    let ct_end = 9usize.checked_add(ct_len).ok_or(OuterProfileError::Malformed)?;
    let side_hdr = ct_end.checked_add(4).ok_or(OuterProfileError::Malformed)?;
    if bytes.len() < side_hdr {
        return Err(OuterProfileError::Malformed);
    }
    let side_len = u32::from_be_bytes(
        bytes[ct_end..side_hdr].try_into().map_err(|_| OuterProfileError::Malformed)?,
    ) as usize;
    let side_end = side_hdr.checked_add(side_len).ok_or(OuterProfileError::Malformed)?;
    if side_end != bytes.len() {
        return Err(OuterProfileError::Malformed);
    }
    Ok(CompactCryptobox { ciphertext: &bytes[9..ct_end], sidecar: &bytes[side_hdr..side_end] })
}

/// Candidate wire payload: compact `CryptoBox` base64url, or the legacy body when the gate is off.
///
/// # Errors
/// Profile refusals from compact encoding of a nested SDK envelope.
pub fn wire_encrypted_payload(encrypted_body: &[u8]) -> Result<String, OuterProfileError> {
    if !schema_v1_live() {
        return Ok(crate::encode_base64url(encrypted_body));
    }
    Ok(crate::encode_base64url(&compact_cryptobox_bytes(encrypted_body)?))
}

/// Convert nested SDK JSON (number-array ciphertext) into a compact `CryptoBox`.
/// Already-compact or opaque bodies are returned unchanged.
///
/// # Errors
/// Unknown nested fields, malformed JSON objects, or length overflow.
pub fn compact_cryptobox_bytes(encrypted_body: &[u8]) -> Result<Vec<u8>, OuterProfileError> {
    if decode_compact_cryptobox(encrypted_body).is_ok() {
        return Ok(encrypted_body.to_vec());
    }
    let Ok(value) = crate::parse_i_json::<Value>(encrypted_body) else {
        return Ok(encrypted_body.to_vec());
    };
    if !value.is_object() || value.get("ciphertext").and_then(|c| c.get("ciphertext")).is_none() {
        return Ok(encrypted_body.to_vec());
    }
    decode_sidecar_value(&value)?;
    compact_from_nested_value(&value)
}

pub(super) fn compact_from_nested_value(value: &Value) -> Result<Vec<u8>, OuterProfileError> {
    let ciphertext = nested_byte_field(value, "ciphertext", "ciphertext")?;
    let mut sidecar = value.clone();
    if let Some(object) = sidecar.get_mut("ciphertext").and_then(Value::as_object_mut) {
        object.insert("ciphertext".into(), Value::Array(Vec::new()));
    }
    let sidecar_bytes = serde_json::to_vec(&sidecar).map_err(|_| OuterProfileError::Malformed)?;
    encode_compact_cryptobox(&ciphertext, &sidecar_bytes)
}

pub(super) fn nested_byte_field(
    value: &Value,
    object: &str,
    field: &str,
) -> Result<Vec<u8>, OuterProfileError> {
    byte_value(value.get(object).and_then(|item| item.get(field)))
}

pub(super) fn nested_x3dh_bytes(value: &Value) -> Result<Vec<u8>, OuterProfileError> {
    match value.get("x3dh") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(header) => {
            crate::canonical_json_bytes(header).map_err(|_| OuterProfileError::Malformed)
        }
    }
}

fn byte_value(value: Option<&Value>) -> Result<Vec<u8>, OuterProfileError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                u8::try_from(item.as_u64().ok_or(OuterProfileError::Malformed)?)
                    .map_err(|_| OuterProfileError::Malformed)
            })
            .collect(),
        Some(Value::String(encoded)) => {
            crate::decode_base64url(encoded).map_err(|_| OuterProfileError::Malformed)
        }
        Some(_) => Err(OuterProfileError::Malformed),
    }
}
