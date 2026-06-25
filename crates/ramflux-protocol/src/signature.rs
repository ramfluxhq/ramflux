// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;

use crate::{
    ProtocolError, SignatureAlg, SignedFields, decode_base64url, signed_bytes, signed_value,
};

/// Verifies canonical Ed25519 signature bytes.
///
/// # Errors
/// Returns an error when base64url decoding, key parsing, or signature verification fails.
pub fn verify_canonical_signature(
    canonical: &[u8],
    signature_base64url: &str,
    public_key_base64url: &str,
) -> Result<(), ProtocolError> {
    let signature_bytes = decode_base64url(signature_base64url)
        .map_err(|source| ProtocolError::InvalidBase64Url { field: "signature", source })?;
    let public_key_bytes = decode_base64url(public_key_base64url)
        .map_err(|source| ProtocolError::InvalidBase64Url { field: "public_key", source })?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| ProtocolError::InvalidSignatureLength(bytes.len()))?;
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| ProtocolError::InvalidPublicKeyLength(bytes.len()))?;
    let signature = Signature::from_bytes(&signature_array);
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_err| ProtocolError::SignatureVerificationFailed)?;
    verifying_key
        .verify(canonical, &signature)
        .map_err(|_err| ProtocolError::SignatureVerificationFailed)
}

/// Verifies a protocol object's flattened `SignedFields` over its signed bytes.
///
/// # Errors
/// Returns an error when the object cannot be canonicalized or verification fails.
pub fn verify_signed_fields<T: Serialize>(
    value: &T,
    signed: &SignedFields,
    public_key_base64url: &str,
) -> Result<(), ProtocolError> {
    if signed.signature_alg != SignatureAlg::Ed25519 {
        return Err(ProtocolError::UnsupportedSignatureAlgorithm);
    }
    let canonical = signed_bytes(value)?;
    verify_canonical_signature(&canonical, &signed.signature, public_key_base64url)
}

/// Verifies a signed JSON protocol fixture/object.
///
/// # Errors
/// Returns an error when signature fields are missing, canonicalization fails, or verification fails.
pub fn verify_json_signature(
    value: &Value,
    public_key_base64url: &str,
) -> Result<(), ProtocolError> {
    let Some(signature) = value.get("signature").and_then(Value::as_str) else {
        return Err(ProtocolError::MissingSignatureField("signature"));
    };
    let Some(signature_alg) = value.get("signature_alg").and_then(Value::as_str) else {
        return Err(ProtocolError::MissingSignatureField("signature_alg"));
    };
    if signature_alg != "ed25519" {
        return Err(ProtocolError::UnsupportedSignatureAlgorithm);
    }
    let canonical = crate::canonical_json_bytes(&signed_value(value)?)?;
    verify_canonical_signature(&canonical, signature, public_key_base64url)
}
