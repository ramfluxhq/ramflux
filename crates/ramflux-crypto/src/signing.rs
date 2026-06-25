use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, verify_batch};
use ramflux_protocol::{decode_base64url, encode_base64url, signed_bytes};
use serde::Serialize;
use std::time::{Duration, Instant};

use crate::{CryptoError, DeviceBranch, FIXTURE_SIGNING_KEY_BYTES};

#[must_use]
pub fn fixture_signing_key() -> SigningKey {
    SigningKey::from_bytes(&FIXTURE_SIGNING_KEY_BYTES)
}

#[must_use]
pub fn fixture_verifying_key() -> VerifyingKey {
    fixture_signing_key().verifying_key()
}

#[must_use]
pub fn fixture_public_key_base64url() -> String {
    encode_base64url(fixture_verifying_key().to_bytes())
}

#[must_use]
pub fn public_key_base64url_from_seed(seed: [u8; 32]) -> String {
    encode_base64url(public_key_bytes_from_seed(seed))
}

#[must_use]
pub fn public_key_bytes_from_seed(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

#[must_use]
pub fn sign_canonical_bytes(bytes: &[u8]) -> String {
    let signature = fixture_signing_key().sign(bytes);
    encode_base64url(signature.to_bytes())
}

#[must_use]
pub fn sign_canonical_bytes_with_seed(bytes: &[u8], seed: [u8; 32]) -> String {
    let signature = SigningKey::from_bytes(&seed).sign(bytes);
    encode_base64url(signature.to_bytes())
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn sign_protocol_object<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    let canonical = signed_bytes(value)?;
    Ok(sign_canonical_bytes(&canonical))
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn sign_protocol_object_with_seed<T: Serialize>(
    value: &T,
    seed: [u8; 32],
) -> Result<String, CryptoError> {
    let canonical = signed_bytes(value)?;
    Ok(sign_canonical_bytes_with_seed(&canonical, seed))
}

/// # Errors
/// Returns an error when the signed fields cannot be canonicalized.
pub fn sign_protocol_object_with_device_branch<T: Serialize>(
    device_branch: &DeviceBranch,
    value: &T,
) -> Result<String, CryptoError> {
    let canonical = signed_bytes(value)?;
    let signature = device_branch.signing_key.sign(&canonical);
    Ok(encode_base64url(signature.to_bytes()))
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn verify_canonical_signature(
    canonical: &[u8],
    signature_base64url: &str,
    public_key_base64url: &str,
) -> Result<(), CryptoError> {
    verify_canonical_signature_with_timings(canonical, signature_base64url, public_key_base64url)
        .map(|_timings| ())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalSignatureVerifyTimings {
    pub signature_parse: Duration,
    pub public_key_parse: Duration,
    pub verify: Duration,
}

/// Verifies canonical Ed25519 signature bytes and returns timing segments.
///
/// # Errors
/// Returns an error when validation, base64 decoding, key parsing, or verification fails.
pub fn verify_canonical_signature_with_timings(
    canonical: &[u8],
    signature_base64url: &str,
    public_key_base64url: &str,
) -> Result<CanonicalSignatureVerifyTimings, CryptoError> {
    let signature_started = Instant::now();
    let signature_bytes = decode_base64url(signature_base64url)?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| CryptoError::InvalidSignatureLength(bytes.len()))?;
    let signature = Signature::from_bytes(&signature_array);
    let signature_parse = signature_started.elapsed();

    let public_key_started = Instant::now();
    let public_key_bytes = decode_base64url(public_key_base64url)?;
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| CryptoError::InvalidPublicKeyLength(bytes.len()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_array).map_err(|_err| CryptoError::VerifyFailed)?;
    let public_key_parse = public_key_started.elapsed();

    let verify_started = Instant::now();
    verifying_key.verify_strict(canonical, &signature).map_err(|_err| CryptoError::VerifyFailed)?;
    Ok(CanonicalSignatureVerifyTimings {
        signature_parse,
        public_key_parse,
        verify: verify_started.elapsed(),
    })
}

pub struct CanonicalSignatureBatchItem<'a> {
    pub public_key_bytes: &'a [u8; 32],
    pub canonical: &'a [u8],
    pub signature_bytes: &'a [u8; 64],
}

pub struct CanonicalSignatureSingleKeyBatchItem<'a> {
    pub canonical: &'a [u8],
    pub signature_bytes: &'a [u8; 64],
}

/// Verifies a batch of canonical Ed25519 signatures.
///
/// # Errors
/// Returns the item indices that failed strict verification. If the optimistic batch check fails,
/// each item is rechecked with `verify_strict` to identify the failing indices.
pub fn verify_canonical_signatures_batch(
    items: &[CanonicalSignatureBatchItem<'_>],
) -> Result<(), Vec<usize>> {
    if items.is_empty() {
        return Ok(());
    }
    let mut failures = Vec::new();
    let mut original_indices = Vec::with_capacity(items.len());
    let mut verifying_keys = Vec::with_capacity(items.len());
    let mut signatures = Vec::with_capacity(items.len());
    let mut messages = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        match VerifyingKey::from_bytes(item.public_key_bytes) {
            Ok(verifying_key) => {
                original_indices.push(index);
                verifying_keys.push(verifying_key);
                signatures.push(Signature::from_bytes(item.signature_bytes));
                messages.push(item.canonical);
            }
            Err(_error) => failures.push(index),
        }
    }
    if messages.is_empty() {
        return Err(failures);
    }
    if verify_batch(&messages, &signatures, &verifying_keys).is_ok() {
        return if failures.is_empty() { Ok(()) } else { Err(failures) };
    }
    for ((local_index, message), (signature, verifying_key)) in
        messages.iter().enumerate().zip(signatures.iter().zip(verifying_keys.iter()))
    {
        if verifying_key.verify_strict(message, signature).is_err() {
            failures.push(original_indices[local_index]);
        }
    }
    failures.sort_unstable();
    failures.dedup();
    if failures.is_empty() { Ok(()) } else { Err(failures) }
}

/// Verifies a batch of canonical Ed25519 signatures signed by one public key.
///
/// # Errors
/// Returns the item indices that failed strict verification. An invalid public key marks every
/// item as failed. If the optimistic batch check fails, each item is rechecked with
/// `verify_strict` to identify the failing indices.
pub fn verify_canonical_signatures_batch_single_key(
    public_key_bytes: &[u8; 32],
    items: &[CanonicalSignatureSingleKeyBatchItem<'_>],
) -> Result<(), Vec<usize>> {
    if items.is_empty() {
        return Ok(());
    }
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key_bytes) else {
        return Err((0..items.len()).collect());
    };
    let mut verifying_keys = Vec::with_capacity(items.len());
    let mut signatures = Vec::with_capacity(items.len());
    let mut messages = Vec::with_capacity(items.len());
    for item in items {
        verifying_keys.push(verifying_key);
        signatures.push(Signature::from_bytes(item.signature_bytes));
        messages.push(item.canonical);
    }
    if verify_batch(&messages, &signatures, &verifying_keys).is_ok() {
        return Ok(());
    }
    let failures = messages
        .iter()
        .zip(signatures.iter())
        .enumerate()
        .filter_map(|(index, (message, signature))| {
            verifying_key.verify_strict(message, signature).is_err().then_some(index)
        })
        .collect::<Vec<_>>();
    if failures.is_empty() { Ok(()) } else { Err(failures) }
}

/// # Errors
/// Returns an error when the value cannot be canonicalized.
pub fn sign_with_device_branch<T: Serialize>(
    device_branch: &DeviceBranch,
    value: &T,
) -> Result<String, CryptoError> {
    let canonical = ramflux_protocol::canonical_json_bytes(value)?;
    let signature = device_branch.signing_key.sign(&canonical);
    Ok(encode_base64url(signature.to_bytes()))
}

/// # Errors
/// Returns an error when canonicalization or signature verification fails.
pub fn verify_device_branch_signature<T: Serialize>(
    device_public_key_base64url: &str,
    value: &T,
    signature_base64url: &str,
) -> Result<(), CryptoError> {
    let canonical = ramflux_protocol::canonical_json_bytes(value)?;
    verify_canonical_signature(&canonical, signature_base64url, device_public_key_base64url)
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn verify_fixture_signature(
    canonical: &[u8],
    signature_base64url: &str,
) -> Result<(), CryptoError> {
    verify_canonical_signature(canonical, signature_base64url, &fixture_public_key_base64url())
}
