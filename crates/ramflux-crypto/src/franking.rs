// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ramflux_protocol::{decode_base64url, encode_base64url};

use crate::{CryptoError, blake3_256_base64url, write_len_prefixed};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrankingCommitmentInput<'a> {
    pub plaintext: &'a [u8],
    pub sender_device_id_hash: &'a [u8],
    pub message_event_id: &'a str,
    pub canonical_header_bytes: &'a [u8],
    pub associated_data: &'a [u8],
    pub ciphertext: &'a [u8],
    pub opening_key: &'a [u8; 32],
    pub commitment_key: &'a [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrankingCommitment {
    pub plaintext_hash: String,
    pub ciphertext_hash: String,
    pub header_hash: String,
    pub associated_data_hash: String,
    pub key_commitment: String,
    pub franking_commitment: String,
    pub commitment: String,
}

#[must_use]
pub fn franking_commitment(input: &FrankingCommitmentInput<'_>) -> FrankingCommitment {
    let plaintext_hash =
        blake3_256_base64url(ramflux_protocol::domain::COMMITTING_AEAD, input.plaintext);
    let ciphertext_hash =
        blake3_256_base64url(ramflux_protocol::domain::COMMITTING_AEAD, input.ciphertext);
    let header_hash = blake3_256_base64url(
        ramflux_protocol::domain::COMMITTING_AEAD_HEADER,
        input.canonical_header_bytes,
    );
    let associated_data_hash =
        blake3_256_base64url(ramflux_protocol::domain::COMMITTING_AEAD_AD, input.associated_data);

    let mut key_preimage = Vec::new();
    key_preimage.extend_from_slice(ramflux_protocol::domain::COMMITTING_AEAD.as_bytes());
    key_preimage.extend_from_slice(input.sender_device_id_hash);
    key_preimage.extend_from_slice(input.message_event_id.as_bytes());
    key_preimage.extend_from_slice(header_hash.as_bytes());
    key_preimage.extend_from_slice(associated_data_hash.as_bytes());
    key_preimage.extend_from_slice(ciphertext_hash.as_bytes());

    let mut key_hasher = blake3::Hasher::new_keyed(input.commitment_key);
    key_hasher.update(&key_preimage);
    let key_commitment_bytes = key_hasher.finalize();

    let mut franking_preimage = Vec::new();
    franking_preimage.extend_from_slice(ramflux_protocol::domain::FRANKING_OPENING.as_bytes());
    franking_preimage.extend_from_slice(input.plaintext);
    franking_preimage.extend_from_slice(input.sender_device_id_hash);
    franking_preimage.extend_from_slice(input.message_event_id.as_bytes());
    franking_preimage.extend_from_slice(header_hash.as_bytes());
    franking_preimage.extend_from_slice(associated_data_hash.as_bytes());

    let mut franking_hasher = blake3::Hasher::new_keyed(input.opening_key);
    franking_hasher.update(&franking_preimage);
    let franking_commitment_bytes = franking_hasher.finalize();

    let mut final_preimage = Vec::new();
    final_preimage.extend_from_slice(ramflux_protocol::domain::COMMITTING_AEAD.as_bytes());
    final_preimage.extend_from_slice(key_commitment_bytes.as_bytes());
    final_preimage.extend_from_slice(franking_commitment_bytes.as_bytes());

    FrankingCommitment {
        plaintext_hash,
        ciphertext_hash,
        header_hash,
        associated_data_hash,
        key_commitment: encode_base64url(key_commitment_bytes.as_bytes()),
        franking_commitment: encode_base64url(franking_commitment_bytes.as_bytes()),
        commitment: blake3_256_base64url(
            ramflux_protocol::domain::COMMITTING_AEAD,
            &final_preimage,
        ),
    }
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn franking_node_tag_preimage(
    node_id: &str,
    envelope_id: &str,
    message_event_id: &str,
    sender_device_id_hash: &[u8],
    commitment: &str,
    ciphertext_hash: &str,
    accepted_at_unix_ms: u64,
) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(ramflux_protocol::domain::FRANKING_NODE_TAG.as_bytes());
    write_len_prefixed(&mut preimage, node_id.as_bytes());
    write_len_prefixed(&mut preimage, envelope_id.as_bytes());
    write_len_prefixed(&mut preimage, message_event_id.as_bytes());
    write_len_prefixed(&mut preimage, sender_device_id_hash);
    write_len_prefixed(&mut preimage, commitment.as_bytes());
    write_len_prefixed(&mut preimage, ciphertext_hash.as_bytes());
    preimage.extend_from_slice(&accepted_at_unix_ms.to_be_bytes());
    preimage
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn sign_franking_node_tag(
    node_id: &str,
    envelope_id: &str,
    message_event_id: &str,
    sender_device_id_hash: &[u8],
    commitment: &str,
    ciphertext_hash: &str,
    accepted_at_unix_ms: u64,
    signing_key: &SigningKey,
) -> String {
    let preimage = franking_node_tag_preimage(
        node_id,
        envelope_id,
        message_event_id,
        sender_device_id_hash,
        commitment,
        ciphertext_hash,
        accepted_at_unix_ms,
    );
    encode_base64url(signing_key.sign(&preimage).to_bytes())
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn sign_franking_node_tag_with_seed(
    node_id: &str,
    envelope_id: &str,
    message_event_id: &str,
    sender_device_id_hash: &[u8],
    commitment: &str,
    ciphertext_hash: &str,
    accepted_at_unix_ms: u64,
    seed: [u8; 32],
) -> String {
    let signing_key = SigningKey::from_bytes(&seed);
    sign_franking_node_tag(
        node_id,
        envelope_id,
        message_event_id,
        sender_device_id_hash,
        commitment,
        ciphertext_hash,
        accepted_at_unix_ms,
        &signing_key,
    )
}

/// # Errors
/// Returns an error when the signature is malformed or does not verify.
pub fn verify_franking_node_tag(
    preimage: &[u8],
    signature_base64url: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let bytes = decode_base64url(signature_base64url)?;
    let signature_bytes: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidSignatureLength(bytes.len()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key.verify_strict(preimage, &signature).map_err(|_err| CryptoError::VerifyFailed)
}
