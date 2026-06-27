// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, PrekeyBundle, X25519KeyPair, blake3_256, hkdf_sha256};
use std::fmt;

#[derive(Clone)]
pub struct X3dhInitiatorInput<'a> {
    pub initiator_identity: &'a X25519KeyPair,
    pub initiator_ephemeral: &'a X25519KeyPair,
    pub initiator_device_id_hash: [u8; 32],
    pub recipient_device_id_hash: [u8; 32],
    pub recipient_bundle: &'a PrekeyBundle,
    pub associated_data: &'a [u8],
    pub prekey_bundle_hash: &'a [u8],
    pub initial_ratchet_public: [u8; 32],
}

#[derive(Clone)]
pub struct X3dhRecipientInput<'a> {
    pub recipient_identity: &'a X25519KeyPair,
    pub recipient_signed_prekey: &'a X25519KeyPair,
    pub recipient_one_time_prekey: Option<&'a X25519KeyPair>,
    pub initiator_identity_public: [u8; 32],
    pub initiator_ephemeral_public: [u8; 32],
    pub initiator_device_id_hash: [u8; 32],
    pub recipient_device_id_hash: [u8; 32],
    pub recipient_signed_prekey_id: &'a str,
    pub recipient_one_time_prekey_id: Option<&'a str>,
    pub associated_data: &'a [u8],
    pub prekey_bundle_hash: &'a [u8],
    pub initial_ratchet_public: [u8; 32],
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct X3dhOutput {
    pub root_seed: [u8; 32],
    pub associated_secret: [u8; 32],
    pub bootstrap_transcript_hash: [u8; 32],
}

impl fmt::Debug for X3dhOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X3dhOutput")
            .field("root_seed", &"<redacted>")
            .field("associated_secret", &"<redacted>")
            .field("bootstrap_transcript_hash", &"<redacted>")
            .finish()
    }
}

pub struct BootstrapTranscriptInput<'a> {
    pub initiator_device_id_hash: &'a [u8; 32],
    pub recipient_device_id_hash: &'a [u8; 32],
    pub recipient_signed_prekey_id: &'a str,
    pub recipient_one_time_prekey_id: Option<&'a str>,
    pub initiator_ephemeral_public: &'a [u8; 32],
    pub prekey_bundle_hash: &'a [u8],
    pub initial_ratchet_public: &'a [u8; 32],
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn x3dh_initiator(input: &X3dhInitiatorInput<'_>) -> Result<X3dhOutput, CryptoError> {
    let dh1 = input
        .initiator_identity
        .secret
        .diffie_hellman(&X25519PublicKey::from(input.recipient_bundle.signed_prekey));
    let dh2 = input
        .initiator_ephemeral
        .secret
        .diffie_hellman(&X25519PublicKey::from(input.recipient_bundle.identity_key));
    let dh3 = input
        .initiator_ephemeral
        .secret
        .diffie_hellman(&X25519PublicKey::from(input.recipient_bundle.signed_prekey));
    let dh4 = input
        .recipient_bundle
        .one_time_prekey
        .map(|key| input.initiator_ephemeral.secret.diffie_hellman(&X25519PublicKey::from(key)));
    derive_x3dh_output(
        &[dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()],
        dh4.as_ref().map(x25519_dalek::SharedSecret::as_bytes),
        input.prekey_bundle_hash,
        input.associated_data,
        &BootstrapTranscriptInput {
            initiator_device_id_hash: &input.initiator_device_id_hash,
            recipient_device_id_hash: &input.recipient_device_id_hash,
            recipient_signed_prekey_id: &input.recipient_bundle.signed_prekey_id,
            recipient_one_time_prekey_id: input.recipient_bundle.one_time_prekey_id.as_deref(),
            initiator_ephemeral_public: &input.initiator_ephemeral.public,
            prekey_bundle_hash: input.prekey_bundle_hash,
            initial_ratchet_public: &input.initial_ratchet_public,
        },
    )
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn x3dh_recipient(input: &X3dhRecipientInput<'_>) -> Result<X3dhOutput, CryptoError> {
    let dh1 = input
        .recipient_signed_prekey
        .secret
        .diffie_hellman(&X25519PublicKey::from(input.initiator_identity_public));
    let dh2 = input
        .recipient_identity
        .secret
        .diffie_hellman(&X25519PublicKey::from(input.initiator_ephemeral_public));
    let dh3 = input
        .recipient_signed_prekey
        .secret
        .diffie_hellman(&X25519PublicKey::from(input.initiator_ephemeral_public));
    let dh4 = input.recipient_one_time_prekey.map(|key| {
        key.secret.diffie_hellman(&X25519PublicKey::from(input.initiator_ephemeral_public))
    });
    derive_x3dh_output(
        &[dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()],
        dh4.as_ref().map(x25519_dalek::SharedSecret::as_bytes),
        input.prekey_bundle_hash,
        input.associated_data,
        &BootstrapTranscriptInput {
            initiator_device_id_hash: &input.initiator_device_id_hash,
            recipient_device_id_hash: &input.recipient_device_id_hash,
            recipient_signed_prekey_id: input.recipient_signed_prekey_id,
            recipient_one_time_prekey_id: input.recipient_one_time_prekey_id,
            initiator_ephemeral_public: &input.initiator_ephemeral_public,
            prekey_bundle_hash: input.prekey_bundle_hash,
            initial_ratchet_public: &input.initial_ratchet_public,
        },
    )
}

fn derive_x3dh_output(
    dh_values: &[&[u8; 32]],
    dh4: Option<&[u8; 32]>,
    prekey_bundle_hash: &[u8],
    associated_data: &[u8],
    transcript: &BootstrapTranscriptInput<'_>,
) -> Result<X3dhOutput, CryptoError> {
    let mut ikm = Vec::new();
    ikm.extend_from_slice(ramflux_protocol::domain::X3DH_INITIAL_SECRET.as_bytes());
    for value in dh_values {
        ikm.extend_from_slice(*value);
    }
    if let Some(value) = dh4 {
        ikm.extend_from_slice(value);
    }
    let salt = blake3_256(ramflux_protocol::domain::X3DH_INITIAL_SECRET, prekey_bundle_hash);
    let mut info = Vec::new();
    info.extend_from_slice(ramflux_protocol::domain::X3DH_INITIAL_SECRET.as_bytes());
    info.extend_from_slice(associated_data);
    let mut output = [0_u8; 64];
    hkdf_sha256(&salt, &ikm, &info, &mut output)?;
    let mut root_seed = [0_u8; 32];
    root_seed.copy_from_slice(&output[..32]);
    let mut associated_secret = [0_u8; 32];
    associated_secret.copy_from_slice(&output[32..]);
    let bootstrap_transcript_hash = bootstrap_transcript_hash(transcript);
    Ok(X3dhOutput { root_seed, associated_secret, bootstrap_transcript_hash })
}

#[must_use]
pub fn bootstrap_transcript_hash(input: &BootstrapTranscriptInput<'_>) -> [u8; 32] {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(ramflux_protocol::domain::X3DH_INITIAL_SECRET.as_bytes());
    transcript.extend_from_slice(input.initiator_device_id_hash);
    transcript.extend_from_slice(input.recipient_device_id_hash);
    transcript.extend_from_slice(input.recipient_signed_prekey_id.as_bytes());
    if let Some(one_time_id) = input.recipient_one_time_prekey_id {
        transcript.extend_from_slice(one_time_id.as_bytes());
    }
    transcript.extend_from_slice(input.initiator_ephemeral_public);
    transcript.extend_from_slice(input.prekey_bundle_hash);
    transcript.extend_from_slice(input.initial_ratchet_public);
    blake3_256(ramflux_protocol::domain::X3DH_INITIAL_SECRET, &transcript)
}
