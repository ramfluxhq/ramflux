// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! HPKE base-mode wrap of one file key to one recipient device.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::{Kem, X25519HkdfSha256};
use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable, setup_receiver, setup_sender_with_rng};
use std::convert::Infallible;
use zeroize::{Zeroize, Zeroizing};

const INFO: &[u8] = b"ramflux.attachment.key_slot.v1";
const ENCAP: usize = 32;
const TAG: usize = 16;

type SuiteKem = X25519HkdfSha256;
type SuiteKdf = HkdfSha256;
type SuiteAead = AesGcm256;

/// Values bound into the key-slot AEAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySlotBinding {
    pub object_id: [u8; 32],
    pub relay_hash: [u8; 32],
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub grant_id: [u8; 32],
    pub reference_id: [u8; 32],
}

/// The caller's current device, the slot recipient, and the grant grantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySlotParties<'a> {
    pub caller: &'a DeviceTarget,
    pub slot_recipient: &'a DeviceTarget,
    pub grant_grantee: &'a DeviceTarget,
}

/// One device identity compared with the slot and the grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTarget {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeySlotError {
    #[error("key slot binding rejected")]
    Binding,
    #[error("key slot recipient rejected")]
    Grantee,
    #[error("key slot format rejected")]
    Format,
    #[error("key slot authentication failed")]
    Authentication,
    #[error("key slot randomness unavailable")]
    Random,
}

/// Wraps the 32-byte file key to `recipient_public`.
/// # Errors
/// Rejects an empty identity, a zero epoch, or an HPKE setup failure.
pub fn wrap_file_key(
    file_key: &[u8; 32],
    recipient_public: &[u8; 32],
    binding: &KeySlotBinding,
) -> Result<Vec<u8>, KeySlotError> {
    let aad = associated_data(binding)?;
    let public = <SuiteKem as Kem>::PublicKey::from_bytes(recipient_public)
        .map_err(|_| KeySlotError::Binding)?;
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|_| KeySlotError::Random)?;
    let mut rng = SeededFill::from_seed(&seed);
    seed.zeroize();
    let (encapped, mut context) = setup_sender_with_rng::<SuiteAead, SuiteKdf, SuiteKem>(
        &OpModeS::Base,
        &public,
        INFO,
        &mut rng,
    )
    .map_err(|_| KeySlotError::Authentication)?;
    let enc = encapped.to_bytes();
    if enc.len() != ENCAP {
        return Err(KeySlotError::Authentication);
    }
    let sealed = context.seal(file_key, &aad).map_err(|_| KeySlotError::Authentication)?;
    let mut out = Vec::with_capacity(ENCAP + sealed.len());
    out.extend_from_slice(&enc);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens format 1 for the caller when the slot recipient and the grant grantee match.
/// # Errors
/// Refuses a format other than 1, an identity mismatch, or an AEAD failure.
pub fn open_file_key(
    format: u32,
    encrypted_key: &[u8],
    recipient_secret: &[u8; 32],
    binding: &KeySlotBinding,
    parties: &KeySlotParties<'_>,
) -> Result<Zeroizing<[u8; 32]>, KeySlotError> {
    if format != 1 {
        return Err(KeySlotError::Format);
    }
    if !matches_binding(parties.caller, binding)
        || parties.caller != parties.slot_recipient
        || parties.caller != parties.grant_grantee
    {
        return Err(KeySlotError::Grantee);
    }
    let aad = associated_data(binding)?;
    let (enc, ciphertext) =
        encrypted_key.split_at_checked(ENCAP).ok_or(KeySlotError::Authentication)?;
    if ciphertext.len() != 32 + TAG {
        return Err(KeySlotError::Authentication);
    }
    let secret = <SuiteKem as Kem>::PrivateKey::from_bytes(recipient_secret)
        .map_err(|_| KeySlotError::Binding)?;
    let encapped = <SuiteKem as Kem>::EncappedKey::from_bytes(enc)
        .map_err(|_| KeySlotError::Authentication)?;
    let mut context =
        setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(&OpModeR::Base, &secret, &encapped, INFO)
            .map_err(|_| KeySlotError::Authentication)?;
    let opened = context.open(ciphertext, &aad).map_err(|_| KeySlotError::Authentication)?;
    let key: [u8; 32] = opened.try_into().map_err(|_| KeySlotError::Authentication)?;
    Ok(Zeroizing::new(key))
}

fn matches_binding(target: &DeviceTarget, binding: &KeySlotBinding) -> bool {
    target.account_anchor == binding.account_anchor
        && target.device_id == binding.device_id
        && target.device_epoch == binding.device_epoch
}

fn associated_data(binding: &KeySlotBinding) -> Result<Vec<u8>, KeySlotError> {
    if binding.account_anchor.is_empty()
        || binding.account_anchor.len() > 256
        || binding.device_id.is_empty()
        || binding.device_id.len() > 256
        || binding.device_epoch == 0
    {
        return Err(KeySlotError::Binding);
    }
    let mut out = Vec::new();
    out.extend(binding.object_id);
    out.extend(binding.relay_hash);
    length_prefix(&mut out, binding.account_anchor.as_bytes())?;
    length_prefix(&mut out, binding.device_id.as_bytes())?;
    out.extend(binding.device_epoch.to_be_bytes());
    out.extend(binding.grant_id);
    out.extend(binding.reference_id);
    Ok(out)
}

fn length_prefix(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), KeySlotError> {
    let length = u32::try_from(bytes.len()).map_err(|_| KeySlotError::Binding)?;
    out.extend(length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct SeededFill {
    cipher: chacha20::ChaCha20,
}

impl SeededFill {
    fn from_seed(seed: &[u8; 32]) -> Self {
        let nonce = chacha20::Nonce::from([0_u8; 12]);
        Self { cipher: chacha20::ChaCha20::new(seed.into(), &nonce) }
    }
}

impl TryRng for SeededFill {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        dest.fill(0);
        self.cipher.apply_keystream(dest);
        Ok(())
    }
}

impl TryCryptoRng for SeededFill {}

#[cfg(test)]
mod tests;
