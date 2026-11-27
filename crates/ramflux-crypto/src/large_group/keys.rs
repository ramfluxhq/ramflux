// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Epoch key schedule (design section 2.4.1): every HKDF is HKDF-SHA-256 (RFC 5869) and `K_e` is
//! only ever an HKDF PRK, never an AEAD key.

use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::LgError;
use super::codec::Enc;

const RATCHET_INFO: &[u8] = b"lg-join";
const KC_INFO: &[u8] = b"rf-lg-kc-v1";
const CONTENT_INFO: &[u8] = b"rf-lg-content-v1";
const W_BODY_DOMAIN: &[u8] = b"rf-lg-wbody-v1";
/// Most joiners one `W`/`W'` may carry (design section 2.4 ON: at most 100).
pub const MAX_JOINERS_PER_ENTRY: usize = 100;

/// One epoch key `K_e`. Not `Clone`, not `Debug`, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EpochKey([u8; 32]);

impl EpochKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Fresh random key (create, removal `R`).
    ///
    /// # Errors
    /// Returns [`LgError::Random`] when the OS refuses randomness.
    pub fn generate() -> Result<Self, LgError> {
        Ok(Self(super::random_array::<32>()?))
    }

    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality (two slots from distinct writers agree).
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

fn expand(prk: &[u8; 32], info: &[u8]) -> Result<[u8; 32], LgError> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| LgError::Crypto("hkdf prk"))?;
    let mut out = [0_u8; 32];
    hkdf.expand(info, &mut out).map_err(|_| LgError::Crypto("hkdf expand"))?;
    Ok(out)
}

/// `H(W_body)` for the canonical host-visible `{group_id, kind, key_epoch, prev_key_seq, joiner P
/// list}` (R3-M2: fixed before `K_{e+1}`, `kc` and `slot_root` exist).
///
/// # Errors
/// Refuses an empty or oversized joiner list.
pub fn w_body_hash(
    group_id: &[u8; 32],
    kind: u8,
    key_epoch: u64,
    prev_key_seq: u64,
    joiners: &[[u8; 32]],
) -> Result<[u8; 32], LgError> {
    if joiners.is_empty() || joiners.len() > MAX_JOINERS_PER_ENTRY {
        return Err(LgError::Format("joiner count"));
    }
    let count = u32::try_from(joiners.len()).map_err(|_| LgError::Format("joiner count"))?;
    let mut enc = Enc::new(W_BODY_DOMAIN);
    enc.fixed(group_id).u8(kind).u64(key_epoch).u64(prev_key_seq).u32(count);
    for joiner in joiners {
        enc.fixed(joiner);
    }
    Ok(*blake3::hash(&enc.finish()).as_bytes())
}

/// Join ratchet: `K_{e+1} = HKDF-Expand-SHA-256(K_e, "lg-join" ‖ H(W_body), 32)`.
///
/// # Errors
/// Returns a crypto error when HKDF expansion fails.
pub fn ratchet_epoch_key(k_e: &EpochKey, w_body: &[u8; 32]) -> Result<EpochKey, LgError> {
    let mut info = Vec::with_capacity(RATCHET_INFO.len() + 32);
    info.extend_from_slice(RATCHET_INFO);
    info.extend_from_slice(w_body);
    Ok(EpochKey(expand(&k_e.0, &info)?))
}

fn epoch_info(prefix: &[u8], group_id: &[u8; 32], key_epoch: u64) -> Vec<u8> {
    let mut info = Vec::with_capacity(prefix.len() + 40);
    info.extend_from_slice(prefix);
    info.extend_from_slice(group_id);
    info.extend_from_slice(&key_epoch.to_be_bytes());
    info
}

/// `kc = HKDF-Expand-SHA-256(K_{e+1}, "rf-lg-kc-v1" ‖ group_id ‖ I2OSP(key_epoch, 8), 32)`.
///
/// # Errors
/// Returns a crypto error when HKDF expansion fails.
pub fn derive_kc(k: &EpochKey, group_id: &[u8; 32], key_epoch: u64) -> Result<[u8; 32], LgError> {
    expand(&k.0, &epoch_info(KC_INFO, group_id, key_epoch))
}

/// `k_content = HKDF-Expand-SHA-256(K_e, "rf-lg-content-v1" ‖ group_id ‖ I2OSP(key_epoch, 8), 32)`.
///
/// # Errors
/// Returns a crypto error when HKDF expansion fails.
pub fn derive_k_content(
    k: &EpochKey,
    group_id: &[u8; 32],
    key_epoch: u64,
) -> Result<EpochKey, LgError> {
    Ok(EpochKey(expand(&k.0, &epoch_info(CONTENT_INFO, group_id, key_epoch))?))
}
