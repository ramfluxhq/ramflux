// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! What the browser vault stores and how the wrapped blob is bound to its device and origin.
//!
//! One non-extractable AES-GCM key lives in IndexedDB by structured clone. It encrypts one blob
//! that holds the branch seeds and the database key. The wrap defends only against the blob being
//! copied alone: any script in the origin can ask the key to decrypt, and nothing is
//! hardware-bound. No primary seed or recovery secret has a slot in [`VaultSecrets`], so none can
//! be stored.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::WebError;

pub const VAULT_DATABASE: &str = "ramflux-keys";
pub const VAULT_DATABASE_VERSION: u32 = 1;
/// Object store and key of the non-extractable wrapping key.
pub const WRAP_STORE: &str = "wrap";
pub const WRAP_KEY_ID: &str = "v1";
/// Object store of the wrapped blob, the public link pins and the sentinel.
pub const STATE_STORE: &str = "state";
pub const WRAPPED_BLOB_ID: &str = "secrets.v1";
pub const LINK_PINS_ID: &str = "pins.v1";

pub const WRAP_ALGORITHM: &str = "AES-GCM";
pub const WRAP_KEY_BITS: u32 = 256;
pub const WRAP_IV_BYTES: usize = 12;
pub const WRAP_TAG_BITS: u32 = 128;
/// The wrapping key can only encrypt and decrypt; it can never be exported or used to wrap.
pub const WRAP_KEY_EXTRACTABLE: bool = false;
pub const WRAP_KEY_USAGES: [&str; 2] = ["encrypt", "decrypt"];

const WRAP_AAD_TAG: &[u8] = b"ramflux.web.wrap.v1";
const WRAPPED_BLOB_VERSION: u32 = 1;
/// Upper bound of a wrapped blob; the plaintext is three 32-byte secrets in a small document.
pub const MAX_WRAPPED_BLOB_BYTES: usize = 4096;

/// Everything secret a web device holds at rest. A linked secondary device has exactly these.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct VaultSecrets {
    /// Ed25519 branch signing seed of this device, base64url.
    pub branch_signing_seed: String,
    /// X25519 agreement identity seed of this device, base64url.
    pub agreement_identity_seed: String,
    /// Raw 256-bit database key, base64url.
    pub database_key: String,
}

impl core::fmt::Debug for VaultSecrets {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VaultSecrets(redacted)")
    }
}

/// The record stored beside the wrapping key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedBlob {
    pub v: u32,
    /// Twelve random bytes, fresh for every write, base64url.
    pub iv: String,
    /// AES-GCM ciphertext with the tag appended, base64url.
    pub ct: String,
}

impl WrappedBlob {
    /// # Errors
    /// Returns [`WebError::VaultUnavailable`] for a malformed or oversized record.
    pub fn new(iv: &[u8], ciphertext: &[u8]) -> Result<Self, WebError> {
        if iv.len() != WRAP_IV_BYTES {
            return Err(WebError::VaultUnavailable("wrap nonce is not 12 bytes"));
        }
        if ciphertext.len() <= (WRAP_TAG_BITS / 8) as usize || ciphertext.len() > MAX_WRAPPED_BLOB_BYTES {
            return Err(WebError::VaultUnavailable("wrapped blob has an impossible length"));
        }
        Ok(Self {
            v: WRAPPED_BLOB_VERSION,
            iv: ramflux_protocol::encode_base64url(iv),
            ct: ramflux_protocol::encode_base64url(ciphertext),
        })
    }

    /// Decode the nonce and ciphertext for decryption.
    ///
    /// # Errors
    /// Returns [`WebError::VaultUnavailable`] for an unknown version or malformed fields.
    pub fn parts(&self) -> Result<(Vec<u8>, Vec<u8>), WebError> {
        let malformed = WebError::VaultUnavailable("wrapped blob is malformed");
        if self.v != WRAPPED_BLOB_VERSION {
            return Err(WebError::VaultUnavailable("wrapped blob version is unknown"));
        }
        let iv = ramflux_protocol::decode_base64url(&self.iv).map_err(|_| malformed.clone())?;
        let ct = ramflux_protocol::decode_base64url(&self.ct).map_err(|_| malformed.clone())?;
        if iv.len() != WRAP_IV_BYTES || ct.len() > MAX_WRAPPED_BLOB_BYTES {
            return Err(malformed);
        }
        Ok((iv, ct))
    }
}

/// Additional data: `"ramflux.web.wrap.v1" || 0x00 || device_id || 0x00 || origin`. A blob moved
/// to another device record or origin fails to decrypt.
#[must_use]
pub fn wrap_additional_data(device_id: &str, origin: &str) -> Vec<u8> {
    let mut data = Vec::with_capacity(WRAP_AAD_TAG.len() + device_id.len() + origin.len() + 2);
    data.extend_from_slice(WRAP_AAD_TAG);
    data.push(0);
    data.extend_from_slice(device_id.as_bytes());
    data.push(0);
    data.extend_from_slice(origin.as_bytes());
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additional_data_separates_device_and_origin() {
        assert_ne!(wrap_additional_data("ab", "c"), wrap_additional_data("a", "bc"));
        assert_eq!(
            wrap_additional_data("d", "https://o"),
            b"ramflux.web.wrap.v1\0d\0https://o".to_vec()
        );
    }

    #[test]
    fn the_wrapping_key_is_never_extractable_and_cannot_wrap() {
        assert!(!WRAP_KEY_EXTRACTABLE);
        assert!(!WRAP_KEY_USAGES.contains(&"wrapKey"));
        assert!(!WRAP_KEY_USAGES.contains(&"deriveKey"));
    }

    #[test]
    fn the_vault_has_no_slot_for_a_primary_seed_or_recovery_secret() {
        let with_seed = r#"{"branch_signing_seed":"a","agreement_identity_seed":"b","database_key":"c","primary_seed":"d"}"#;
        assert!(serde_json::from_str::<VaultSecrets>(with_seed).is_err());
        let with_recovery = r#"{"branch_signing_seed":"a","agreement_identity_seed":"b","database_key":"c","recovery_secret":"d"}"#;
        assert!(serde_json::from_str::<VaultSecrets>(with_recovery).is_err());
    }

    #[test]
    fn rejects_a_wrong_nonce_length_and_round_trips_the_record() {
        assert!(WrappedBlob::new(&[0; 11], &[0; 64]).is_err());
        let blob = WrappedBlob::new(&[1; 12], &[2; 64]).unwrap_or_else(|_| unreachable!());
        assert_eq!(blob.parts(), Ok((vec![1; 12], vec![2; 64])));
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let secrets = VaultSecrets {
            branch_signing_seed: "seed".to_owned(),
            agreement_identity_seed: "seed".to_owned(),
            database_key: "key".to_owned(),
        };
        assert!(!format!("{secrets:?}").contains("seed"));
    }
}
