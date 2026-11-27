// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::LgError;

/// The 64-byte per-group host key file content: `skS seed (32) ‖ host_head_sk seed (32)`
/// (design section 2.4.2). Deliberately not `Clone`, not `Debug`, zeroized on drop; `NodeSecret`
/// is 32 bytes and `Clone` (`node_secret.rs:15`), so it is not reused.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LgGroupKey {
    bytes: [u8; 64],
}

impl LgGroupKey {
    /// Fresh random key material.
    ///
    /// # Errors
    /// Returns [`LgError::Random`] when the OS refuses randomness.
    pub fn generate() -> Result<Self, LgError> {
        Ok(Self { bytes: super::random_array::<64>()? })
    }

    /// # Errors
    /// Refuses any length other than 64.
    pub fn from_file_bytes(bytes: &[u8]) -> Result<Self, LgError> {
        let array: [u8; 64] =
            bytes.try_into().map_err(|_| LgError::KeyFile("key file must be 64 bytes"))?;
        Ok(Self { bytes: array })
    }

    /// The bytes to write into the key file.
    #[must_use]
    pub const fn file_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// POPRF root key seed.
    #[must_use]
    pub fn token_root_seed(&self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (dst, src) in out.iter_mut().zip(self.bytes.iter()) {
            *dst = *src;
        }
        out
    }

    /// Ed25519 seed of `host_head_sk`.
    #[must_use]
    pub fn head_signing_seed(&self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (dst, src) in out.iter_mut().zip(self.bytes.iter().skip(32)) {
            *dst = *src;
        }
        out
    }
}
