// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! File-key seal under the account key. The AEAD lives in `ramflux-crypto`.

use super::codes::{CODE_SEAL_FAILED, Refusal};

#[must_use]
pub(crate) fn seal_key(account_secret: &[u8; 32], prepare_id: &str) -> [u8; 32] {
    ramflux_crypto::blake3_keyed_derive(account_secret, prepare_id.as_bytes())
}

/// # Errors
/// Returns `seal_failed` when randomness or the AEAD rejects the record.
pub(crate) fn seal(
    key: &[u8; 32],
    file_key: &[u8; 32],
    object_id: &[u8; 32],
) -> Result<Vec<u8>, Refusal> {
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    ramflux_crypto::large_attachment::seal_prepare_record(key, file_key, object_id, &nonce)
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))
}

/// # Errors
/// Returns `seal_failed` when the record does not open.
pub(crate) fn open(
    key: &[u8; 32],
    blob: &[u8],
) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32]), Refusal> {
    ramflux_crypto::large_attachment::open_prepare_record(key, blob)
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))
}
