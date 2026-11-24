// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Domain-separated pseudonyms for private diagnostic identifiers.
use crate::CryptoError;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fmt::Write as _;

/// Return `h:` and ten lowercase hex characters of HMAC-SHA-256(key, class || NUL || value).
/// # Errors
/// Returns a typed crypto error if the HMAC cannot be initialized.
pub fn diagnostic_short_hash(
    key: &[u8; 32],
    class: &str,
    value: &[u8],
) -> Result<String, CryptoError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| CryptoError::HmacFailed)?;
    mac.update(class.as_bytes());
    mac.update(&[0]);
    mac.update(value);
    let digest = mac.finalize().into_bytes();
    let mut result = String::from("h:");
    for byte in digest.iter().take(5) {
        write!(&mut result, "{byte:02x}").map_err(|_| CryptoError::HmacFailed)?;
    }
    Ok(result)
}
