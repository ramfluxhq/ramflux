// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native account-anchor check for mention values. Reuses custody `bytes(value, 32)`.

use super::validate;
use crate::CryptoError;

/// Canonical unpadded base64url encoding of exactly 32 bytes (43 ASCII characters).
///
/// # Errors
/// Returns [`CryptoError::IdentityAuthority`] when the value is not the canonical
/// 43-character encoding of 32 bytes. This is not the ≤256-byte custody `id` check.
pub fn validate_native_account_anchor(value: &str) -> Result<[u8; 32], CryptoError> {
    let raw = validate::bytes(value, 32)?;
    <[u8; 32]>::try_from(raw).map_err(|_| validate::reject("noncanonical custody binary length"))
}

#[cfg(test)]
mod tests {
    use super::validate_native_account_anchor;
    use ramflux_protocol::encode_base64url;

    #[test]
    fn native_account_anchor_accepts_exact_43_character_canonical_encoding() {
        let value = encode_base64url([0x5a; 32]);
        assert_eq!(value.len(), 43);
        assert_eq!(validate_native_account_anchor(&value).ok(), Some([0x5a; 32]));
    }

    #[test]
    fn native_account_anchor_rejects_padding_aliases_and_id_length() {
        let canonical = encode_base64url([0xff; 32]);
        assert!(validate_native_account_anchor(&canonical).is_ok());
        assert!(validate_native_account_anchor(&format!("{canonical}=")).is_err());
        let aliased = canonical.replace('_', "/");
        assert_ne!(aliased, canonical);
        assert!(validate_native_account_anchor(&aliased).is_err());
        assert!(validate_native_account_anchor(&canonical[..42]).is_err());
        assert!(validate_native_account_anchor(&format!("{canonical}a")).is_err());
        assert!(validate_native_account_anchor("").is_err());
        assert!(validate_native_account_anchor(&"a".repeat(200)).is_err());
        assert!(validate_native_account_anchor(&"a".repeat(256)).is_err());
    }
}
