// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stable v2 identity comparison over canonical account anchors, separate from roster trust.
use crate::CryptoError;

fn anchor(value: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = ramflux_protocol::decode_base64url(value)
        .map_err(|_| CryptoError::IdentityAuthority("invalid safety anchor"))?;
    if ramflux_protocol::encode_base64url(&bytes) != value {
        return Err(CryptoError::IdentityAuthority("noncanonical safety anchor"));
    }
    bytes.try_into().map_err(|_| CryptoError::IdentityAuthority("invalid safety anchor length"))
}
/// Compute the custody v2 safety fingerprint from two independently authenticated anchors.
/// # Errors
/// Rejects noncanonical anchors and anchors whose decoded length is not 32 bytes.
pub fn safety_fingerprint(first: &str, second: &str) -> Result<[u8; 32], CryptoError> {
    let first = anchor(first)?;
    let second = anchor(second)?;
    let (first, second) = if first <= second { (first, second) } else { (second, first) };
    let mut hasher = blake3::Hasher::new();
    hasher.update(ramflux_protocol::domain::CUSTODY_SAFETY_NUMBER.as_bytes());
    hasher.update(&[0]);
    hasher.update(&first);
    hasher.update(&second);
    Ok(*hasher.finalize().as_bytes())
}
/// Render the v2 anchor fingerprint with the existing twelve-group rejection sampler.
/// # Errors
/// Rejects invalid account anchors.
pub fn safety_number(first: &str, second: &str) -> Result<Vec<String>, CryptoError> {
    Ok(crate::key_verification::render_safety_fingerprint(&safety_fingerprint(first, second)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_safety_comparison_sorts_decoded_anchors_and_uses_exact_nul_framing()
    -> Result<(), CryptoError> {
        let a = ramflux_protocol::encode_base64url([0; 32]);
        let b = ramflux_protocol::encode_base64url([255; 32]);
        let expected = blake3::hash(
            &[b"ramflux.identity.safety_number.v2\0".as_slice(), &[0; 32], &[255; 32]].concat(),
        );
        assert_eq!(safety_fingerprint(&a, &b)?, *expected.as_bytes());
        assert_eq!(safety_fingerprint(&b, &a)?, *expected.as_bytes());
        let groups = safety_number(&a, &b)?;
        assert_eq!(groups, safety_number(&b, &a)?);
        assert_eq!(groups.len(), 12);
        assert!(
            groups
                .iter()
                .all(|group| group.len() == 5 && group.bytes().all(|c| c.is_ascii_digit()))
        );
        assert!(safety_number(&format!("{a}="), &b).is_err());
        assert!(safety_number(&ramflux_protocol::encode_base64url([1; 31]), &b).is_err());
        Ok(())
    }
}
