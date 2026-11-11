// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Audited ordinary-DM identity and namespace reservation. Roots are verified by the caller.
use super::identity::lp;

pub const DOMAIN: &str = "ramflux.message.dm_conversation.v1";
pub const PREFIX: &str = "dm:";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DmScopeError {
    #[error("invalid canonical root anchor")]
    Anchor,
    #[error("ordinary DM requires two distinct roots")]
    EqualRoots,
    #[error("reserved DM conversation belongs to another root pair")]
    WrongPair,
    #[error("group conversation cannot use the reserved dm: namespace")]
    ReservedGroup,
}

fn anchor(value: &str) -> Result<(), DmScopeError> {
    if value.len() != 43 || !value.is_ascii() {
        return Err(DmScopeError::Anchor);
    }
    let bytes = crate::decode_base64url(value).map_err(|_| DmScopeError::Anchor)?;
    if bytes.len() != 32 || crate::encode_base64url(bytes) != value {
        return Err(DmScopeError::Anchor);
    }
    Ok(())
}

/// The fixed 132-byte transcript, sorted by encoded ASCII anchors, without normalization.
/// # Errors
/// Refuses malformed or equal anchors.
pub fn transcript(first: &str, second: &str) -> Result<Vec<u8>, DmScopeError> {
    anchor(first)?;
    anchor(second)?;
    if first == second {
        return Err(DmScopeError::EqualRoots);
    }
    let (a, b) =
        if first.as_bytes() < second.as_bytes() { (first, second) } else { (second, first) };
    let mut bytes = Vec::with_capacity(132);
    for value in [DOMAIN.as_bytes(), a.as_bytes(), b.as_bytes()] {
        lp(&mut bytes, value).map_err(|_| DmScopeError::Anchor)?;
    }
    Ok(bytes)
}

/// Shared sender/receiver conversation derivation. This public id grants no authority.
/// # Errors
/// Refuses malformed or equal anchors.
pub fn derive(first: &str, second: &str) -> Result<String, DmScopeError> {
    Ok(format!(
        "{PREFIX}{}",
        crate::encode_base64url(blake3::hash(&transcript(first, second)?).as_bytes())
    ))
}

/// Reserve the entire prefix at every group creation, import, link and repair boundary.
/// # Errors
/// Refuses even malformed ids beginning with the reserved prefix.
pub fn validate_group(conversation: &str) -> Result<(), DmScopeError> {
    if conversation.starts_with(PREFIX) { Err(DmScopeError::ReservedGroup) } else { Ok(()) }
}

/// Check every reserved direct id, including an existing one; callers also check bound roots/kind.
/// # Errors
/// Refuses another pair's reserved id or malformed verified anchors.
pub fn validate_direct(conversation: &str, local: &str, peer: &str) -> Result<(), DmScopeError> {
    if conversation.starts_with(PREFIX) && conversation != derive(local, peer)? {
        return Err(DmScopeError::WrongPair);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NA";
    const B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const ID: &str = "dm:kMnoa9jDpfKsJjopJ4NV7ScM259q2dzi2X3NpgG6bFQ";
    #[test]
    fn golden_ascii_ordered_dm_scope() -> Result<(), DmScopeError> {
        let bytes = transcript(A, B)?;
        let hex = |bytes: &[u8]| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            bytes
                .iter()
                .flat_map(|b| {
                    [char::from(HEX[usize::from(b >> 4)]), char::from(HEX[usize::from(b & 15)])]
                })
                .collect::<String>()
        };
        assert_eq!(bytes.len(), 132);
        assert_eq!(
            hex(&bytes),
            "0000002272616d666c75782e6d6573736167652e646d5f636f6e766572736174696f6e2e76310000002b304e4451304e4451304e4451304e4451304e4451304e4451304e4451304e4451304e4451304e4451304e410000002b41414141414141414141414141414141414141414141414141414141414141414141414141414141414141"
        );
        assert_eq!(
            hex(blake3::hash(&bytes).as_bytes()),
            "90c9e86bd8c3a5f2ac263a29278355ed270cdb9f6ad9dce2d97dcda601ba6c54"
        );
        assert_eq!(derive(A, B)?, ID);
        assert_eq!(derive(B, A)?, ID);
        assert!(A < B);
        assert!(
            crate::decode_base64url(A).map_err(|_| DmScopeError::Anchor)?
                > crate::decode_base64url(B).map_err(|_| DmScopeError::Anchor)?
        );
        let digest = blake3::hash(&bytes);
        assert_ne!(blake3::hash(format!("{DOMAIN}\0{A}\0{B}").as_bytes()), digest);
        assert_ne!(blake3::hash(format!("{DOMAIN}{A}{B}").as_bytes()), digest);
        assert_ne!(blake3::derive_key(DOMAIN, format!("{A}{B}").as_bytes()), *digest.as_bytes());
        Ok(())
    }
    #[test]
    fn malformed_roots_and_namespace_are_refused() -> Result<(), DmScopeError> {
        assert_eq!(derive(A, A), Err(DmScopeError::EqualRoots));
        for bad in [
            "",
            "AAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            " AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAé",
        ] {
            assert_eq!(derive(A, bad), Err(DmScopeError::Anchor), "{bad}");
        }
        for group in ["dm:", "dm:malformed", ID] {
            assert_eq!(validate_group(group), Err(DmScopeError::ReservedGroup));
        }
        validate_group("group:ordinary")?;
        validate_direct(ID, A, B)?;
        assert_eq!(validate_direct("dm:wrong", A, B), Err(DmScopeError::WrongPair));
        let third = crate::encode_base64url([1; 32]);
        assert_eq!(validate_direct(ID, A, &third), Err(DmScopeError::WrongPair));
        Ok(())
    }
}
