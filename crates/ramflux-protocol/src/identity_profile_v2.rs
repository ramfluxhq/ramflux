// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit profile-version dispatch; invalid v2 never falls back to legacy parsing.
pub use crate::username_directory::{AvatarRef, IdentityProfileV2Body, SignedIdentityProfileV2};
use crate::username_directory::{CodecError, Wire};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityProfileDocument {
    V1(crate::SignedIdentityProfile),
    V2(SignedIdentityProfileV2),
}
/// # Errors
/// Rejects noncanonical or invalid records without a version fallback.
pub fn decode_profile_document(bytes: &[u8]) -> Result<IdentityProfileDocument, CodecError> {
    if bytes.len() > 4096 {
        return Err(CodecError::Size);
    }
    let value: serde_json::Value = crate::parse_i_json(bytes)?;
    if value.get("body").is_some() {
        return crate::username_directory::decode(bytes).map(IdentityProfileDocument::V2);
    }
    let profile: crate::SignedIdentityProfile = serde_json::from_value(value)?;
    crate::identity_profile_signing_bytes(&profile)?;
    if crate::canonical_json_bytes(&profile)? != bytes {
        return Err(CodecError::Noncanonical);
    }
    Ok(IdentityProfileDocument::V1(profile))
}
impl IdentityProfileDocument {
    /// # Errors
    /// Rejects invalid values or serialization failures; legacy bytes are unchanged.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        match self {
            Self::V1(p) => {
                crate::identity_profile_signing_bytes(p)?;
                Ok(crate::canonical_json_bytes(p)?)
            }
            Self::V2(p) => {
                p.validate()?;
                crate::username_directory::encode(p)
            }
        }
    }
}
