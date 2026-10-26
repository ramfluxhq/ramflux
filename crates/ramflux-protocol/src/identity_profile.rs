// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-owned public profile, independently signed and bound into complete device-set v2.
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIdentityProfile {
    pub domain: String,
    pub principal_id: String,
    pub principal_commitment: String,
    pub kind: crate::PrincipalKind,
    pub display_name: String,
    pub epoch: u64,
    pub signature: String,
}
/// Normalizes locally supplied public names before signing. Verifiers compare exact NFC bytes.
/// # Errors
/// Rejects blank, oversized or unsafe single-line names.
pub fn normalize_profile_display_name(value: &str) -> Result<String, crate::ProtocolError> {
    if value.len() > 1024 || !crate::text_safety::single_line_is_safe(value) {
        return Err(invalid());
    }
    let name: String = value.trim().nfc().collect();
    if name.is_empty()
        || name.len() > 256
        || name.chars().count() > 128
        || !crate::text_safety::single_line_is_safe(&name)
    {
        return Err(invalid());
    }
    Ok(name)
}
/// Canonical profile bytes exclude the signature and include the root/principal/domain binding.
/// # Errors
/// Rejects unsafe profile fields and non-I-JSON values.
pub fn identity_profile_signing_bytes(
    profile: &SignedIdentityProfile,
) -> Result<Vec<u8>, crate::ProtocolError> {
    if profile.domain != crate::domain::IDENTITY_PROFILE
        || profile.signature.len() > 86
        || profile.epoch == 0
        || profile.epoch > crate::MAX_SAFE_JSON_INTEGER
        || !matches!(
            profile.kind,
            crate::PrincipalKind::Human
                | crate::PrincipalKind::HeadlessAi
                | crate::PrincipalKind::Bot
        )
        || normalize_profile_display_name(&profile.display_name)? != profile.display_name
        || profile.principal_id.is_empty()
        || profile.principal_id.len() > 256
        || profile.principal_commitment.len() != 43
    {
        return Err(invalid());
    }
    let mut value = serde_json::to_value(profile)?;
    value.as_object_mut().ok_or_else(invalid)?.remove("signature");
    crate::canonical_json_bytes(&value)
}
fn invalid() -> crate::ProtocolError {
    crate::ProtocolError::InvalidIdentityRecord("invalid public identity profile")
}
