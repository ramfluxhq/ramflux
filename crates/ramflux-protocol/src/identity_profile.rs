// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-owned public profile, independently signed and bound into complete device-set v2.
use crate::identity_name::normalize_profile_display_name;
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod name_policy_tests {
    use super::*;
    #[test]
    fn profile_names_reject_blank_rendering_default_ignorables_and_false_verification_glyphs() {
        for name in [
            "\u{3164}",
            "\u{115f}\u{1160}",
            "\u{ffa0}",
            "\u{2800}",
            "\u{301}",
            "\u{301}Alice",
            "a\u{fe0f}\u{34f}b",
            "Alice\u{a0}\u{a0}(verified human)",
            "Alice ✓",
            "Alice ✔",
            "Alice ✅",
            "Alice ☑",
            "Alice 🗸",
            "Alice 🗹",
            "-._",
        ] {
            assert!(
                normalize_profile_display_name(name).is_err(),
                "unsafe name accepted: {name:?}"
            );
        }
        for ch in ['\u{ad}', '\u{17b4}', '\u{180b}', '\u{fe0e}', '\u{e0100}', '\u{e0001}'] {
            assert!(
                normalize_profile_display_name(&format!("A{ch}B")).is_err(),
                "default ignorable U+{:X}",
                u32::from(ch)
            );
        }
    }
}
