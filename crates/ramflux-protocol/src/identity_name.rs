// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded public-name normalization and warning-only UTS #39 analysis.
use unicode_general_category::{GeneralCategory as C, get_general_category};
use unicode_normalization::UnicodeNormalization;
use unicode_security::{
    GeneralSecurityProfile, MixedScript, general_security_profile::IdentifierType,
};

/// Normalizes locally supplied names; signed remote names must already equal this form.
/// # Errors
/// Rejects oversized, invisible, unsafe or symbol-only names and verification-like checkmarks.
pub fn normalize_profile_display_name(value: &str) -> Result<String, crate::ProtocolError> {
    if value.len() > 1024
        || !crate::text_safety::single_line_is_safe(value)
        || value.chars().any(unsafe_scalar)
    {
        return Err(invalid());
    }
    let name: String = value.trim().nfc().collect();
    if name.is_empty()
        || name.len() > 256
        || name.chars().count() > 128
        || name.chars().any(unsafe_scalar)
        || name.chars().next().is_some_and(|ch| {
            matches!(
                get_general_category(ch),
                C::NonspacingMark | C::SpacingMark | C::EnclosingMark
            )
        })
        || !name.chars().any(|ch| {
            matches!(
                get_general_category(ch),
                C::UppercaseLetter
                    | C::LowercaseLetter
                    | C::TitlecaseLetter
                    | C::ModifierLetter
                    | C::OtherLetter
                    | C::DecimalNumber
                    | C::LetterNumber
                    | C::OtherNumber
            )
        })
    {
        return Err(invalid());
    }
    Ok(name)
}
fn unsafe_scalar(ch: char) -> bool {
    ch.identifier_type() == Some(IdentifierType::Default_Ignorable)
        || matches!(
            get_general_category(ch),
            C::Control
                | C::Format
                | C::LineSeparator
                | C::ParagraphSeparator
                | C::PrivateUse
                | C::Unassigned
        )
        || get_general_category(ch) == C::SpaceSeparator && ch != ' '
        || matches!(
            ch,
            '\u{115f}'
                | '\u{1160}'
                | '\u{3164}'
                | '\u{ffa0}'
                | '\u{2800}'
                | '\u{2611}'
                | '\u{2705}'
                | '\u{2713}'
                | '\u{2714}'
                | '\u{1f5f8}'
                | '\u{1f5f9}'
        )
}
/// Warning facts are not identity equality or authorization. The skeleton is never display text.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct DisplayNameSecurity {
    pub confusable_skeleton: String,
    pub mixed_script: bool,
}
/// Computes warning-only confusability using the pinned Unicode security data.
/// # Errors
/// Rejects input outside the public-name policy and bounds.
pub fn profile_display_name_security(
    value: &str,
) -> Result<DisplayNameSecurity, crate::ProtocolError> {
    let name = normalize_profile_display_name(value)?;
    Ok(DisplayNameSecurity {
        confusable_skeleton: unicode_security::skeleton(&name).collect(),
        mixed_script: !name.as_str().is_single_script(),
    })
}
fn invalid() -> crate::ProtocolError {
    crate::ProtocolError::InvalidIdentityRecord("invalid public identity profile")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confusable_skeletons_detect_mixed_and_whole_script_impostors_without_rejecting_languages()
    -> Result<(), crate::ProtocolError> {
        assert_eq!(normalize_profile_display_name(" Cafe\u{301} ")?, "Café");
        let latin = profile_display_name_security("Alice")?;
        let mixed = profile_display_name_security("Al\u{456}ce")?;
        assert_eq!(latin.confusable_skeleton, mixed.confusable_skeleton);
        assert!(!latin.mixed_script);
        assert!(mixed.mixed_script);
        assert_eq!(
            profile_display_name_security("scope")?.confusable_skeleton,
            profile_display_name_security("ѕсоре")?.confusable_skeleton
        );
        assert!(!profile_display_name_security("ѕсоре")?.mixed_script);
        for name in ["小明", "مريم", "マリア", "123"] {
            assert!(normalize_profile_display_name(name).is_ok());
        }
        Ok(())
    }
}
