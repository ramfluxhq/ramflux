// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Admission for a user-chosen passphrase when it is set or changed.
//!
//! The rules are a minimum of 15 Unicode scalar values after NFC, acceptance of
//! at least 64 scalar values, no composition requirements, and an exact
//! case-insensitive blocklist match. Unlocking an existing secret does not use
//! this module.
//!
//! The blocklist is `Passwords/Common-Credentials/10k-most-common.txt` from
//! <https://github.com/danielmiessler/SecLists> at commit
//! `913b327317496d062bcc7cace524aaad8a693be2` (2026-09-08). The MIT licence
//! text ships beside the list as `common-passwords.LICENSE`.

use std::collections::HashSet;
use std::sync::OnceLock;

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::SdkError;

/// Minimum Unicode scalar values in the NFC form of a new passphrase.
pub const MIN_PASSPHRASE_SCALARS: usize = 15;

/// A new passphrase of this many scalar values must be accepted. This is not a maximum.
pub const MIN_ACCEPTED_PASSPHRASE_SCALARS: usize = 64;

/// Why a new passphrase was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PassphrasePolicyError {
    /// Fewer than [`MIN_PASSPHRASE_SCALARS`] Unicode scalar values after NFC.
    #[error("too_short")]
    TooShort {
        /// NFC scalar count of the refused passphrase.
        scalars: usize,
    },
    /// The NFC, case-folded passphrase is on the common-password blocklist.
    #[error("too_common")]
    TooCommon,
}

impl PassphrasePolicyError {
    /// Stable wire name for this rule.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooShort { .. } => "too_short",
            Self::TooCommon => "too_common",
        }
    }

    /// Sentence shown by `rf` for this rule. The wire [`Self::code`] stays unchanged.
    #[must_use]
    pub fn user_message(self) -> String {
        match self {
            Self::TooShort { scalars } => {
                let missing = MIN_PASSPHRASE_SCALARS.saturating_sub(scalars);
                format!(
                    "{missing} more characters needed. The data passphrase must be at least {MIN_PASSPHRASE_SCALARS} characters."
                )
            }
            Self::TooCommon => "This passphrase is too common or has appeared in a data breach. Choose a different one.".to_owned(),
        }
    }
}

/// Admit `passphrase` for a set or change.
///
/// # Errors
/// Returns [`PassphrasePolicyError::TooShort`] or [`PassphrasePolicyError::TooCommon`].
pub fn check_new_passphrase(passphrase: &str) -> Result<(), PassphrasePolicyError> {
    let normalized = Zeroizing::new(passphrase.nfc().collect::<String>());
    let scalars = normalized.chars().count();
    if scalars < MIN_PASSPHRASE_SCALARS {
        return Err(PassphrasePolicyError::TooShort { scalars });
    }
    let folded = Zeroizing::new(normalized.to_lowercase());
    if common_passphrases().contains(folded.as_str()) {
        return Err(PassphrasePolicyError::TooCommon);
    }
    Ok(())
}

/// Admit UTF-8 passphrase bytes for a set or change.
///
/// # Errors
/// Returns [`SdkError::CustodySetupInvalid`] for non-UTF-8 bytes, or a
/// [`PassphrasePolicyError`] for a rule failure.
pub(crate) fn admit_new_passphrase(bytes: &[u8]) -> Result<(), SdkError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    Ok(check_new_passphrase(text)?)
}

fn common_passphrases() -> &'static HashSet<String> {
    static LIST: OnceLock<HashSet<String>> = OnceLock::new();
    LIST.get_or_init(|| {
        include_str!("common-passwords.txt")
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| line.nfc().collect::<String>().to_lowercase())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::{
        MIN_ACCEPTED_PASSPHRASE_SCALARS, MIN_PASSPHRASE_SCALARS, PassphrasePolicyError,
        check_new_passphrase,
    };
    use unicode_normalization::UnicodeNormalization;

    #[test]
    fn fourteen_scalars_are_too_short_and_fifteen_are_admitted() {
        assert_eq!(
            check_new_passphrase(&"a".repeat(MIN_PASSPHRASE_SCALARS - 1)),
            Err(PassphrasePolicyError::TooShort { scalars: MIN_PASSPHRASE_SCALARS - 1 }),
            "test: 14 scalars were admitted"
        );
        assert_eq!(
            check_new_passphrase(&"a".repeat(MIN_PASSPHRASE_SCALARS)),
            Ok(()),
            "test: 15 scalars were refused"
        );
        assert_eq!(
            PassphrasePolicyError::TooShort { scalars: MIN_PASSPHRASE_SCALARS - 1 }.user_message(),
            "1 more characters needed. The data passphrase must be at least 15 characters.",
            "test: too_short sentence dropped the missing count"
        );
    }

    #[test]
    fn sixty_four_scalars_and_longer_passphrases_are_admitted() {
        assert_eq!(
            check_new_passphrase(&"q".repeat(MIN_ACCEPTED_PASSPHRASE_SCALARS)),
            Ok(()),
            "test: 64 scalars were refused"
        );
        assert_eq!(
            check_new_passphrase(&"q".repeat(MIN_ACCEPTED_PASSPHRASE_SCALARS + 1)),
            Ok(()),
            "test: 65 scalars were refused"
        );
        assert_eq!(
            check_new_passphrase(&"q".repeat(128)),
            Ok(()),
            "test: 128 scalars were refused"
        );
    }

    #[test]
    fn nfc_collapses_a_decomposed_scalar_below_the_minimum() {
        let decomposed = format!("{}e\u{0301}", "n".repeat(MIN_PASSPHRASE_SCALARS - 2));
        assert_eq!(
            decomposed.chars().count(),
            MIN_PASSPHRASE_SCALARS,
            "test: decomposed fixture is not 15 scalars before NFC"
        );
        assert_eq!(
            check_new_passphrase(&decomposed),
            Err(PassphrasePolicyError::TooShort { scalars: MIN_PASSPHRASE_SCALARS - 1 }),
            "test: NFC did not collapse the decomposed scalar below the minimum"
        );
        let composed: String = decomposed.nfc().collect();
        assert_eq!(
            composed.chars().count(),
            MIN_PASSPHRASE_SCALARS - 1,
            "test: NFC did not collapse the decomposed scalar"
        );
        let admitted = format!("{}é", "n".repeat(MIN_PASSPHRASE_SCALARS - 1));
        assert_eq!(
            admitted.chars().count(),
            MIN_PASSPHRASE_SCALARS,
            "test: composed fixture is not 15 scalars"
        );
        assert_eq!(
            check_new_passphrase(&admitted),
            Ok(()),
            "test: 15 composed scalars were refused"
        );
    }

    #[test]
    fn blocklist_hits_are_too_common_without_a_composition_rule() {
        assert_eq!(
            check_new_passphrase("films+pic+galeries"),
            Err(PassphrasePolicyError::TooCommon),
            "test: blocklist entry was admitted"
        );
        assert_eq!(
            check_new_passphrase("Films+Pic+Galeries"),
            Err(PassphrasePolicyError::TooCommon),
            "test: case-folded blocklist entry was admitted"
        );
        assert_eq!(
            check_new_passphrase(&"7".repeat(MIN_PASSPHRASE_SCALARS)),
            Ok(()),
            "test: a repeated digit was refused by a composition rule"
        );
        let short = PassphrasePolicyError::TooShort { scalars: 14 };
        assert_eq!(short.code(), "too_short", "test: too_short wire code changed");
        assert_eq!(
            PassphrasePolicyError::TooCommon.code(),
            "too_common",
            "test: too_common wire code changed"
        );
        assert_eq!(short.to_string(), "too_short", "test: too_short display changed");
        assert_eq!(
            PassphrasePolicyError::TooCommon.to_string(),
            "too_common",
            "test: too_common display changed"
        );
        assert_eq!(
            PassphrasePolicyError::TooCommon.user_message(),
            "This passphrase is too common or has appeared in a data breach. Choose a different one.",
            "test: too_common sentence changed"
        );
    }

    #[test]
    fn shipped_blocklist_license_is_the_pinned_mit_notice() {
        let license = include_str!("common-passwords.LICENSE");
        assert!(
            license.contains("MIT License"),
            "test: shipped blocklist licence is missing the MIT heading"
        );
        assert!(
            license.contains("Copyright (c) 2018 Daniel Miessler"),
            "test: shipped blocklist licence is missing the copyright notice"
        );
        assert!(
            license.contains("Permission is hereby granted"),
            "test: shipped blocklist licence is missing the permission notice"
        );
    }
}
