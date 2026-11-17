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
//! `913b327317496d062bcc7cace524aaad8a693be2` (2026-09-08), MIT licensed.

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
    TooShort,
    /// The NFC, case-folded passphrase is on the common-password blocklist.
    #[error("too_common")]
    TooCommon,
}

impl PassphrasePolicyError {
    /// Stable wire name for this rule.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::TooCommon => "too_common",
        }
    }
}

/// Admit `passphrase` for a set or change.
///
/// # Errors
/// Returns [`PassphrasePolicyError::TooShort`] or [`PassphrasePolicyError::TooCommon`].
pub fn check_new_passphrase(passphrase: &str) -> Result<(), PassphrasePolicyError> {
    let normalized = Zeroizing::new(passphrase.nfc().collect::<String>());
    if normalized.chars().count() < MIN_PASSPHRASE_SCALARS {
        return Err(PassphrasePolicyError::TooShort);
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
            Err(PassphrasePolicyError::TooShort)
        );
        assert_eq!(check_new_passphrase(&"a".repeat(MIN_PASSPHRASE_SCALARS)), Ok(()));
    }

    #[test]
    fn sixty_four_scalars_and_longer_passphrases_are_admitted() {
        assert_eq!(check_new_passphrase(&"q".repeat(MIN_ACCEPTED_PASSPHRASE_SCALARS)), Ok(()));
        assert_eq!(check_new_passphrase(&"q".repeat(MIN_ACCEPTED_PASSPHRASE_SCALARS + 1)), Ok(()));
        assert_eq!(check_new_passphrase(&"q".repeat(128)), Ok(()));
    }

    #[test]
    fn nfc_collapses_a_decomposed_scalar_below_the_minimum() {
        let decomposed = format!("{}e\u{0301}", "n".repeat(MIN_PASSPHRASE_SCALARS - 2));
        assert_eq!(decomposed.chars().count(), MIN_PASSPHRASE_SCALARS);
        assert_eq!(check_new_passphrase(&decomposed), Err(PassphrasePolicyError::TooShort));
        let composed: String = decomposed.nfc().collect();
        assert_eq!(composed.chars().count(), MIN_PASSPHRASE_SCALARS - 1);
        let admitted = format!("{}é", "n".repeat(MIN_PASSPHRASE_SCALARS - 1));
        assert_eq!(admitted.chars().count(), MIN_PASSPHRASE_SCALARS);
        assert_eq!(check_new_passphrase(&admitted), Ok(()));
    }

    #[test]
    fn blocklist_hits_are_too_common_without_a_composition_rule() {
        assert_eq!(
            check_new_passphrase("films+pic+galeries"),
            Err(PassphrasePolicyError::TooCommon)
        );
        assert_eq!(
            check_new_passphrase("Films+Pic+Galeries"),
            Err(PassphrasePolicyError::TooCommon)
        );
        assert_eq!(check_new_passphrase(&"7".repeat(MIN_PASSPHRASE_SCALARS)), Ok(()));
        assert_eq!(PassphrasePolicyError::TooShort.code(), "too_short");
        assert_eq!(PassphrasePolicyError::TooCommon.code(), "too_common");
        assert_eq!(PassphrasePolicyError::TooShort.to_string(), "too_short");
        assert_eq!(PassphrasePolicyError::TooCommon.to_string(), "too_common");
    }
}
