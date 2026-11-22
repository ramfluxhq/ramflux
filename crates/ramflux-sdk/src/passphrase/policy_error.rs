// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Why a new account code or archive passphrase was refused.

use super::archive::MIN_PASSPHRASE_SCALARS;
use super::code::ACCOUNT_CODE_DIGITS;

/// Why a new secret was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PassphrasePolicyError {
    /// The account code is not exactly [`ACCOUNT_CODE_DIGITS`] ASCII digits.
    #[error("not_six_digits")]
    NotSixDigits,
    /// The account code is on the closed trivial list (all digits equal, or a straight run).
    #[error("trivial_code")]
    TrivialCode,
    /// Archive passphrase: fewer than [`MIN_PASSPHRASE_SCALARS`] Unicode scalar values after NFC.
    #[error("too_short")]
    TooShort {
        /// NFC scalar count of the refused passphrase.
        scalars: usize,
    },
    /// Archive passphrase: the NFC, case-folded text is on the common-password blocklist.
    #[error("too_common")]
    TooCommon,
}

impl PassphrasePolicyError {
    /// Stable wire name for this rule.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotSixDigits => "not_six_digits",
            Self::TrivialCode => "trivial_code",
            Self::TooShort { .. } => "too_short",
            Self::TooCommon => "too_common",
        }
    }

    /// Sentence shown by `rf` for this rule. The wire [`Self::code`] stays unchanged.
    #[must_use]
    pub fn user_message(self) -> String {
        match self {
            Self::NotSixDigits => {
                format!("The account code must be exactly {ACCOUNT_CODE_DIGITS} digits (0-9).")
            }
            Self::TrivialCode => {
                "This code is too easy to guess (repeated digits or a straight run). Choose another."
                    .to_owned()
            }
            Self::TooShort { scalars } => {
                let missing = MIN_PASSPHRASE_SCALARS.saturating_sub(scalars);
                format!(
                    "{missing} more characters needed. The archive passphrase must be at least {MIN_PASSPHRASE_SCALARS} characters."
                )
            }
            Self::TooCommon => "This passphrase is too common or has appeared in a data breach. Choose a different one.".to_owned(),
        }
    }
}
