// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Admission for the account code when it is set or changed: exactly six ASCII digits, and not
//! one of a small closed list of trivial codes: all six digits equal (000000 ... 999999) and the
//! straight runs 012345, 123456, 234567, 345678, 456789, 987654, 876543, 765432, 654321, 543210.
//! The list removes the cheapest first guesses; it is deliberately tiny.
//!
//! The code is never the only barrier against guessing that cannot be limited: both account DB
//! key wraps also need the device secret held by the platform vault, and code checks are
//! rate-limited by the SDK. Unlocking an existing account does not use this module.

use super::PassphrasePolicyError;
use crate::SdkError;

/// Number of decimal digits in an account code.
pub const ACCOUNT_CODE_DIGITS: usize = 6;

/// Admit `code` as a new account code.
///
/// # Errors
/// Returns [`PassphrasePolicyError::NotSixDigits`] unless `code` is exactly six ASCII digits,
/// and [`PassphrasePolicyError::TrivialCode`] for a code on the trivial list.
pub fn check_new_passphrase(code: &str) -> Result<(), PassphrasePolicyError> {
    if code.len() != ACCOUNT_CODE_DIGITS || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PassphrasePolicyError::NotSixDigits);
    }
    if is_trivial(code.as_bytes()) {
        return Err(PassphrasePolicyError::TrivialCode);
    }
    Ok(())
}

/// All digits equal, or each digit one more (or one less) than the previous one.
fn is_trivial(digits: &[u8]) -> bool {
    let steps: Vec<i16> = digits
        .iter()
        .zip(digits.iter().skip(1))
        .map(|(previous, next)| i16::from(*next) - i16::from(*previous))
        .collect();
    [0_i16, 1, -1].iter().any(|step| steps.iter().all(|value| value == step))
}

/// Admit UTF-8 account code bytes for a set or change.
///
/// # Errors
/// Returns [`SdkError::CustodySetupInvalid`] for non-UTF-8 bytes, or
/// [`PassphrasePolicyError::NotSixDigits`].
pub(crate) fn admit_new_passphrase(bytes: &[u8]) -> Result<(), SdkError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    Ok(check_new_passphrase(text)?)
}
