// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-code check that authenticates one app-lock change. It shares the durable code attempt
//! limit with every other code check and never resets it through presence or restart.

use crate::SdkError;
use crate::client::device_unlock;
use ramflux_storage::{AccountIndex, unwrap_with_vault_secret};

/// Checks `code` against the stored code wrap of `account_id`. A wrong code counts as a failed
/// attempt; a correct one clears the failure count.
///
/// # Errors
/// Returns the attempt-limit refusals, `AccountDbNotUnlocked` without a code wrap, or an integrity
/// error for a wrong code.
pub(crate) fn verify_account_code(
    index: &AccountIndex,
    account_id: &str,
    vault_secret: &[u8; 32],
    code: &[u8],
) -> Result<(), SdkError> {
    device_unlock::guard_code_attempt(index, account_id)?;
    let wrapping = zeroize::Zeroizing::new(crate::client::account::account_db_key_encryption_key(
        vault_secret,
        code,
    )?);
    let wrapped = index.load_wrapped_db_key(account_id)?.ok_or(SdkError::AccountDbNotUnlocked)?;
    let _key = unwrap_with_vault_secret(&wrapping, &wrapped)?;
    device_unlock::code_attempt_succeeded(index, account_id)
}
