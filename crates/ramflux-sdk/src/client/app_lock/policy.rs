// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commits one app-lock policy change. A presence wrap is staged by the platform before this
//! call; a refused commit hands it back for release so no orphan platform item remains.

use crate::SdkError;
use ramflux_storage::{AccountIndex, AppLockChange, AppLockPolicy, AppLockPresenceWrap};

/// Commits `change` only while `expected_generation` is still the stored generation.
///
/// On refusal the previous policy, silent wrap and presence wrap stay as they were, and a
/// presence wrap staged for this change is passed to `discard`.
///
/// # Errors
/// Returns the storage refusal (missing account, out-of-range timeout or wrap, generation changed,
/// or a failed commit).
pub(crate) fn commit_policy(
    index: &AccountIndex,
    account_id: &str,
    expected_generation: u64,
    change: AppLockChange,
    discard: impl FnOnce(&AppLockPresenceWrap),
) -> Result<AppLockPolicy, SdkError> {
    let staged = match &change {
        AppLockChange::Enable { presence: Some(wrap), .. } => Some(wrap.clone()),
        AppLockChange::Enable { presence: None, .. } | AppLockChange::Disable { .. } => None,
    };
    match index.commit_app_lock(account_id, expected_generation, change) {
        Ok(policy) => Ok(policy),
        Err(error) => {
            if let Some(wrap) = staged.as_ref() {
                discard(wrap);
            }
            Err(error.into())
        }
    }
}
