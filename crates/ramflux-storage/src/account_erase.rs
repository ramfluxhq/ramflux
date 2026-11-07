// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account erase: exclusive lease, then a `removed` tombstone that open refuses.

use crate::{AccountIndex, StorageError};
use rusqlite::params;
use std::path::Path;

const REMOVED: &str = "removed";

/// Maps a tombstoned account to the same error as an unknown one.
pub(crate) fn refuse_removed(account: &crate::LocalAccountRecord) -> Result<(), StorageError> {
    if account.account_state == REMOVED {
        return Err(StorageError::AccountNotFound(account.local_account_id.clone()));
    }
    Ok(())
}

#[cfg(test)]
type OpenRaceHook = std::sync::Arc<dyn Fn(&str) + Send + Sync>;
#[cfg(test)]
static OPEN_RACE_HOOK: std::sync::Mutex<Option<OpenRaceHook>> = std::sync::Mutex::new(None);

/// Runs between the first state read and the writer lease in `AccountDb::open`.
#[cfg(test)]
pub(crate) fn open_race_hook(account: &str) {
    let hook = OPEN_RACE_HOOK.lock().ok().and_then(|hook| hook.clone());
    if let Some(hook) = hook {
        hook(account);
    }
}

#[cfg(test)]
pub(crate) fn set_open_race_hook(hook: Option<OpenRaceHook>) {
    *OPEN_RACE_HOOK.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
}

impl AccountIndex {
    /// Tombstones an account under an exclusive writer lease (dormant; no file removal yet).
    ///
    /// The lease is taken before the tombstone, so a refused erase leaves the state and
    /// the wrapped key unchanged. The tombstone sets `removed` and clears the wrapped key.
    /// The operation is idempotent.
    /// # Errors
    /// Returns `AuthorizationRejected` for an invalid id, `AccountNotFound` for an unknown
    /// one, `AccountWriterBusy` while any other holder owns the account, or storage errors.
    pub fn erase_account_database(&self, local_account_id: &str) -> Result<(), StorageError> {
        let id = Path::new(local_account_id);
        if id.components().count() != 1
            || id.components().any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(StorageError::AuthorizationRejected);
        }
        self.account(local_account_id)?;
        std::fs::create_dir_all(self.root().join("accounts").join(local_account_id))?;
        let _lease =
            crate::account_writer::AccountWriter::acquire_exclusive(self.root(), local_account_id)?;
        self.connection.execute(
            "UPDATE local_account
                SET account_state = ?2, wrapped_key = NULL, wrapped_key_nonce = NULL
              WHERE local_account_id = ?1",
            params![local_account_id, REMOVED],
        )?;
        Ok(())
    }
}
