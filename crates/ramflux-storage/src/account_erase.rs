// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account erase: exclusive lease, `removed` tombstone, then root payload removal.

use crate::{ACCOUNT_DB_FILE, AccountIndex, BACKUP_GENERATION_MARKER, StorageError};
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
    /// Tombstones an account under an exclusive writer lease, then removes its root payload
    /// (dormant; nothing calls it yet).
    ///
    /// The lease is taken before the tombstone, so a refused erase leaves the state and
    /// the wrapped key unchanged. The tombstone sets `removed` and clears the wrapped key.
    /// The root database, its `-wal`/`-shm`/`-journal` sidecars, the segment tree, `objects/`
    /// and the backup-generation marker are then removed; the `.writer.lock` inode is kept.
    /// `generation_*` trees are left for P03a-4c. Any symlink in the account directory is
    /// refused with `Integrity("account erase symlink")` before the first unlink, which
    /// happens after the tombstone, so a refused erase still leaves the account `removed`.
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
        remove_root_payload(&self.root().join("accounts").join(local_account_id))
    }
}

/// Every per-account root path this part owns (class inventory). `.writer.lock` is kept on
/// purpose, and `generation_*` trees belong to P03a-4c.
fn root_files() -> [String; 5] {
    [
        ACCOUNT_DB_FILE.to_owned(),
        format!("{ACCOUNT_DB_FILE}-wal"),
        format!("{ACCOUNT_DB_FILE}-shm"),
        format!("{ACCOUNT_DB_FILE}-journal"),
        BACKUP_GENERATION_MARKER.to_owned(),
    ]
}

fn root_trees() -> [String; 2] {
    // `AccountDb::segment_store` derives the segment root with `with_extension`.
    let segments = Path::new(ACCOUNT_DB_FILE).with_extension("segments");
    [segments.to_string_lossy().into_owned(), "objects".to_owned()]
}

fn ignore_not_found(result: std::io::Result<()>) -> Result<(), StorageError> {
    match result {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

/// Refuses any symlink before the first unlink, then removes the owned root payload.
fn remove_root_payload(dir: &Path) -> Result<(), StorageError> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
            return Err(StorageError::Integrity("account erase symlink"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    for entry in std::fs::read_dir(dir)? {
        if entry?.file_type()?.is_symlink() {
            return Err(StorageError::Integrity("account erase symlink"));
        }
    }
    for name in root_files() {
        ignore_not_found(std::fs::remove_file(dir.join(name)))?;
    }
    for name in root_trees() {
        ignore_not_found(std::fs::remove_dir_all(dir.join(name)))?;
    }
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}
