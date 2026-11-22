// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Replace the open account by backing a scratch copy into it.
//! The scratch is a copy of B's current file. A failed replace restores that copy.
//! A crash during the replace can still leave a partial file: the destination is the
//! open account, not a new path.

use super::export_local;
use crate::{AccountDbKey, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::PREPUBLICATION_DELTA_STOP_BYTES;
use std::path::{Path, PathBuf};

const COPY_SLACK_BYTES: u64 = 8 * 1024 * 1024;

pub(super) struct StagedCopies {
    before: rusqlite::Connection,
    after: rusqlite::Connection,
    before_remove: RemoveFile,
    after_remove: RemoveFile,
}

struct RemoveFile(PathBuf);
impl Drop for RemoveFile {
    fn drop(&mut self) {
        remove_db(&self.0);
    }
}

/// Refuse an account whose page bytes exceed 64 MiB plus 8 MiB, then copy it twice.
/// `before` stays pristine. `after` is the copy the tail may change.
/// # Errors
/// `NoSpace` over the page cap; `Busy` when backup does not finish; I/O and SQL errors.
pub(super) fn stage_copies(
    live: &rusqlite::Connection,
    directory: &Path,
    key: &AccountDbKey,
) -> Result<StagedCopies, StorageError> {
    require_page_budget(live)?;
    let before_path = create_scratch(directory, "export-tail-before.db")?;
    let before_remove = RemoveFile(before_path.clone());
    let after_path = create_scratch(directory, "export-tail-after.db")?;
    let after_remove = RemoveFile(after_path.clone());
    let mut before = export_local::open_keyed(&before_path, key)?;
    copy_db(live, &mut before)?;
    let mut after = export_local::open_keyed(&after_path, key)?;
    copy_db(&before, &mut after)?;
    Ok(StagedCopies { before, after, before_remove, after_remove })
}

impl StagedCopies {
    pub(super) fn after(&self) -> &rusqlite::Connection {
        &self.after
    }

    /// Commit `apply` on the second copy, then back that copy up over the open account.
    /// On a failed replace, the pristine copy is written back and the original error is
    /// returned. A failed restore returns the restore error instead.
    /// # Errors
    /// The apply error, `Busy`, or the restore error when the restore itself fails.
    pub(super) fn commit_and_swap(
        self,
        live: &mut rusqlite::Connection,
        apply: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let StagedCopies { mut after, before, before_remove, after_remove } = self;
        let result = apply_and_replace(&mut after, &before, live, apply);
        drop(after);
        drop(before);
        drop(after_remove);
        drop(before_remove);
        result
    }
}

fn apply_and_replace(
    after: &mut rusqlite::Connection,
    before: &rusqlite::Connection,
    live: &mut rusqlite::Connection,
    apply: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    {
        let tx = after.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        apply(&tx)?;
        tx.commit()?;
    }
    if let Err(error) = copy_db(after, live) {
        copy_db(before, live)?;
        return Err(error);
    }
    Ok(())
}

fn require_page_budget(db: &rusqlite::Connection) -> Result<(), StorageError> {
    let bytes: u64 = db.query_row(
        "SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size()",
        [],
        |row| row.get(0),
    )?;
    let cap = PREPUBLICATION_DELTA_STOP_BYTES.saturating_add(COPY_SLACK_BYTES);
    if bytes > cap { Err(StorageError::PairingField("NoSpace")) } else { Ok(()) }
}

fn create_scratch(directory: &Path, name: &str) -> Result<PathBuf, StorageError> {
    let path = directory.join(name);
    remove_db(&path);
    super::stage::create_file(&path)?;
    Ok(path)
}

fn copy_db(
    source: &rusqlite::Connection,
    dest: &mut rusqlite::Connection,
) -> Result<(), StorageError> {
    let backup = rusqlite::backup::Backup::new(source, dest)?;
    loop {
        match backup.step(128)? {
            rusqlite::backup::StepResult::Done => return Ok(()),
            rusqlite::backup::StepResult::More => {}
            _ => return Err(StorageError::PairingField("Busy")),
        }
    }
}

fn remove_db(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-journal"));
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}
