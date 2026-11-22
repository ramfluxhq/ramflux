// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit an export tail on the open account.
//! Design r2 M1 (lines 65–70; audit r1 M1): the tail uses the same fenced private
//! copy as the base, and only as the read cut. The open account is not a backup
//! destination. The row patch is one immediate transaction on that connection.
//! The account stays WAL because its readers hold the log, so the file is not
//! renamed and a crash before commit leaves it unchanged.

use super::export_local;
use crate::{AccountDbKey, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::PREPUBLICATION_DELTA_STOP_BYTES;
use std::path::{Path, PathBuf};

const COPY_SLACK_BYTES: u64 = 8 * 1024 * 1024;
const SCRATCH_NAME: &str = "export-tail-after.db";

pub(super) struct StagedCopy {
    after: rusqlite::Connection,
    after_remove: RemoveFile,
}

struct RemoveFile(PathBuf);
impl Drop for RemoveFile {
    fn drop(&mut self) {
        remove_db(&self.0);
    }
}

/// Refuse an account whose page bytes exceed 64 MiB plus 8 MiB, then copy it once.
/// # Errors
/// `NoSpace` over the page cap; `Busy` when backup does not finish; I/O and SQL errors.
pub(super) fn stage_copy(
    live: &rusqlite::Connection,
    directory: &Path,
    key: &AccountDbKey,
) -> Result<StagedCopy, StorageError> {
    require_page_budget(live)?;
    let after_path = create_scratch(directory, SCRATCH_NAME)?;
    let after_remove = RemoveFile(after_path.clone());
    let mut after = export_local::open_keyed(&after_path, key)?;
    copy_db(live, &mut after)?;
    Ok(StagedCopy { after, after_remove })
}

impl StagedCopy {
    pub(super) fn after(&self) -> &rusqlite::Connection {
        &self.after
    }

    /// Commit `apply` on the open account, then discard the scratch.
    /// A failure before commit leaves `live_path` unchanged.
    /// # Errors
    /// The apply error, or the error from starting or committing the transaction.
    pub(super) fn commit_and_replace(
        self,
        live: &mut rusqlite::Connection,
        live_path: &Path,
        apply: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let StagedCopy { after, after_remove } = self;
        drop(after);
        let committed = commit_live(live, live_path, apply);
        drop(after_remove);
        committed
    }
}

fn commit_live(
    live: &mut rusqlite::Connection,
    live_path: &Path,
    apply: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let tx = live.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    apply(&tx)?;
    tx.commit()?;
    super::stage::sync_regular(live_path)?;
    Ok(())
}

/// Remove a crash leftover of the tail scratch. Known names only.
pub(super) fn sweep_scratches(directory: &Path) {
    remove_db(&directory.join(SCRATCH_NAME));
    remove_db(&directory.join("export-tail-before.db"));
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
