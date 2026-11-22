// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publish an export tail by renaming a finished scratch onto the account path.
//! Design r2 M1 (lines 65–70; audit r1 M1): the tail uses the same fenced private
//! copy as the base. The open account is not a backup destination. A crash before
//! the rename leaves that file unchanged. After the rename, the open connection
//! denies every statement until a new `AccountDb::open`.

use super::export_local;
use crate::{AccountDbKey, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::PREPUBLICATION_DELTA_STOP_BYTES;
use std::path::{Path, PathBuf};

const COPY_SLACK_BYTES: u64 = 8 * 1024 * 1024;
const SCRATCH_NAME: &str = "export-tail-after.db";

pub(super) struct StagedCopy {
    after: rusqlite::Connection,
    after_path: PathBuf,
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
    Ok(StagedCopy { after, after_path, after_remove })
}

impl StagedCopy {
    pub(super) fn after(&self) -> &rusqlite::Connection {
        &self.after
    }

    /// Commit `apply` on the scratch, fsync it, and rename it onto `live_path`.
    /// The open connection is then denied. A failure before the rename leaves `live_path`
    /// untouched and returns that error.
    /// # Errors
    /// The apply error, `Busy`, `WrongContext` when the scratch is on another device,
    /// or the error from denying the open connection.
    pub(super) fn commit_and_replace(
        self,
        live: &mut rusqlite::Connection,
        live_path: &Path,
        apply: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let StagedCopy { mut after, after_path, after_remove } = self;
        let applied = apply_on_scratch(&mut after, apply);
        drop(after);
        // The open account is WAL. Its sidecar makes the rename look like a foreign file.
        let published = applied.and_then(|()| {
            release_live_sidecar(live)?;
            publish(&after_path, live_path)
        });
        drop(after_remove);
        published?;
        refuse_reopen(live)
    }
}

fn apply_on_scratch(
    after: &mut rusqlite::Connection,
    apply: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let tx = after.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    apply(&tx)?;
    tx.commit()?;
    Ok(())
}

fn release_live_sidecar(live: &rusqlite::Connection) -> Result<(), StorageError> {
    let mode: String = live.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    if mode.eq_ignore_ascii_case("delete") {
        Ok(())
    } else {
        Err(StorageError::PairingField("Busy"))
    }
}

fn publish(scratch: &Path, live_path: &Path) -> Result<(), StorageError> {
    super::stage::sync_regular(scratch)?;
    require_no_sidecar(scratch)?;
    require_no_sidecar(live_path)?;
    let parent = live_path.parent().ok_or_else(|| StorageError::PairingField("WrongContext"))?;
    if let Err(error) = std::fs::rename(scratch, live_path) {
        if error.kind() == std::io::ErrorKind::CrossesDevices {
            return Err(StorageError::PairingField("WrongContext"));
        }
        return Err(error.into());
    }
    crate::sync_path::sync_path(parent)?;
    Ok(())
}

fn require_no_sidecar(path: &Path) -> Result<(), StorageError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        match std::fs::symlink_metadata(&sidecar) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(StorageError::PairingField("WrongContext")),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn refuse_reopen(live: &mut rusqlite::Connection) -> Result<(), StorageError> {
    live.authorizer(Some(|_: rusqlite::hooks::AuthContext<'_>| {
        rusqlite::hooks::Authorization::Deny
    }))?;
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
