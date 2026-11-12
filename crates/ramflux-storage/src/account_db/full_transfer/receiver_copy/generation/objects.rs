// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current fixed-owner subset has no local payload T owner. Never omit a live sidecar.
use crate::StorageError;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(super) fn require_supported(db: &rusqlite::Connection) -> Result<(), StorageError> {
    // The metadata owners must extend this together with payload transfer, validation
    // and all-writer draining. An empty directory cannot replace referenced payloads.
    let payload:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM object_index) OR EXISTS(SELECT 1 FROM object_segment_file) OR EXISTS(SELECT 1 FROM object_segment_resource)",[],|row|row.get(0))?;
    if payload {
        return Err(StorageError::PairingField("UnsupportedRecord"));
    }
    let active: bool =
        db.query_row("SELECT EXISTS(SELECT 1 FROM object_transfer_state)", [], |row| row.get(0))?;
    if active {
        return Err(StorageError::PairingField("Busy"));
    }
    Ok(())
}
fn paths(database: &Path) -> Result<[PathBuf; 2], StorageError> {
    Ok([
        database.parent().ok_or(StorageError::AuthorizationRejected)?.join("objects"),
        database.with_extension("segments"),
    ])
}
pub(super) fn prepare(database: &Path) -> Result<(), StorageError> {
    for path in paths(database)? {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            fs::DirBuilder::new().mode(0o700).create(&path)?;
        }
        #[cfg(not(unix))]
        return Err(StorageError::AuthorizationRejected);
        fs::File::open(&path)?.sync_all()?;
    }
    fs::File::open(database.parent().ok_or(StorageError::AuthorizationRejected)?)?.sync_all()?;
    Ok(())
}
pub(super) fn verify(database: &Path) -> Result<(), StorageError> {
    for path in paths(database)? {
        let meta = fs::symlink_metadata(&path)?;
        if !meta.is_dir() || meta.file_type().is_symlink() || fs::read_dir(&path)?.next().is_some()
        {
            return Err(StorageError::PairingField("ManifestMismatch"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(StorageError::AuthorizationRejected);
            }
        }
    }
    Ok(())
}
