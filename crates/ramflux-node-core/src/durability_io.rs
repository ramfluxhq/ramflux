// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Physical startup durability boundaries shared by the WAL and redb store.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

pub(crate) fn boundary<T>(
    path: &Path,
    operation: &str,
    work: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let fatal_guard = crate::fatal_durability::WriteGuard::new(operation.starts_with("tombstone"))
        .map_err(io::Error::other)?;
    #[cfg(any(test, feature = "durability-test-hooks"))]
    crate::durability_test_hooks::notify(path, operation, false)?;
    crate::fatal_durability::check().map_err(io::Error::other)?;
    #[cfg(not(any(test, feature = "durability-test-hooks")))]
    let _ = (path, operation);
    let result = work()?;
    #[cfg(any(test, feature = "durability-test-hooks"))]
    crate::durability_test_hooks::notify(path, operation, true)?;
    fatal_guard.complete().map_err(io::Error::other)?;
    Ok(result)
}

pub(crate) fn sync_file(file: &File, path: &Path) -> io::Result<()> {
    boundary(path, "sync_all", || file.sync_all())
}

pub(crate) fn sync_dir(path: &Path) -> io::Result<()> {
    boundary(path, "directory_sync", || open_dir(path)?.sync_all())
}

#[cfg(windows)]
fn open_dir(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_BACKUP_SEMANTICS is required before a directory handle can be flushed.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new().write(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(path)
}

#[cfg(not(windows))]
fn open_dir(path: &Path) -> io::Result<File> {
    File::open(path)
}

pub(crate) fn set_len(file: &File, path: &Path, len: u64) -> io::Result<()> {
    boundary(path, "set_len", || file.set_len(len))
}

pub(crate) fn write_header(file: &mut File, path: &Path, bytes: &[u8]) -> io::Result<()> {
    boundary(path, "header_write", || file.write_all(bytes))
}

pub(crate) fn create_dir_all(path: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut ancestor = path;
    while !ancestor.as_os_str().is_empty() && !ancestor.exists() {
        missing.push(ancestor.to_path_buf());
        ancestor = ancestor.parent().unwrap_or(Path::new(""));
    }
    for directory in missing.iter().rev() {
        boundary(directory, "mkdir", || fs::create_dir(directory))?;
        if let Some(parent) = directory.parent().filter(|p| !p.as_os_str().is_empty()) {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

pub(crate) fn immediate_commit(
    db: &redb::Database,
    path: &Path,
) -> Result<(), crate::NodeCoreError> {
    crate::fatal_durability::run(|| {
        boundary(path, "immediate_commit", || {
            let mut txn =
                boundary(path, "begin_write", || db.begin_write().map_err(io::Error::other))?;
            txn.set_durability(redb::Durability::Immediate).map_err(io::Error::other)?;
            txn.commit().map_err(io::Error::other)
        })
        .map_err(|error| crate::NodeCoreError::Redb(error.to_string()))
    })
}
