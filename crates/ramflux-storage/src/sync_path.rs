// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Flush a file, or a directory after an entry in it changed.

use std::io;
use std::path::Path;

/// Unix opens the path read-only and flushes it; that works for files and directories.
///
/// # Errors
/// Returns the OS error when the path cannot be opened or flushed.
#[cfg(unix)]
pub(crate) fn sync_path(path: impl AsRef<Path>) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

/// Windows cannot open a directory as a file, and a file must be open for writing before it
/// can be flushed. NTFS journals the metadata of a rename, so a directory has nothing to flush
/// through a handle.
///
/// # Errors
/// Returns the OS error when the path is missing or a file cannot be opened or flushed.
#[cfg(not(unix))]
pub(crate) fn sync_path(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();
    if std::fs::metadata(path)?.is_dir() {
        return Ok(());
    }
    std::fs::OpenOptions::new().write(true).open(path)?.sync_all()
}
