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

/// A directory flush opens the directory with `FILE_FLAG_BACKUP_SEMANTICS` and write access,
/// then `FlushFileBuffers` runs through `File::sync_all`. Journaling alone does not push a
/// rename. A file is opened for write and flushed the same way.
///
/// # Errors
/// Returns the OS error when the path is missing or cannot be opened or flushed.
#[cfg(windows)]
pub(crate) fn sync_path(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();
    if std::fs::metadata(path)?.is_dir() {
        return flush_directory(path);
    }
    std::fs::OpenOptions::new().write(true).open(path)?.sync_all()
}

/// `FILE_FLAG_BACKUP_SEMANTICS`. Required before `FlushFileBuffers` accepts a directory handle.
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

#[cfg(windows)]
fn flush_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()
}

/// Targets that are neither Unix nor Windows keep the previous file-only flush. A directory
/// has no portable handle there.
///
/// # Errors
/// Returns the OS error when the path is missing or a file cannot be opened or flushed.
#[cfg(not(any(unix, windows)))]
pub(crate) fn sync_path(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();
    if std::fs::metadata(path)?.is_dir() {
        return Ok(());
    }
    std::fs::OpenOptions::new().write(true).open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::sync_path;

    #[test]
    fn a_renamed_file_stays_visible_after_the_directory_flush() {
        let root = std::env::temp_dir().join(format!(
            "rf-sync-path-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        std::fs::create_dir_all(&root).expect("test: create directory");
        let temporary = root.join("authority.json.tmp");
        let published = root.join("authority.json");
        std::fs::write(&temporary, b"authority").expect("test: write temp");
        sync_path(&temporary).expect("test: flush temp");
        std::fs::rename(&temporary, &published).expect("test: rename");
        sync_path(&root).expect("test: flush publication directory");
        assert_eq!(std::fs::read(&published).expect("test: read publication"), b"authority");
        let _ = std::fs::remove_dir_all(&root);
    }
}
