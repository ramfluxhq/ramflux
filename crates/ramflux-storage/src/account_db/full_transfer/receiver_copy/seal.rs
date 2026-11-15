// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private immutable-file evidence carried from physical verification to a short commit.
use crate::StorageError;
use std::path::Path;
#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct FileSeal {
    device: u64,
    inode: u64,
    bytes: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn wrong() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
impl FileSeal {
    #[cfg(unix)]
    pub(super) fn capture(path: &Path) -> Result<Self, StorageError> {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            #[cfg(test)]
            eprintln!(
                "test: invalid private-file metadata: mode={} links={}",
                metadata.mode(),
                metadata.nlink()
            );
            return Err(wrong());
        }
        for suffix in ["db-wal", "db-shm", "db-journal"] {
            match std::fs::symlink_metadata(path.with_extension(suffix)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    #[cfg(test)]
                    eprintln!("test: private-file attestation found sidecar {suffix}");
                    return Err(wrong());
                }
            }
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            mode: metadata.mode(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
    #[cfg(not(unix))]
    pub(super) fn capture(_path: &Path) -> Result<Self, StorageError> {
        Err(StorageError::AuthorizationRejected)
    }
    pub(super) fn require(&self, path: &Path) -> Result<(), StorageError> {
        let actual = Self::capture(path)?;
        if actual != *self {
            #[cfg(test)]
            eprintln!("test: immutable-file observation changed: {self:?} -> {actual:?}");
            return Err(wrong());
        }
        Ok(())
    }
}
pub(super) struct CopySeal {
    private: FileSeal,
    contributions: FileSeal,
}
impl CopySeal {
    pub(super) fn capture(directory: &Path) -> Result<Self, StorageError> {
        Ok(Self {
            private: FileSeal::capture(&directory.join("private.db"))?,
            contributions: FileSeal::capture(&directory.join("contributions.db"))?,
        })
    }
    pub(super) fn require(&self, directory: &Path) -> Result<(), StorageError> {
        self.private.require(&directory.join("private.db"))?;
        self.contributions.require(&directory.join("contributions.db"))
    }
}
