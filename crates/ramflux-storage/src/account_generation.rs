// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Physical generation lifetimes survive writer close, including independent readers.
use crate::{AccountIndex, StorageError};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

const LOCK: &str = ".generation-readers.lock";
fn lock_file(database: &Path) -> std::io::Result<File> {
    let parent = database.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let path = parent.join(LOCK);
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let before = std::fs::symlink_metadata(&path)?;
            if !before.is_file() || before.file_type().is_symlink() {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            options.create_new(false).create(false);
            let file = options.open(&path)?;
            let after = std::fs::symlink_metadata(&path)?;
            if !after.is_file() || after.file_type().is_symlink() {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
                let opened = file.metadata()?;
                if before.dev() != opened.dev()
                    || before.ino() != opened.ino()
                    || after.dev() != opened.dev()
                    || after.ino() != opened.ino()
                    || opened.nlink() != 1
                    || opened.permissions().mode() & 0o077 != 0
                {
                    return Err(std::io::ErrorKind::InvalidInput.into());
                }
            }
            file
        }
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    Ok(file)
}

pub(crate) struct GenerationReadLease(File);
impl GenerationReadLease {
    pub(crate) fn acquire(database: &Path) -> std::io::Result<Self> {
        let file = lock_file(database)?;
        fs2::FileExt::try_lock_shared(&file)?;
        Ok(Self(file))
    }
}
impl Drop for GenerationReadLease {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}
/// Exclusive physical generation lifetime guard. Retain through deletion and directory fsync.
/// This grants no authority to select paths, roll back publication or reclaim a selected DB.
#[must_use]
pub struct GenerationReclamationLease(File);
impl Drop for GenerationReclamationLease {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}
impl AccountIndex {
    /// Exclude every writer, pinned snapshot and independent reader of an OLD generation.
    /// The caller must separately prove it is unselected, fully installed and reclaimable.
    /// An in-use generation returns None immediately; never wait on a reader or delete it.
    /// # Errors
    /// Refuses unsafe/symlink paths and returns lock/open errors. No inode is unlinked here.
    pub fn try_acquire_generation_reclamation(
        &self,
        relative: &str,
    ) -> Result<Option<GenerationReclamationLease>, StorageError> {
        let path = Path::new(relative);
        if path.components().any(|part| !matches!(part, std::path::Component::Normal(_)))
            || !matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some(crate::ACCOUNT_DB_FILE | "account.db")
            )
        {
            return Err(StorageError::AuthorizationRejected);
        }
        let parent = path.parent().ok_or(StorageError::AuthorizationRejected)?;
        let mut current = self.root().to_path_buf();
        for part in parent.components() {
            current.push(part);
            let metadata = std::fs::symlink_metadata(&current)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(StorageError::AuthorizationRejected);
            }
        }
        let file = lock_file(&self.root().join(path))?;
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Some(GenerationReclamationLease(file))),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pairing_full_reclamation_waits_for_writer_snapshot_and_independent_reader()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, db) = crate::tests::test_db("full-generation-reader-drain")?;
        let index = crate::AccountIndex::open(&root)?;
        let path = index.account("acct")?.db_relative_path;
        let reader = db.open_reader()?;
        let pinned = db.open_reader()?;
        let connection = pinned.connection.clone();
        assert!(index.try_acquire_generation_reclamation(&path)?.is_none());
        drop(db);
        drop(pinned);
        assert!(
            index.try_acquire_generation_reclamation(&path)?.is_none(),
            "reader did not retain physical generation"
        );
        drop(reader);
        assert!(
            index.try_acquire_generation_reclamation(&path)?.is_none(),
            "cloned snapshot worker did not retain generation"
        );
        drop(connection);
        let exclusive =
            index.try_acquire_generation_reclamation(&path)?.ok_or("drained generation lock")?;
        let key = crate::AccountDbKey::derive("acct", b"storage-test-secret");
        assert!(
            crate::AccountDb::open(&index, "acct", &key).is_err(),
            "reader entered a generation during reclamation"
        );
        drop(exclusive);
        let reopened = crate::AccountDb::open(&index, "acct", &key)?;
        drop(reopened);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(test)]
mod layout_tests {
    #[test]
    fn pairing_full_generation_reader_guard_covers_legacy_and_installer_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, db) = crate::tests::test_db("full-generation-lock-layouts")?;
        let index = crate::AccountIndex::open(&root)?;
        let legacy = index.account("acct")?.db_relative_path;
        assert!(index.try_acquire_generation_reclamation(&legacy)?.is_none());
        let relative = "accounts/acct/generation_next/account.db";
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().ok_or("generation directory")?)?;
        std::fs::write(&path, b"ciphertext placeholder: physical lifetime fixture only")?;
        let reader = super::GenerationReadLease::acquire(&path)?;
        assert!(index.try_acquire_generation_reclamation(relative)?.is_none());
        drop(reader);
        assert!(
            index.try_acquire_generation_reclamation(relative)?.is_some(),
            "installer account.db layout was rejected"
        );
        assert!(index.try_acquire_generation_reclamation("accounts/acct/private.key").is_err());
        assert!(
            index.try_acquire_generation_reclamation("accounts/acct/../acct/account.db").is_err()
        );
        drop(db);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
