// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process ownership of account writers, independent of database generations.

use crate::StorageError;
use fs2::FileExt;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// Retains this process's account writer ownership until the guard is dropped.
///
/// Used by quiesced restore and generation cleanup before opening or replacing
/// account database files. Ownership is process-local and never serialized.
#[must_use]
pub struct AccountWriterLease {
    _owner: Arc<AccountWriter>,
}

impl crate::AccountIndex {
    /// Acquires local writer ownership for a live account or a prepared restore.
    ///
    /// Creates the account directory if needed. Same-process writer connections
    /// share ownership; another process is refused without waiting.
    /// # Errors
    /// Returns `AccountWriterBusy`, filesystem errors or an invalid account ID.
    pub fn acquire_account_writer(
        &self,
        account: &str,
    ) -> Result<AccountWriterLease, StorageError> {
        let id = Path::new(account);
        if id.components().count() != 1
            || id.components().any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(StorageError::AuthorizationRejected);
        }
        std::fs::create_dir_all(self.root().join("accounts").join(account))?;
        Ok(AccountWriterLease { _owner: AccountWriter::acquire(self.root(), account)? })
    }
}

pub(crate) struct AccountWriter {
    // The kernel releases the lease only when the last descriptor closes or the
    // process exits. Never unlink this inode or use file age to break ownership.
    _file: File,
}

type Owners = BTreeMap<PathBuf, Weak<AccountWriter>>;

impl AccountWriter {
    pub(crate) fn acquire(root: &Path, account: &str) -> Result<Arc<Self>, StorageError> {
        static OWNERS: OnceLock<Mutex<Owners>> = OnceLock::new();
        let directory = root.join("accounts").join(account).canonicalize()?;
        let path = directory.join(".writer.lock");
        let mut owners = OWNERS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| std::io::Error::other("account writer registry poisoned"))?;
        owners.retain(|_, owner| owner.strong_count() != 0);
        if let Some(owner) = owners.get(&path).and_then(Weak::upgrade) {
            return Ok(owner);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        if let Err(error) = file.try_lock_exclusive() {
            if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
                return Err(StorageError::AccountWriterBusy(account.to_owned()));
            }
            return Err(error.into());
        }
        let owner = Arc::new(Self { _file: file });
        owners.insert(path, Arc::downgrade(&owner));
        Ok(owner)
    }
}
