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
    file: Option<File>,
    path: PathBuf,
}

type Owners = BTreeMap<PathBuf, Weak<AccountWriter>>;
static OWNERS: OnceLock<Mutex<Owners>> = OnceLock::new();

fn owners() -> &'static Mutex<Owners> {
    OWNERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
type DropHook = Arc<dyn Fn(&Path) + Send + Sync>;
#[cfg(test)]
static DROP_HOOK: OnceLock<Mutex<Option<DropHook>>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn set_drop_hook(hook: Option<DropHook>) -> Result<(), StorageError> {
    *DROP_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| std::io::Error::other("account writer drop hook poisoned"))? = hook;
    Ok(())
}

impl AccountWriter {
    pub(crate) fn acquire(root: &Path, account: &str) -> Result<Arc<Self>, StorageError> {
        let directory = root.join("accounts").join(account).canonicalize()?;
        let path = directory.join(".writer.lock");
        let mut owners = owners()
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
        let file = options
            .open(&path)
            .map_err(|source| StorageError::AccountWriterLock { path: path.clone(), source })?;
        if let Err(error) = file.try_lock_exclusive() {
            if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
                return Err(StorageError::AccountWriterBusy(account.to_owned()));
            }
            return Err(StorageError::AccountWriterLock { path, source: error });
        }
        let owner = Arc::new(Self { file: Some(file), path: path.clone() });
        owners.insert(path, Arc::downgrade(&owner));
        Ok(owner)
    }
}

impl Drop for AccountWriter {
    fn drop(&mut self) {
        let Ok(mut owners) = owners().lock() else {
            drop(self.file.take());
            return;
        };
        owners.remove(&self.path);
        #[cfg(test)]
        {
            let hook = DROP_HOOK
                .get_or_init(|| Mutex::new(None))
                .lock()
                .ok()
                .and_then(|hook| hook.clone());
            if let Some(hook) = hook {
                hook(&self.path);
            }
        }
        // Close the descriptor before releasing the registry mutex. An acquire
        // can therefore observe either the live shared owner or a released
        // kernel lock, never the stale interval between those two states.
        drop(self.file.take());
    }
}
