// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process ownership of account writers, independent of database generations.

use crate::StorageError;
use fs2::FileExt;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};

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
    // Drop explicitly unlocks before close; process exit also releases ownership.
    // Never unlink this inode or use file age to break ownership.
    file: Option<File>,
    path: PathBuf,
}

type Owners = BTreeMap<PathBuf, Weak<AccountWriter>>;
struct OwnerRegistry {
    owners: Mutex<Owners>,
    teardown_complete: Condvar,
}

static OWNERS: OnceLock<OwnerRegistry> = OnceLock::new();

fn owners() -> &'static OwnerRegistry {
    OWNERS.get_or_init(|| OwnerRegistry {
        owners: Mutex::new(BTreeMap::new()),
        teardown_complete: Condvar::new(),
    })
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

#[derive(Debug, thiserror::Error)]
#[error("account writer lock failed at {}: {source}", path.display())]
struct WriterLockIo {
    path: PathBuf,
    #[source]
    source: std::io::Error,
}

fn lock_io(path: &Path, source: std::io::Error) -> StorageError {
    StorageError::Io(std::io::Error::new(
        source.kind(),
        WriterLockIo { path: path.to_path_buf(), source },
    ))
}

impl AccountWriter {
    pub(crate) fn acquire(root: &Path, account: &str) -> Result<Arc<Self>, StorageError> {
        let directory = root.join("accounts").join(account).canonicalize()?;
        let path = directory.join(".writer.lock");
        let registry = owners();
        let mut registered =
            registry.owners.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(owner) = registered.get(&path) {
            if let Some(owner) = owner.upgrade() {
                return Ok(owner);
            }
            // The final Arc is already running Drop and will remove the entry
            // only after closing its descriptor under this mutex.
            registered = registry
                .teardown_complete
                .wait(registered)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|source| lock_io(&path, source))?;
        match file.try_lock_exclusive() {
            Ok(()) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
            {
                return Err(StorageError::AccountWriterBusy(account.to_owned()));
            }
            Err(error) => {
                return Err(lock_io(&path, error));
            }
        }
        let owner = Arc::new(Self { file: Some(file), path: path.clone() });
        registered.insert(path, Arc::downgrade(&owner));
        Ok(owner)
    }
}

impl Drop for AccountWriter {
    fn drop(&mut self) {
        let registry = owners();
        let mut registered =
            registry.owners.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
        // Unlock and close the descriptor before releasing the registry mutex. An acquire
        // can therefore observe either the live shared owner or a released
        // kernel lock, never the stale interval between those two states.
        if let Some(file) = self.file.take() {
            let _ = FileExt::unlock(&file);
            drop(file);
        }
        registered.remove(&self.path);
        registry.teardown_complete.notify_all();
    }
}

#[cfg(test)]
pub(crate) fn poison_registry() {
    let _ = std::panic::catch_unwind(|| {
        let _registered = owners().owners.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        std::panic::resume_unwind(Box::new("injected account writer registry poison"));
    });
}
