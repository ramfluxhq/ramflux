// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process ownership of account writers, independent of database generations.

use crate::StorageError;
use fs2::FileExt;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

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
struct OwnerRegistry {
    owners: Mutex<Owners>,
    teardown_complete: Condvar,
}

static OWNERS: OnceLock<OwnerRegistry> = OnceLock::new();
const INHERITED_DESCRIPTOR_GRACE: Duration = Duration::from_millis(250);

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

impl AccountWriter {
    pub(crate) fn acquire(root: &Path, account: &str) -> Result<Arc<Self>, StorageError> {
        let directory = root.join("accounts").join(account).canonicalize()?;
        let path = directory.join(".writer.lock");
        let registry = owners();
        let mut registered = registry
            .owners
            .lock()
            .map_err(|_| std::io::Error::other("account writer registry poisoned"))?;
        while let Some(owner) = registered.get(&path) {
            if let Some(owner) = owner.upgrade() {
                return Ok(owner);
            }
            // The final Arc is already running Drop and will remove the entry
            // only after closing its descriptor under this mutex.
            registered = registry
                .teardown_complete
                .wait(registered)
                .map_err(|_| std::io::Error::other("account writer registry poisoned"))?;
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
        let deadline = Instant::now() + INHERITED_DESCRIPTOR_GRACE;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => break,
                Err(error)
                    if error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
                        && Instant::now() < deadline =>
                {
                    // A concurrently spawned child can briefly inherit the old
                    // descriptor before close-on-exec runs. That is teardown,
                    // not a distinct account owner.
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error)
                    if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
                {
                    return Err(StorageError::AccountWriterBusy(account.to_owned()));
                }
                Err(error) => {
                    return Err(StorageError::AccountWriterLock { path, source: error });
                }
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
        let Ok(mut registered) = registry.owners.lock() else {
            drop(self.file.take());
            return;
        };
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
        registered.remove(&self.path);
        registry.teardown_complete.notify_all();
    }
}
