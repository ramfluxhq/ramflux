// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Android storage: the application passes its no-backup directory and everything the SDK
//! writes lives under it.
//!
//! The SDK never asks Android for a path and never guesses one. The host passes
//! `Context.getNoBackupFilesDir()`; a path on shared or external storage, on
//! device-protected storage, or outside the no-backup directory is refused before a single
//! file is created. The database, its WAL, the object spool and the wrapped vault entries
//! all live there, which keeps them out of Auto Backup and device-to-device transfer.

use std::path::{Component, Path, PathBuf};

use crate::SdkError;
use crate::custody::CustodyVaultReason;
use crate::platform::lifecycle::HostPaths;

/// Directory name Android gives `Context.getNoBackupFilesDir()` inside the app data dir.
const NO_BACKUP_DIR: &str = "no_backup";
const DATA_ROOT_DIR: &str = "ramflux";
const VAULT_DIR: &str = "ramflux-vault";
const SENTINEL_FILE: &str = "installed.v1";
const LOCK_PROBE_FILE: &str = "lock-probe";
const VAULT_ENTRY_SUFFIX: &str = "rfv";

/// Why a host-supplied directory was refused. Carries no path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageRefusal {
    /// Not absolute, or contains a parent or current-directory component.
    NotNormalized,
    /// On shared, external, removable or adopted storage.
    ExternalStorage,
    /// Device-protected storage, which is readable before the first unlock.
    DeviceProtectedStorage,
    /// Not inside the application's credential-protected private data directory.
    NotAppPrivate,
    /// Not the no-backup directory, so Auto Backup or a device transfer could copy it.
    NotNoBackupDir,
    /// The directory resolves through a symbolic link to somewhere else.
    Redirected,
    /// Advisory file locks are not effective on this filesystem.
    LockingUnavailable,
}

impl StorageRefusal {
    /// Stable, secret-free reason string for logs and the host UI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotNormalized => "android_storage_path_not_normalized",
            Self::ExternalStorage => "android_storage_external",
            Self::DeviceProtectedStorage => "android_storage_device_protected",
            Self::NotAppPrivate => "android_storage_not_app_private",
            Self::NotNoBackupDir => "android_storage_not_no_backup_dir",
            Self::Redirected => "android_storage_redirected",
            Self::LockingUnavailable => "android_storage_locking_unavailable",
        }
    }
}

impl From<StorageRefusal> for SdkError {
    fn from(refusal: StorageRefusal) -> Self {
        Self::LocalBus(format!("android storage refused: {}", refusal.as_str()))
    }
}

/// Classify a host-supplied path by its text alone.
///
/// Accepted shapes are `/data/user/<user>/<package>/no_backup` and
/// `/data/data/<package>/no_backup`, the two spellings Android uses for the
/// credential-protected private directory on internal storage.
///
/// # Errors
/// The first rule the path breaks.
pub fn classify_no_backup_dir(path: &Path) -> Result<(), StorageRefusal> {
    if !path.is_absolute() {
        return Err(StorageRefusal::NotNormalized);
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                parts.push(part.to_str().ok_or(StorageRefusal::NotNormalized)?);
            }
            Component::ParentDir | Component::CurDir | Component::Prefix(_) => {
                return Err(StorageRefusal::NotNormalized);
            }
        }
    }
    match parts.as_slice() {
        ["sdcard" | "storage" | "mnt", ..] | ["data", "media", ..] => {
            Err(StorageRefusal::ExternalStorage)
        }
        ["data", "user_de", ..] => Err(StorageRefusal::DeviceProtectedStorage),
        ["data", "user", user, package, rest @ ..] => {
            if user.is_empty() || !user.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(StorageRefusal::NotAppPrivate);
            }
            no_backup_tail(package, rest)
        }
        ["data", "data", package, rest @ ..] => no_backup_tail(package, rest),
        _ => Err(StorageRefusal::NotAppPrivate),
    }
}

fn no_backup_tail(package: &str, rest: &[&str]) -> Result<(), StorageRefusal> {
    if package.is_empty() || !package.contains('.') {
        return Err(StorageRefusal::NotAppPrivate);
    }
    if rest == [NO_BACKUP_DIR] { Ok(()) } else { Err(StorageRefusal::NotNoBackupDir) }
}

/// What the directories say about this installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallState {
    /// No sentinel and no vault entry: a first run.
    Fresh,
    /// The sentinel exists: this installation has run before.
    Established,
    /// Vault entries exist but the sentinel does not: the data root was lost or the vault
    /// entries arrived without it. Fresh state must not be minted under the old identity.
    DataLost,
}

/// The validated Android storage layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndroidStorage {
    no_backup_dir: PathBuf,
}

impl AndroidStorage {
    /// Validate the directory returned by `Context.getNoBackupFilesDir()`.
    ///
    /// # Errors
    /// A [`StorageRefusal`] as an `SdkError` when the path is not the application's
    /// credential-protected no-backup directory on internal storage, or resolves elsewhere.
    pub fn from_no_backup_files_dir(dir: &Path) -> Result<Self, SdkError> {
        classify_no_backup_dir(dir)?;
        // The directory exists once the platform returned it. Its resolved location must
        // pass the same rules, so a link cannot redirect the data root to shared storage.
        let resolved = std::fs::canonicalize(dir)?;
        classify_no_backup_dir(&resolved).map_err(|_| StorageRefusal::Redirected)?;
        Ok(Self { no_backup_dir: resolved })
    }

    /// A layout over a temporary directory, without the Android path rules.
    #[cfg(test)]
    pub(crate) fn for_tests(dir: &Path) -> Self {
        Self { no_backup_dir: dir.to_path_buf() }
    }

    /// The data root handed to the supervisor: account index, per-account databases with
    /// their WAL files, the object spool and `daemon.lock`.
    #[must_use]
    pub fn host_paths(&self) -> HostPaths {
        HostPaths { data_root: self.no_backup_dir.join(DATA_ROOT_DIR) }
    }

    /// Directory of Keystore-wrapped vault entries, beside the data root.
    #[must_use]
    pub fn vault_dir(&self) -> PathBuf {
        self.no_backup_dir.join(VAULT_DIR)
    }

    /// Create the data root and the vault directory owner-only and prove that advisory
    /// locks work there, which the data-root lock and the account writer lock rely on.
    ///
    /// # Errors
    /// I/O failures, a non-directory in place of either directory, or
    /// [`StorageRefusal::LockingUnavailable`].
    pub fn prepare(&self) -> Result<(), SdkError> {
        let data_root = self.host_paths().data_root;
        for dir in [&data_root, &self.vault_dir()] {
            match std::fs::symlink_metadata(dir) {
                Ok(metadata) if metadata.is_dir() => {
                    crate::platform::fs::set_owner_only_dir(dir)?;
                }
                Ok(_) => return Err(StorageRefusal::Redirected.into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    crate::platform::fs::create_owner_only_dir(dir)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if locks_are_effective(&data_root)? {
            Ok(())
        } else {
            Err(StorageRefusal::LockingUnavailable.into())
        }
    }

    /// Fresh install, established install, or lost data.
    ///
    /// # Errors
    /// I/O failures while inspecting the directories.
    pub fn install_state(&self) -> Result<InstallState, SdkError> {
        if self.host_paths().data_root.join(SENTINEL_FILE).try_exists()? {
            return Ok(InstallState::Established);
        }
        let entries = match std::fs::read_dir(self.vault_dir()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(InstallState::Fresh);
            }
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let path = entry?.path();
            if path.extension().is_some_and(|extension| extension == VAULT_ENTRY_SUFFIX) {
                return Ok(InstallState::DataLost);
            }
        }
        Ok(InstallState::Fresh)
    }

    /// Refuse to continue when vault entries exist without their data root.
    ///
    /// # Errors
    /// `CustodyVault(Missing)` for [`InstallState::DataLost`]. The host then offers exactly
    /// two actions: restore from a recovery export, or delete the orphan and link as a new
    /// device.
    pub fn require_not_orphaned(&self) -> Result<InstallState, SdkError> {
        match self.install_state()? {
            InstallState::DataLost => Err(SdkError::CustodyVault(CustodyVaultReason::Missing)),
            state => Ok(state),
        }
    }

    /// Record that this installation has run. Idempotent.
    ///
    /// # Errors
    /// I/O failures other than the sentinel already existing.
    pub fn mark_installed(&self) -> Result<(), SdkError> {
        let data_root = self.host_paths().data_root;
        match crate::platform::fs::create_new_owner_only_io(&data_root.join(SENTINEL_FILE)) {
            Ok(file) => {
                file.sync_all()?;
                std::fs::File::open(&data_root)?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Refuse a data root that is not the SDK's directory inside the no-backup directory.
///
/// The embedded supervisor calls this before it opens anything, so a host that skipped
/// [`AndroidStorage`] still cannot place the database on shared storage or in a directory
/// that Auto Backup copies.
///
/// # Errors
/// A [`StorageRefusal`] as an `SdkError`.
pub fn require_private_data_root(data_root: &Path) -> Result<(), SdkError> {
    if data_root.file_name().is_none_or(|name| name != DATA_ROOT_DIR) {
        return Err(StorageRefusal::NotNoBackupDir.into());
    }
    let parent = data_root.parent().ok_or(StorageRefusal::NotNormalized)?;
    classify_no_backup_dir(parent)?;
    // The platform created the no-backup directory; it must not resolve somewhere else.
    let resolved_parent = std::fs::canonicalize(parent)?;
    classify_no_backup_dir(&resolved_parent).map_err(|_| StorageRefusal::Redirected)?;
    // The data root itself may not exist yet, but it may never be a link or a file.
    match std::fs::symlink_metadata(data_root) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(StorageRefusal::Redirected.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Take an exclusive lock through one descriptor and observe a second descriptor being
/// refused. Some emulated filesystems accept the call and enforce nothing.
fn locks_are_effective(dir: &Path) -> Result<bool, SdkError> {
    let path = dir.join(LOCK_PROBE_FILE);
    let first = crate::platform::fs::open_owner_only_read_write(&path)?;
    if crate::platform::fs::try_lock_exclusive(&first).is_err() {
        return Ok(false);
    }
    let second = crate::platform::fs::open_owner_only_read_write(&path)?;
    let refused = matches!(
        crate::platform::fs::try_lock_exclusive(&second),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    );
    crate::platform::fs::unlock(&first)?;
    Ok(refused)
}

/// Whether the data-root lock is free right now, observed with a fresh descriptor. Used
/// after a suspension: Android may freeze or kill the process at any later moment, and no
/// lock may be held when it does.
///
/// # Errors
/// I/O failures opening the lock file.
pub fn data_root_lock_is_released(data_root: &Path) -> Result<bool, SdkError> {
    let file = crate::platform::fs::open_owner_only_read_write(&data_root.join("daemon.lock"))?;
    match crate::platform::fs::try_lock_exclusive(&file) {
        Ok(()) => {
            crate::platform::fs::unlock(&file)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn accepts_only_the_private_no_backup_directory() {
        for accepted in [
            "/data/user/0/org.ramflux.app/no_backup",
            "/data/data/org.ramflux.app/no_backup",
            "/data/user/10/org.ramflux.app/no_backup",
        ] {
            assert_eq!(classify_no_backup_dir(Path::new(accepted)), Ok(()), "{accepted}");
        }
    }

    #[test]
    fn refuses_external_shared_and_adopted_storage() {
        for refused in [
            "/sdcard/Android/data/org.ramflux.app/files",
            "/storage/emulated/0/Android/data/org.ramflux.app/files",
            "/storage/1A2B-3C4D/Android/data/org.ramflux.app/files",
            "/mnt/expand/uuid/user/0/org.ramflux.app/no_backup",
            "/data/media/0/Android/data/org.ramflux.app/files",
        ] {
            assert_eq!(
                classify_no_backup_dir(Path::new(refused)),
                Err(StorageRefusal::ExternalStorage),
                "{refused}"
            );
        }
    }

    #[test]
    fn refuses_backed_up_and_device_protected_directories() {
        let cases = [
            ("/data/user/0/org.ramflux.app/files", StorageRefusal::NotNoBackupDir),
            ("/data/user/0/org.ramflux.app/databases", StorageRefusal::NotNoBackupDir),
            ("/data/user/0/org.ramflux.app", StorageRefusal::NotNoBackupDir),
            ("/data/user/0/org.ramflux.app/no_backup/nested", StorageRefusal::NotNoBackupDir),
            ("/data/user_de/0/org.ramflux.app/no_backup", StorageRefusal::DeviceProtectedStorage),
            ("/data/user/x/org.ramflux.app/no_backup", StorageRefusal::NotAppPrivate),
            ("/data/local/tmp/no_backup", StorageRefusal::NotAppPrivate),
            ("/tmp/no_backup", StorageRefusal::NotAppPrivate),
            ("data/user/0/org.ramflux.app/no_backup", StorageRefusal::NotNormalized),
            ("/data/user/0/org.ramflux.app/files/../no_backup", StorageRefusal::NotNormalized),
        ];
        for (path, refusal) in cases {
            assert_eq!(classify_no_backup_dir(Path::new(path)), Err(refusal), "{path}");
        }
    }

    #[test]
    fn data_root_outside_the_no_backup_directory_is_refused() -> TestResult {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("ramflux");
        std::fs::create_dir(&root)?;
        assert!(require_private_data_root(&root).is_err());
        assert!(
            require_private_data_root(Path::new("/data/user/0/org.ramflux.app/files/ramflux"))
                .is_err()
        );
        assert!(require_private_data_root(Path::new("/storage/emulated/0/ramflux")).is_err());
        assert!(
            require_private_data_root(Path::new("/data/user/0/org.ramflux.app/no_backup/other"))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn host_supplied_temporary_directory_is_refused_by_the_public_constructor() -> TestResult {
        let dir = tempfile::tempdir()?;
        assert!(AndroidStorage::from_no_backup_files_dir(dir.path()).is_err());
        Ok(())
    }

    #[test]
    fn prepare_creates_owner_only_directories_under_the_no_backup_dir() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir()?;
        let storage = AndroidStorage::for_tests(dir.path());
        storage.prepare()?;
        storage.prepare()?;
        for created in [storage.host_paths().data_root, storage.vault_dir()] {
            assert!(created.starts_with(dir.path()));
            assert_eq!(std::fs::metadata(&created)?.permissions().mode() & 0o777, 0o700);
        }
        Ok(())
    }

    #[test]
    fn data_root_lock_probe_sees_a_held_and_a_released_lock() -> TestResult {
        let dir = tempfile::tempdir()?;
        let storage = AndroidStorage::for_tests(dir.path());
        storage.prepare()?;
        let data_root = storage.host_paths().data_root;
        // The same file and the same exclusive lock the data-root owner takes.
        let held = crate::platform::fs::open_owner_only_read_write(&data_root.join("daemon.lock"))?;
        crate::platform::fs::try_lock_exclusive(&held)?;
        assert!(!data_root_lock_is_released(&data_root)?);
        drop(held);
        assert!(data_root_lock_is_released(&data_root)?);
        Ok(())
    }

    #[test]
    fn vault_entry_without_sentinel_is_data_lost_and_fails_closed() -> TestResult {
        let dir = tempfile::tempdir()?;
        let storage = AndroidStorage::for_tests(dir.path());
        assert_eq!(storage.install_state()?, InstallState::Fresh);
        storage.prepare()?;
        assert_eq!(storage.require_not_orphaned()?, InstallState::Fresh);
        std::fs::write(storage.vault_dir().join("entry.rfv"), b"wrapped")?;
        assert_eq!(storage.install_state()?, InstallState::DataLost);
        assert!(matches!(
            storage.require_not_orphaned(),
            Err(SdkError::CustodyVault(CustodyVaultReason::Missing))
        ));
        storage.mark_installed()?;
        storage.mark_installed()?;
        assert_eq!(storage.require_not_orphaned()?, InstallState::Established);
        Ok(())
    }
}
