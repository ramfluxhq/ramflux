// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner-only files, the exclusive data-root lock, and the per-user data root on Windows.
//!
//! A Unix mode of 0o600 or 0o700 becomes a security descriptor whose protected access list
//! holds only the current user. Directories pass that entry on to what is created inside them.
//! An elevated token may leave BUILTIN\Administrators as the owner; that owner is accepted only
//! when the token is elevated and its `TokenOwner` is Administrators. The access list is
//! hygiene against other standard users and sandboxed processes; administrators and SYSTEM can
//! always reach a user's files.

#[cfg(test)]
use std::cell::Cell;
use std::fs::File;
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_WRITE_DATA, OPEN_ALWAYS,
};

#[cfg(test)]
thread_local! {
    static DIRECTORY_FLUSHES: Cell<u32> = const { Cell::new(0) };
}

use crate::SdkError;
use crate::platform::pipe::win32::files::{self, KnownFolder};

pub(crate) type LocalSocketStream = crate::platform::pipe::listener::PipeClientStream;

/// Directory name of the product under the local application-data folder.
const PRODUCT_DIRECTORY: &str = "ramflux";
/// Profile used when the caller names none.
pub(crate) const DEFAULT_PROFILE: &str = "default";

pub(crate) fn set_owner_only_dir(path: &Path) -> Result<(), SdkError> {
    Ok(files::restrict(path, true)?)
}

pub(crate) fn set_owner_only_file(path: &Path) -> Result<(), SdkError> {
    Ok(files::restrict(path, false)?)
}

pub(crate) fn create_new_owner_only(path: &Path) -> Result<File, SdkError> {
    Ok(create_new_owner_only_io(path)?)
}

pub(crate) fn create_new_owner_only_io(path: &Path) -> io::Result<File> {
    files::open_owner_only(path, GENERIC_WRITE, CREATE_NEW, 0)
}

pub(crate) fn open_owner_only_truncate(path: &Path) -> Result<File, SdkError> {
    Ok(files::open_owner_only_truncate(path)?)
}

pub(crate) fn create_owner_only_dir(path: &Path) -> Result<(), SdkError> {
    Ok(files::create_dir_owner_only(path)?)
}

pub(crate) fn open_owner_only_read_write(path: &Path) -> Result<File, SdkError> {
    Ok(files::open_owner_only(path, GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS, 0)?)
}

/// A held lock reports `WouldBlock`, as on Unix. Windows reports it as a lock violation.
fn contended(error: io::Error) -> io::Error {
    let violation = i32::try_from(ERROR_LOCK_VIOLATION).ok();
    if error.raw_os_error() == violation && violation.is_some() {
        io::ErrorKind::WouldBlock.into()
    } else {
        error
    }
}

/// Windows byte-range locks are mandatory: while the lock is held, no other handle can read or
/// write the file. Lock files therefore hold no data another process needs.
pub(crate) fn try_lock_exclusive(file: &File) -> Result<(), io::Error> {
    fs2::FileExt::try_lock_exclusive(file).map_err(contended)
}

pub(crate) fn lock_exclusive(file: &File) -> Result<(), io::Error> {
    fs2::FileExt::lock_exclusive(file)
}

pub(crate) fn unlock(file: &File) -> Result<(), io::Error> {
    fs2::FileExt::unlock(file)
}

pub(crate) fn open_owner_only_append(path: &Path) -> Result<File, SdkError> {
    Ok(files::open_owner_only(path, FILE_GENERIC_WRITE & !FILE_WRITE_DATA, OPEN_ALWAYS, 0)?)
}

/// Read/write create without truncate, owner-only, refusing a final reparse point (symbolic
/// link, junction or mount point).
///
/// # Errors
/// Returns an error when the file cannot be opened or the final component is a reparse point.
pub(crate) fn open_owner_only_no_follow(path: &Path) -> io::Result<File> {
    let file = files::open_owner_only(
        path,
        GENERIC_READ | GENERIC_WRITE,
        OPEN_ALWAYS,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "final component is a link"));
    }
    Ok(file)
}

/// Volume serial number and file index, the Windows counterpart of device and inode.
pub(crate) fn file_device_inode(file: &File) -> io::Result<(u64, u64)> {
    files::identity(file)
}

/// The metadata the standard library returns for a path carries no file index on Windows, so
/// the identity is read from the path itself, without following a final reparse point.
#[must_use]
pub(crate) fn same_metadata_identity(
    _metadata: &std::fs::Metadata,
    path: &Path,
    device: u64,
    inode: u64,
) -> bool {
    matches!(files::path_identity(path), Ok(Some(found)) if found == (device, inode))
}

// Kept for parity with the Unix seam; only the Unix socket listener calls it today.
#[allow(dead_code)]
pub(crate) fn same_device_inode(path: &Path, device: u64, inode: u64) -> Result<bool, SdkError> {
    Ok(files::path_identity(path)? == Some((device, inode)))
}

/// Move `from` over `to` in one step and return when the move is on disk. This is the Windows
/// counterpart of `rename` followed by a directory sync.
///
/// # Errors
/// Returns the OS error.
// The SDK renames through the standard library, which also replaces in one step. This call
// adds the wait for the disk and is the one to use for new Windows-only call sites.
#[allow(dead_code)]
pub(crate) fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    files::move_file(from, to, true)
}

/// Move `from` to `to` only if `to` does not exist.
///
/// # Errors
/// `AlreadyExists` when `to` exists; otherwise the OS error.
pub(crate) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    files::move_file(from, to, false)
}

/// Flush a file, or a directory after a name in it changed.
///
/// A directory is opened with `FILE_FLAG_BACKUP_SEMANTICS` and `GENERIC_WRITE`, then
/// `FlushFileBuffers` runs through `File::sync_all`. NTFS journaling alone is not this
/// barrier: `FlushFileBuffers` on the directory handle is what pushes the namespace update.
/// A crash that cuts power before this call returns can still lose the rename. This host
/// cannot prove that with a VM reset; a failed flush is an error, not success.
///
/// # Errors
/// Returns the OS error when the path is missing or cannot be opened or flushed.
pub(crate) fn sync_path(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();
    if std::fs::metadata(path)?.is_dir() {
        flush_directory(path)?;
        #[cfg(test)]
        DIRECTORY_FLUSHES.with(|count| count.set(count.get().saturating_add(1)));
        return Ok(());
    }
    std::fs::OpenOptions::new().write(true).open(path)?.sync_all()
}

fn flush_directory(path: &Path) -> io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()
}

/// How many directory flushes this thread has completed. Tests use the delta to tell a real
/// flush from a successful no-op.
#[cfg(test)]
pub(crate) fn directory_flushes() -> u32 {
    DIRECTORY_FLUSHES.with(Cell::get)
}

fn is_inside(path: &Path, ancestor: &Path) -> bool {
    let lower = |value: &Path| value.to_string_lossy().replace('/', "\\").to_lowercase();
    let path = lower(path);
    let ancestor = lower(ancestor);
    let ancestor = ancestor.trim_end_matches('\\');
    path == ancestor || path.strip_prefix(ancestor).is_some_and(|rest| rest.starts_with('\\'))
}

/// Refuse a data root under the roaming application-data folder. A roaming profile can copy
/// device state to another machine without establishing a new device identity. This is a
/// product policy, not a protection against a domain administrator.
///
/// # Errors
/// `LocalBusPermissionDenied` for a roaming path; an I/O error when the folder is unknown.
pub(crate) fn refuse_roaming(root: &Path) -> Result<(), SdkError> {
    let roaming = files::known_folder(KnownFolder::RoamingAppData)?;
    let absolute = std::path::absolute(root)?;
    if is_inside(&absolute, &roaming) {
        return Err(SdkError::LocalBusPermissionDenied);
    }
    Ok(())
}

fn valid_profile(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= 64
        && profile.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// `%LOCALAPPDATA%\ramflux\<profile>`, from the Known Folder API and not from the environment,
/// which another process can set.
///
/// # Errors
/// Returns an error for an invalid profile name or when the shell reports no folder.
pub(crate) fn default_data_root(profile: &str) -> Result<PathBuf, SdkError> {
    if !valid_profile(profile) {
        return Err(SdkError::Io(io::Error::new(io::ErrorKind::InvalidInput, "profile name")));
    }
    let local = files::known_folder(KnownFolder::LocalAppData)?;
    Ok(local.join(PRODUCT_DIRECTORY).join(profile))
}

/// Create the data root and every missing ancestor as owner-only directories, then verify
/// that the root belongs to the current user, is not a reparse point, and is not roaming.
///
/// # Errors
/// `LocalBusPermissionDenied` when the root or an ancestor is a junction or other reparse
/// point, the resolved path is roaming, or the directory belongs to another user.
pub(crate) fn ensure_data_root(root: &Path) -> Result<(), SdkError> {
    refuse_roaming(root)?;
    let absolute = std::path::absolute(root)?;
    match files::prepare_owner_only_directory(&absolute) {
        Ok(resolved) => refuse_roaming(&resolved),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            Err(SdkError::LocalBusPermissionDenied)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
#[path = "fs_windows/tests.rs"]
pub(crate) mod tests;
