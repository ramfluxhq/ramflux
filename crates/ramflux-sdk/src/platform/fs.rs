// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner-only files, the exclusive data-root lock, and local-bus peer identity.
//! Unix keeps the modes and the credential check the daemon already used.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::SdkError;

pub(crate) type LocalSocketStream = tokio::net::UnixStream;

pub(crate) fn set_owner_only_dir(path: &Path) -> Result<(), SdkError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(crate) fn set_owner_only_file(path: &Path) -> Result<(), SdkError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub(crate) fn create_new_owner_only(path: &Path) -> Result<File, SdkError> {
    Ok(OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?)
}

pub(crate) fn open_owner_only_read_write(path: &Path) -> Result<File, SdkError> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?)
}

pub(crate) fn try_lock_exclusive(file: &File) -> Result<(), std::io::Error> {
    fs2::FileExt::try_lock_exclusive(file)
}

pub(crate) fn file_owner_uid(path: &Path) -> Result<u32, SdkError> {
    Ok(std::fs::metadata(path)?.uid())
}

pub(crate) fn same_device_inode(path: &Path, device: u64, inode: u64) -> Result<bool, SdkError> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(metadata.dev() == device && metadata.ino() == inode),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn verify_peer_uid(
    stream: &LocalSocketStream,
    expected_uid: u32,
) -> Result<(), SdkError> {
    let peer = stream.peer_cred()?;
    if peer.uid() == expected_uid { Ok(()) } else { Err(SdkError::LocalBusPermissionDenied) }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    fn mode_bits(path: &Path) -> Result<u32, String> {
        Ok(std::fs::metadata(path).map_err(|err| err.to_string())?.permissions().mode() & 0o777)
    }

    #[test]
    fn owner_only_dir_and_file_modes() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let nested = dir.path().join("accounts");
        std::fs::create_dir(&nested).map_err(|err| err.to_string())?;
        set_owner_only_dir(&nested).map_err(|err| err.to_string())?;
        let dir_mode = mode_bits(&nested)?;
        if dir_mode != 0o700 {
            return Err(format!("dir mode {dir_mode:o}"));
        }
        let file = nested.join("manifest.json");
        let mut created = create_new_owner_only(&file).map_err(|err| err.to_string())?;
        std::io::Write::write_all(&mut created, b"{}").map_err(|err| err.to_string())?;
        drop(created);
        let file_mode = mode_bits(&file)?;
        if file_mode != 0o600 {
            return Err(format!("file mode {file_mode:o}"));
        }
        match create_new_owner_only(&file) {
            Err(SdkError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Ok(_) => Err("create_new replaced an existing file".to_owned()),
            Err(error) => Err(error.to_string()),
        }
    }

    #[test]
    fn second_exclusive_lock_is_would_block() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let path = dir.path().join("daemon.lock");
        let first = open_owner_only_read_write(&path).map_err(|err| err.to_string())?;
        try_lock_exclusive(&first).map_err(|err| err.to_string())?;
        let second = open_owner_only_read_write(&path).map_err(|err| err.to_string())?;
        match try_lock_exclusive(&second) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Ok(()) => Err("second exclusive lock was acquired".to_owned()),
            Err(error) => Err(error.to_string()),
        }
    }

    #[test]
    fn file_identity_ignores_a_replaced_inode() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let path = dir.path().join("daemon.sock");
        let _listener =
            std::os::unix::net::UnixListener::bind(&path).map_err(|err| err.to_string())?;
        let metadata = std::fs::metadata(&path).map_err(|err| err.to_string())?;
        let device = metadata.dev();
        let inode = metadata.ino();
        if !same_device_inode(&path, device, inode).map_err(|err| err.to_string())? {
            return Err("bound socket identity did not match".to_owned());
        }
        std::fs::remove_file(&path).map_err(|err| err.to_string())?;
        std::fs::write(&path, b"replaced").map_err(|err| err.to_string())?;
        if same_device_inode(&path, device, inode).map_err(|err| err.to_string())? {
            return Err("replaced path reused the socket inode".to_owned());
        }
        Ok(())
    }
}
