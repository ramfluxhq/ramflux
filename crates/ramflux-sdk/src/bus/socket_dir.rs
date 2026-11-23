// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unix socket directory. Mode 0700, owner-only, and a live socket is left in place.

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use crate::SdkError;

fn path_unusable() -> SdkError {
    SdkError::LocalBus("the socket path is not usable".to_owned())
}

fn dir_unusable() -> SdkError {
    SdkError::LocalBus("the socket directory is not usable".to_owned())
}

fn in_use() -> SdkError {
    SdkError::LocalBus("the socket is in use".to_owned())
}

fn our_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn restrict(dir: &Path) -> Result<(), SdkError> {
    crate::platform::fs::set_owner_only_dir(dir).map_err(|_| dir_unusable())?;
    let meta = std::fs::symlink_metadata(dir).map_err(|_| dir_unusable())?;
    let owner_only = !meta.file_type().is_symlink()
        && meta.is_dir()
        && meta.uid() == our_uid()
        && meta.permissions().mode() & 0o777 == 0o700;
    if owner_only { Ok(()) } else { Err(dir_unusable()) }
}

fn create_dir(dir: &Path) -> Result<(), SdkError> {
    match crate::platform::fs::create_owner_only_dir(dir) {
        Ok(()) => restrict(dir),
        Err(_) => match std::fs::symlink_metadata(dir) {
            Ok(meta) => accept_dir(dir, &meta),
            Err(_) => Err(dir_unusable()),
        },
    }
}

fn accept_dir(dir: &Path, meta: &std::fs::Metadata) -> Result<(), SdkError> {
    if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() != our_uid() {
        return Err(dir_unusable());
    }
    restrict(dir)
}

fn prepare_dir(socket: &Path) -> Result<(), SdkError> {
    let Some(dir) = socket.parent() else {
        return Err(dir_unusable());
    };
    if dir.as_os_str().is_empty() || dir.parent().is_none() {
        return Err(dir_unusable());
    }
    match std::fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_dir(dir),
        Ok(meta) => accept_dir(dir, &meta),
        Err(_) => Err(dir_unusable()),
    }
}

fn remove_stale(path: &Path) -> Result<(), SdkError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| path_unusable())?;
    if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
        return Err(path_unusable());
    }
    std::fs::remove_file(path).map_err(|_| path_unusable())
}

async fn replace_if_stale(path: &Path) -> Result<(), SdkError> {
    let probe =
        tokio::time::timeout(Duration::from_millis(200), tokio::net::UnixStream::connect(path));
    match probe.await {
        Ok(Ok(_stream)) => Err(in_use()),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            remove_stale(path)
        }
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(Err(_)) | Err(_) => Err(path_unusable()),
    }
}

pub(super) async fn prepare(path: &Path) -> Result<(), SdkError> {
    prepare_dir(path)?;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(path_unusable()),
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
                return Err(path_unusable());
            }
            replace_if_stale(path).await
        }
    }
}
