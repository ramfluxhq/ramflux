// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Admission for host-selected shared storage; entitlements remain host authority.
use super::super::{CAbiError, RamfluxErrorCode};
use std::path::{Path, PathBuf};

fn invalid() -> CAbiError {
    CAbiError::new(RamfluxErrorCode::InvalidArgument, "data_root must be an existing directory")
}

fn permission() -> CAbiError {
    CAbiError::new(RamfluxErrorCode::PermissionDenied, "data_root must be private to its owner")
}

fn io_error(error: &std::io::Error) -> CAbiError {
    if error.kind() == std::io::ErrorKind::PermissionDenied { permission() } else { invalid() }
}

pub(super) fn validate(value: &str) -> Result<PathBuf, CAbiError> {
    let root = Path::new(value);
    if !root.is_absolute() {
        return Err(invalid());
    }
    let root: PathBuf = root.components().collect();
    let metadata = std::fs::symlink_metadata(&root).map_err(|error| io_error(&error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid());
    }
    let canonical = std::fs::canonicalize(&root).map_err(|error| io_error(&error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&canonical).map_err(|error| io_error(&error))?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o777 != 0o700
        {
            return Err(permission());
        }
    }
    // Windows startup retains its existing owner/DACL and reparse-point checks.
    Ok(canonical)
}

pub(super) fn custody_error(error: &crate::SdkError) -> CAbiError {
    if matches!(error, crate::SdkError::CustodyVault(crate::custody::CustodyVaultReason::Locked)) {
        CAbiError::with_status(super::RamfluxV2Status::VaultLocked as i32, "vault locked")
    } else {
        super::super::map_sdk_error(error)
    }
}
