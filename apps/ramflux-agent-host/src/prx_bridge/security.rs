// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Recheck the operator-owned same-user socket before every connection.
use crate::{Error, Result};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};

/// Missing sockets are retryable; existing insecure paths fail closed.
pub(super) fn validate(path: &Path) -> Result<bool> {
    let uid = rustix::process::geteuid().as_raw();
    let parent = path.parent().ok_or(Error::Config)?;
    match std::fs::symlink_metadata(parent) {
        Ok(meta) if meta.is_dir() && meta.uid() == uid && meta.mode() & 0o7777 == 0o700 => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Ok(_) | Err(_) => return Err(Error::Config),
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta)
            if meta.file_type().is_socket()
                && meta.uid() == uid
                && meta.mode() & 0o7777 == 0o600 =>
        {
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Ok(_) | Err(_) => Err(Error::Config),
    }
}
