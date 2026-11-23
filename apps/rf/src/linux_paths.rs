// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Linux XDG defaults. An empty or relative base is a refusal, never a `/tmp` path.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::RfError;

fn message(text: &'static str) -> RfError {
    RfError::Message(text.into())
}

fn absolute_env(key: &str) -> Result<Option<PathBuf>, RfError> {
    match std::env::var_os(key) {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                Ok(Some(path))
            } else {
                Err(message("an XDG path is not absolute"))
            }
        }
    }
}

fn home_dir() -> Result<PathBuf, RfError> {
    absolute_env("HOME")?.ok_or_else(|| message("HOME is unset, empty, or not absolute"))
}

fn base(key: &str, fallback: impl FnOnce(PathBuf) -> PathBuf) -> Result<PathBuf, RfError> {
    match absolute_env(key)? {
        Some(path) => Ok(path),
        None => Ok(fallback(home_dir()?)),
    }
}

pub(crate) fn default_socket() -> PathBuf {
    absolute_env("XDG_RUNTIME_DIR")
        .ok()
        .flatten()
        .map(|dir| dir.join("ramflux").join("rfd.sock"))
        .unwrap_or_default()
}

pub(crate) fn resolve_socket(explicit: Option<PathBuf>) -> Result<PathBuf, RfError> {
    let socket = explicit.unwrap_or_else(default_socket);
    require_resolved(&socket, "provide --socket or set an absolute XDG_RUNTIME_DIR").map_err(
        |error| RfError::Refused { code: "socket_path_required", message: error.to_string() },
    )?;
    Ok(socket)
}

pub(crate) fn default_data_root() -> PathBuf {
    base("XDG_DATA_HOME", |home| home.join(".local").join("share"))
        .map(|dir| dir.join("ramflux"))
        .unwrap_or_default()
}

pub(crate) fn state_dir() -> Result<PathBuf, RfError> {
    base("XDG_STATE_HOME", |home| home.join(".local").join("state")).map(|dir| dir.join("ramflux"))
}

pub(crate) fn require_resolved(path: &Path, text: &'static str) -> Result<(), RfError> {
    if path.as_os_str().is_empty() { Err(message(text)) } else { Ok(()) }
}

fn our_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub(crate) fn ensure_state_dir(path: &Path) -> Result<(), RfError> {
    if !path.is_absolute() {
        return Err(message("the state directory is not usable"));
    }
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .map_err(|_| message("the state directory is not usable"))?;
        }
        Ok(meta) if !meta.file_type().is_symlink() && meta.is_dir() => {}
        _ => return Err(message("the state directory is not usable")),
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| message("the state directory is not usable"))?;
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| message("the state directory is not usable"))?;
    let ready = !meta.file_type().is_symlink()
        && meta.is_dir()
        && meta.uid() == our_uid()
        && meta.permissions().mode() & 0o777 == 0o700;
    if ready { Ok(()) } else { Err(message("the state directory is not usable")) }
}
