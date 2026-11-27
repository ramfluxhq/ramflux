// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-group host key files (design 2.4.2): directory 0700 with a group/other-writable check, file
//! created with `create_new` and mode 0600, staged publish, directory `sync_all`. The 64 key bytes
//! are never written to the node database.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use ramflux_crypto::large_group::{LgGroupKey, random_array};

use super::store::Refuse;

fn io(error: impl std::fmt::Display) -> Refuse {
    tracing::warn!(%error, "large-group key file error");
    "key_file"
}

/// Creates the private key directory (mode 0700) and checks it is not group/other writable.
pub(super) fn open_dir(path: &Path) -> Result<PathBuf, Refuse> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(io)?;
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    if !metadata.file_type().is_dir() {
        return Err("key_file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err("key_file");
        }
    }
    Ok(path.to_path_buf())
}

fn name_for(prefix: &str, id: &[u8]) -> String {
    format!("{prefix}-{}.key", ramflux_protocol::encode_base64url(id))
}

pub(super) fn group_name(gid: &[u8; 32]) -> String {
    name_for("lg", gid)
}

pub(super) fn prep_name(prep_id: &[u8; 16]) -> String {
    name_for("lg-prep", prep_id)
}

fn sync_dir(dir: &Path) -> Result<(), Refuse> {
    #[cfg(unix)]
    fs::File::open(dir).and_then(|handle| handle.sync_all()).map_err(io)?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Writes `key` under `name` through a staged file and a hard link; never replaces a file.
pub(super) fn publish(dir: &Path, name: &str, key: &LgGroupKey) -> Result<(), Refuse> {
    let suffix = random_array::<8>().map_err(io)?;
    let stage = dir.join(format!("{name}.{}.tmp", ramflux_protocol::encode_base64url(suffix)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&stage).map_err(io)?;
    let written = file.write_all(key.file_bytes()).and_then(|()| file.sync_all());
    let linked = written.and_then(|()| fs::hard_link(&stage, dir.join(name)));
    let _ = fs::remove_file(&stage);
    linked.map_err(io)?;
    sync_dir(dir)
}

/// Moves a prepared key to its final group name.
pub(super) fn promote(dir: &Path, prep: &str, group: &str) -> Result<(), Refuse> {
    let from = dir.join(prep);
    match fs::hard_link(&from, dir.join(group)) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => return Err("group_exists"),
        Err(error) => return Err(io(error)),
    }
    fs::remove_file(&from).map_err(io)?;
    sync_dir(dir)
}

/// Loads one key file, refusing links, a wrong size and any mode other than 0600.
pub(super) fn load(dir: &Path, name: &str) -> Result<LgGroupKey, Refuse> {
    let path = dir.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(io)?;
    if !metadata.file_type().is_file() {
        return Err("key_file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err("key_file");
        }
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    fs::File::open(&path).map_err(io)?.take(65).read_to_end(&mut bytes).map_err(io)?;
    LgGroupKey::from_file_bytes(&bytes).map_err(io)
}
