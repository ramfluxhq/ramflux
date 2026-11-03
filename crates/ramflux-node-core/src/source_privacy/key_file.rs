// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publish one complete private source-pseudonym key per configured node identity.
use crate::{NodeCoreError, NodeSecret};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn invalid() -> NodeCoreError {
    NodeCoreError::Unauthorized("node privacy key file cannot be initialized".into())
}

pub(super) fn load_or_create(
    config_path: &Path,
    node_id: &str,
) -> Result<NodeSecret, NodeCoreError> {
    let parent = config_path.parent().filter(|p| !p.as_os_str().is_empty());
    let directory = parent.unwrap_or_else(|| Path::new(".")).join("node-identity");
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory).map_err(|_| invalid())?;
    let metadata = fs::symlink_metadata(&directory).map_err(|_| invalid())?;
    if !metadata.file_type().is_dir() {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(invalid());
        }
    }
    let identity = ramflux_crypto::blake3_256_base64url(
        "ramflux.source_ip_key.identity.v1",
        node_id.as_bytes(),
    );
    let path = directory.join(format!("source-ip-{identity}.key"));
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => publish(&path)?,
        Err(_) => return Err(invalid()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::symlink_metadata(&path).map_err(|_| invalid())?.permissions().mode() & 0o777 != 0o600
        {
            return Err(invalid());
        }
    }
    let key = NodeSecret::from_file(&path)?;
    // A concurrent creator may have linked the complete file just before this read.
    // Every opener makes that directory entry durable before using the key.
    #[cfg(unix)]
    fs::File::open(&directory).and_then(|directory| directory.sync_all()).map_err(|_| invalid())?;
    Ok(key)
}

struct StagedKey(PathBuf);
impl Drop for StagedKey {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn publish(path: &Path) -> Result<(), NodeCoreError> {
    let secret = NodeSecret::ephemeral()?;
    let suffix = ramflux_crypto::random_32().map_err(|_| invalid())?;
    let stage_path =
        path.with_extension(format!("{}.tmp", ramflux_protocol::encode_base64url(suffix)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&stage_path).map_err(|_| invalid())?;
    let stage = StagedKey(stage_path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|_| invalid())?;
    }
    let encoded =
        secret.with_bytes(|bytes| Zeroizing::new(ramflux_protocol::encode_base64url(bytes)));
    file.write_all(encoded.as_bytes()).map_err(|_| invalid())?;
    file.sync_all().map_err(|_| invalid())?;
    // Never replace a competing creator's key or expose a partially written final file.
    match fs::hard_link(&stage.0, path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(invalid()),
    }
}
