// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publish one complete private source-pseudonym key per configured node identity.
use crate::{NodeCoreError, NodeSecret};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

const STALE_STAGE_AGE: Duration = Duration::from_hours(1);

fn invalid(directory: &Path) -> NodeCoreError {
    NodeCoreError::Unauthorized(format!(
        "node privacy key directory {} cannot be initialized; mount a writable volume there \
         or set RAMFLUX_NODE_PRIVACY_KEY_FILE to an existing private key file",
        directory.display()
    ))
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
    builder.create(&directory).map_err(|_| invalid(&directory))?;
    let metadata = fs::symlink_metadata(&directory).map_err(|_| invalid(&directory))?;
    if !metadata.file_type().is_dir() {
        return Err(invalid(&directory));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(invalid(&directory));
        }
    }
    let identity = ramflux_crypto::blake3_256_base64url(
        "ramflux.source_ip_key.identity.v1",
        node_id.as_bytes(),
    );
    let path = directory.join(format!("source-ip-{identity}.key"));
    clean_staged_keys(&directory, &format!("source-ip-{identity}."))?;
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => publish(&path)?,
        Err(_) => return Err(invalid(&directory)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::symlink_metadata(&path).map_err(|_| invalid(&directory))?.permissions().mode()
            & 0o777
            != 0o600
        {
            return Err(invalid(&directory));
        }
    }
    let key = NodeSecret::from_file(&path).map_err(|_| invalid(&directory))?;
    // A concurrent creator may have linked the complete file just before this read.
    // Every opener makes that directory entry durable before using the key.
    #[cfg(unix)]
    fs::File::open(&directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| invalid(&directory))?;
    Ok(key)
}

fn clean_staged_keys(directory: &Path, prefix: &str) -> Result<(), NodeCoreError> {
    for entry in fs::read_dir(directory).map_err(|_| invalid(directory))? {
        let entry = entry.map_err(|_| invalid(directory))?;
        let name = entry.file_name();
        let suffix = name
            .to_str()
            .and_then(|name| name.strip_prefix(prefix))
            .and_then(|name| name.strip_suffix(".tmp"));
        if !suffix.is_some_and(|suffix| {
            ramflux_protocol::decode_base64url(suffix).is_ok_and(|bytes| bytes.len() == 32)
        }) {
            continue;
        }
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return Err(invalid(directory)),
        };
        // Keep fresh staging files so concurrent publishers can finish. Never follow links.
        if metadata.file_type().is_file()
            && metadata
                .modified()
                .ok()
                .and_then(|time| time.elapsed().ok())
                .is_some_and(|age| age >= STALE_STAGE_AGE)
        {
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(_) => return Err(invalid(directory)),
            }
        }
    }
    Ok(())
}

struct StagedKey(PathBuf);
impl Drop for StagedKey {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn publish(path: &Path) -> Result<(), NodeCoreError> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let secret = NodeSecret::ephemeral().map_err(|_| invalid(directory))?;
    let suffix = ramflux_crypto::random_32().map_err(|_| invalid(directory))?;
    let stage_path =
        path.with_extension(format!("{}.tmp", ramflux_protocol::encode_base64url(suffix)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&stage_path).map_err(|_| invalid(directory))?;
    let stage = StagedKey(stage_path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|_| invalid(directory))?;
    }
    let encoded =
        secret.with_bytes(|bytes| Zeroizing::new(ramflux_protocol::encode_base64url(bytes)));
    file.write_all(encoded.as_bytes()).map_err(|_| invalid(directory))?;
    file.sync_all().map_err(|_| invalid(directory))?;
    // Never replace a competing creator's key or expose a partially written final file.
    match fs::hard_link(&stage.0, path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(invalid(directory)),
    }
}
