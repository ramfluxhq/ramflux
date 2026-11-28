// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-group host key files (from 6ed, LARGE-GROUP-01 2.4.2): directory 0700 with a
//! group/other-writable check, file created with `create_new` and mode 0600, staged publish,
//! directory `sync_all`. The 64 key bytes (POPRF root seed, head-signing seed) are never written to
//! the node database.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ramflux_crypto::large_group::{LgTokenRootKey, random_array};
use zeroize::Zeroizing;

use super::refusal::{LgRefusal, LgResult};

const KEY_FILE_BYTES: usize = 64;
/// Most directory entries one prepared-key cleanup looks at.
const CLEANUP_SCAN_MAX: usize = 4_096;

fn io(error: impl std::fmt::Display) -> LgRefusal {
    tracing::warn!(%error, "group host key file error");
    LgRefusal::KeyFile
}

/// The two secrets of one group host: POPRF root seed and head-signing seed.
pub struct HostKeys {
    bytes: Zeroizing<[u8; KEY_FILE_BYTES]>,
}

impl HostKeys {
    /// Fresh random keys.
    ///
    /// # Errors
    /// [`LgRefusal::Internal`] when the OS has no randomness.
    pub fn generate() -> LgResult<Self> {
        let seed = Zeroizing::new(random_array::<KEY_FILE_BYTES>()?);
        Ok(Self { bytes: seed })
    }

    fn from_file_bytes(bytes: &[u8]) -> LgResult<Self> {
        let array: [u8; KEY_FILE_BYTES] = bytes.try_into().map_err(|_| LgRefusal::KeyFile)?;
        Ok(Self { bytes: Zeroizing::new(array) })
    }

    fn half(&self, upper: bool) -> LgResult<[u8; 32]> {
        let (low, high) = self.bytes.split_at(32);
        let part = if upper { high } else { low };
        part.try_into().map_err(|_| LgRefusal::KeyFile)
    }

    /// Seed of the POPRF token root key.
    ///
    /// # Errors
    /// [`LgRefusal::KeyFile`] on a broken invariant.
    pub fn token_root_seed(&self) -> LgResult<[u8; 32]> {
        self.half(false)
    }

    /// Seed of the per-group head-signing key.
    ///
    /// # Errors
    /// [`LgRefusal::KeyFile`] on a broken invariant.
    pub fn head_signing_seed(&self) -> LgResult<[u8; 32]> {
        self.half(true)
    }

    /// The POPRF root key and its public key.
    ///
    /// # Errors
    /// [`LgRefusal::Internal`] when the POPRF key cannot be derived.
    pub fn token_root(&self) -> LgResult<LgTokenRootKey> {
        Ok(LgTokenRootKey::from_seed(&self.token_root_seed()?)?)
    }

    /// Public key of the head-signing seed.
    ///
    /// # Errors
    /// [`LgRefusal::KeyFile`] on a broken invariant.
    pub fn head_public(&self) -> LgResult<[u8; 32]> {
        Ok(ed25519_dalek::SigningKey::from_bytes(&self.head_signing_seed()?)
            .verifying_key()
            .to_bytes())
    }
}

/// Creates the private key directory (mode 0700) and checks it is not group/other writable.
pub(super) fn open_dir(path: &Path) -> LgResult<PathBuf> {
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
        return Err(LgRefusal::KeyFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(LgRefusal::KeyFile);
        }
    }
    Ok(path.to_path_buf())
}

fn name_for(prefix: &str, id: &[u8]) -> String {
    format!("{prefix}-{}.key", ramflux_protocol::encode_base64url(id))
}

/// File name of a group's keys.
pub(super) fn group_name(gid: &[u8; 32]) -> String {
    name_for("lg", gid)
}

/// File name of keys prepared for a group that is not created yet.
pub(super) fn prep_name(prep_id: &[u8; 16]) -> String {
    name_for("lg-prep", prep_id)
}

fn sync_dir(dir: &Path) -> LgResult<()> {
    #[cfg(unix)]
    fs::File::open(dir).and_then(|handle| handle.sync_all()).map_err(io)?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Writes `keys` under `name` through a staged file and a hard link; never replaces a file.
pub(super) fn publish(dir: &Path, name: &str, keys: &HostKeys) -> LgResult<()> {
    let suffix = random_array::<8>()?;
    let stage = dir.join(format!("{name}.{}.tmp", ramflux_protocol::encode_base64url(suffix)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&stage).map_err(io)?;
    let written = file.write_all(keys.bytes.as_slice()).and_then(|()| file.sync_all());
    let linked = written.and_then(|()| fs::hard_link(&stage, dir.join(name)));
    let _ = fs::remove_file(&stage);
    linked.map_err(io)?;
    sync_dir(dir)
}

/// Moves a prepared key file to its final group name.
pub(super) fn promote(dir: &Path, prep: &str, group: &str) -> LgResult<()> {
    let from = dir.join(prep);
    match fs::hard_link(&from, dir.join(group)) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            return Err(LgRefusal::GroupExists);
        }
        Err(error) => return Err(io(error)),
    }
    fs::remove_file(&from).map_err(io)?;
    sync_dir(dir)
}

/// Loads one key file, refusing links, a wrong size and any mode other than 0600.
pub(super) fn load(dir: &Path, name: &str) -> LgResult<HostKeys> {
    let path = dir.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(io)?;
    if !metadata.file_type().is_file() {
        return Err(LgRefusal::KeyFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(LgRefusal::KeyFile);
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let limit = u64::try_from(KEY_FILE_BYTES).unwrap_or(64).saturating_add(1);
    fs::File::open(&path).map_err(io)?.take(limit).read_to_end(&mut bytes).map_err(io)?;
    HostKeys::from_file_bytes(&bytes)
}

/// Deletes prepared key files older than `max_age` (a create that never came). Local housekeeping
/// on file times; it never decides anything about a request.
pub(super) fn remove_stale_prepared(dir: &Path, max_age: Duration) -> LgResult<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(dir).map_err(io)?.take(CLEANUP_SCAN_MAX) {
        let entry = entry.map_err(io)?;
        if !entry.file_name().to_string_lossy().starts_with("lg-prep-") {
            continue;
        }
        let age = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok());
        if age.is_some_and(|age| age > max_age) && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}
