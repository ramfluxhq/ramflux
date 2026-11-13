// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded same-user operation registry; cleanup never searches outside registered paths.
use super::{File, InvitationOutput, Path, PathBuf, RfError, invalid};
use serde::{Deserialize, Serialize};
use std::{
    fs::DirBuilder,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
};
const LIMIT: usize = 128;
const MAX_ENTRY: u64 = 16 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl OwnedPath {
    fn new(path: &Path, file: &File) -> Result<Self, RfError> {
        let metadata = file.metadata()?;
        Ok(Self {
            path: std::fs::canonicalize(
                path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")),
            )?
            .join(path.file_name().ok_or_else(invalid)?),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    fn exists(&self) -> Result<bool, RfError> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata)
                if metadata.is_file()
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.permissions().mode() & 0o077 == 0
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode =>
            {
                Ok(true)
            }
            Ok(_) => Err(invalid()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    operation: String,
    invitation: OwnedPath,
    sidecar: OwnedPath,
}
pub(super) struct Registry {
    directory: PathBuf,
    _lock: File,
}
fn private_file(path: &Path) -> Result<File, RfError> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid());
    }
    Ok(file)
}
impl Registry {
    pub(super) fn open(socket: &Path) -> Result<Self, RfError> {
        let directory = socket
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .join(".rf-pairing-files");
        match DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = std::fs::symlink_metadata(&directory)?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        let fd = rustix::fs::open(
            directory.join("owner.lock"),
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(std::io::Error::from)?;
        let lock = File::from(fd);
        let metadata = lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        lock.lock()?;
        Ok(Self { directory, _lock: lock })
    }
    fn path(&self, operation: &str) -> Result<PathBuf, RfError> {
        let bytes = ramflux_protocol::decode_base64url(operation).map_err(|_| invalid())?;
        if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != operation {
            return Err(invalid());
        }
        Ok(self.directory.join(format!("{operation}.json")))
    }
    pub(super) fn register(
        &self,
        operation: &str,
        output: &InvitationOutput,
    ) -> Result<(), RfError> {
        let path = self.path(operation)?;
        if std::fs::read_dir(&self.directory)?.take(LIMIT + 2).count() > LIMIT {
            return Err(invalid());
        }
        let mut sidecar_path = output.path.as_os_str().to_os_string();
        sidecar_path.push(".op");
        let mut sidecar = InvitationOutput::create(PathBuf::from(sidecar_path))?;
        let mut entry = InvitationOutput::create(path)?;
        let value = Entry {
            operation: operation.into(),
            invitation: OwnedPath::new(&output.path, &output.file)?,
            sidecar: OwnedPath::new(&sidecar.path, &sidecar.file)?,
        };
        let bytes = serde_json::to_vec(&value)?;
        if u64::try_from(bytes.len()).map_err(|_| invalid())? > MAX_ENTRY {
            return Err(invalid());
        }
        sidecar.commit(operation.as_bytes())?;
        if let Err(error) = entry.commit(&bytes) {
            // The still-owned sidecar is retired by the same identity checks as cleanup.
            sidecar.keep = false;
            return Err(error);
        }
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
    pub(super) fn cleanup(&self, operation: &str) -> Result<(), RfError> {
        let path = self.path(operation)?;
        let file = match private_file(&path) {
            Ok(file) => file,
            Err(RfError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(MAX_ENTRY + 1).read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).map_err(|_| invalid())? > MAX_ENTRY {
            return Err(invalid());
        }
        let entry: Entry = serde_json::from_slice(&bytes)?;
        if entry.operation != operation {
            return Err(invalid());
        }
        // Check both identities before deleting either path, including a replaced sidecar.
        let invitation_exists = entry.invitation.exists()?;
        let sidecar_exists = entry.sidecar.exists()?;
        if sidecar_exists {
            let mut sidecar = String::new();
            private_file(&entry.sidecar.path)?.take(128).read_to_string(&mut sidecar)?;
            if sidecar != operation {
                return Err(invalid());
            }
        }
        for (owned, exists) in
            [(&entry.invitation, invitation_exists), (&entry.sidecar, sidecar_exists)]
        {
            if exists {
                std::fs::remove_file(&owned.path)?;
                File::open(owned.path.parent().ok_or_else(invalid)?)?.sync_all()?;
            }
        }
        std::fs::remove_file(path)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}
/// Capture the supplied file's identity before Join; never unlink a later replacement.
pub(super) struct JoinedFile(OwnedPath);
impl JoinedFile {
    pub(super) fn open(path: &Path) -> Result<Self, RfError> {
        Ok(Self(OwnedPath::new(path, &private_file(path)?)?))
    }
    pub(super) fn remove(self) -> Result<(), RfError> {
        if !self.0.exists()? {
            return Ok(());
        }
        std::fs::remove_file(&self.0.path)?;
        File::open(self.0.path.parent().ok_or_else(invalid)?)?.sync_all()?;
        Ok(())
    }
}
