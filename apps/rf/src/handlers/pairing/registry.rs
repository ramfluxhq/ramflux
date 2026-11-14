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
                    && metadata.permissions().mode().trailing_zeros() >= 6
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
    account: String,
    role: String,
    invitation: Option<OwnedPath>,
    sidecar: Option<OwnedPath>,
    sas: Vec<OwnedPath>,
}
pub(super) struct Registry {
    directory: PathBuf,
    _lock: File,
}
pub(super) fn private_file(path: &Path) -> Result<File, RfError> {
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
        account: &str,
    ) -> Result<(), RfError> {
        if account.is_empty() || account.len() > 128 {
            return Err(invalid());
        }
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
            account: account.into(),
            role: "initiator".into(),
            invitation: Some(OwnedPath::new(&output.path, &output.file)?),
            sidecar: Some(OwnedPath::new(&sidecar.path, &sidecar.file)?),
            sas: Vec::new(),
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
    fn load(&self, operation: &str) -> Result<Option<Entry>, RfError> {
        let file = match private_file(&self.path(operation)?) {
            Ok(file) => file,
            Err(RfError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(MAX_ENTRY + 1).read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).map_err(|_| invalid())? > MAX_ENTRY {
            return Err(invalid());
        }
        let entry: Entry = serde_json::from_slice(&bytes)?;
        if entry.operation != operation
            || entry.sas.len() > 8
            || entry.invitation.is_some() != entry.sidecar.is_some()
        {
            return Err(invalid());
        }
        Ok(Some(entry))
    }
    pub(super) fn record_role(
        &self,
        operation: &str,
        account: &str,
        role: &str,
    ) -> Result<(), RfError> {
        if account.is_empty() || account.len() > 128 || !matches!(role, "initiator" | "responder") {
            return Err(invalid());
        }
        if let Some(entry) = self.load(operation)? {
            if entry.account != account || entry.role != role {
                return Err(invalid());
            }
            return Ok(());
        }
        if std::fs::read_dir(&self.directory)?.take(LIMIT + 2).count() > LIMIT {
            return Err(invalid());
        }
        self.save(&Entry {
            operation: operation.into(),
            account: account.into(),
            role: role.into(),
            invitation: None,
            sidecar: None,
            sas: Vec::new(),
        })
    }
    pub(super) fn role(&self, operation: &str, account: &str) -> Result<String, RfError> {
        let entry = self.load(operation)?.ok_or_else(invalid)?;
        if entry.account != account || !matches!(entry.role.as_str(), "initiator" | "responder") {
            return Err(invalid());
        }
        Ok(entry.role)
    }
    pub(super) fn register_sas(
        &self,
        operation: &str,
        output: &InvitationOutput,
    ) -> Result<(), RfError> {
        let mut entry = self.load(operation)?.ok_or_else(invalid)?;
        if entry.sas.len() >= 8 {
            return Err(invalid());
        }
        entry.sas.push(OwnedPath::new(&output.path, &output.file)?);
        self.save(&entry)
    }
    fn save(&self, entry: &Entry) -> Result<(), RfError> {
        let operation = &entry.operation;
        let bytes = serde_json::to_vec(entry)?;
        if u64::try_from(bytes.len()).map_err(|_| invalid())? > MAX_ENTRY {
            return Err(invalid());
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_nanos();
        let mut temporary = InvitationOutput::create(
            self.directory.join(format!(".{operation}-{}-{nonce}.tmp", std::process::id())),
        )?;
        temporary.commit(&bytes)?;
        temporary.keep = false;
        std::fs::rename(&temporary.path, self.path(operation)?)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
    pub(super) fn cleanup(&self, operation: &str) -> Result<(), RfError> {
        let Some(entry) = self.load(operation)? else {
            return Ok(());
        };
        let paths = entry.invitation.iter().chain(entry.sidecar.iter()).chain(entry.sas.iter());
        // Validate every original identity before deleting any registered path.
        let mut owned = Vec::new();
        for path in paths {
            if path.exists()? {
                owned.push(path);
            }
        }
        if let Some(sidecar) = &entry.sidecar
            && sidecar.exists()?
        {
            let mut value = String::new();
            private_file(&sidecar.path)?.take(128).read_to_string(&mut value)?;
            if value != operation {
                return Err(invalid());
            }
        }
        for path in owned {
            std::fs::remove_file(&path.path)?;
            File::open(path.path.parent().ok_or_else(invalid)?)?.sync_all()?;
        }
        std::fs::remove_file(self.path(operation)?)?;
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
