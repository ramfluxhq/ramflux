// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Installation-wide, resumable, insert-only systemd initialization. Dormant SDK API.
use super::{
    LinuxVaultMode,
    cleanup::Secret,
    durability::{DurabilityOps, RealDurabilityOps},
    systemd,
};
use rustix::fs::{self, FlockOperation, Mode, OFlags, RenameFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

/// Static refusal codes never include paths, provider output or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LinuxVaultInitError {
    /// Only explicit systemd modes are supported by this initializer.
    #[error("vault_mode")]
    Mode,
    /// Unsafe path, owner, permissions, link count or file type.
    #[error("vault_metadata")]
    Metadata,
    /// Root or credential absent; runtime never generates a replacement.
    #[error("vault_missing")]
    Missing,
    /// Initialization must be reconciled explicitly before runtime open.
    #[error("vault_init_pending")]
    Pending,
    /// Invalid or conflicting persisted installation state.
    #[error("vault_corrupt")]
    Corrupt,
    /// Worker or permanent installation lock already held.
    #[error("vault_busy")]
    Busy,
    /// Filesystem operation failed.
    #[error("vault_io")]
    Io,
    /// systemd refused the requested operation or mode.
    #[error("vault_provider")]
    Provider,
    /// Key or provider pipe exceeded its exact bounds.
    #[error("vault_length")]
    Length,
    /// Unknown realm.
    #[error("vault_realm")]
    Realm,
    /// Operating-system randomness failed.
    #[error("vault_random")]
    Random,
    /// Bounded provider/initialization deadline expired.
    #[error("vault_timeout")]
    Timeout,
    /// Caller cancelled; outstanding child is killed and reaped.
    #[error("vault_cancelled")]
    Cancelled,
}
type Error = LinuxVaultInitError;
impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        match e {
            rustix::io::Errno::NOENT => Self::Missing,
            rustix::io::Errno::EXIST => Self::Corrupt,
            rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => Self::Metadata,
            _ => Self::Io,
        }
    }
}
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
pub(super) struct Slot;
impl Slot {
    pub(super) fn acquire() -> Result<Self, Error> {
        ACTIVE
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < 4).then_some(n + 1))
            .map_err(|_| Error::Busy)?;
        Ok(Self)
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Cancel(watch::Sender<bool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    root: PathBuf,
    mode: String,
    class: String,
    vault_id: String,
    key_ids: [String; 3],
    names: [String; 3],
}
impl Manifest {
    fn new(root: &Path, mode: LinuxVaultMode) -> Result<Self, Error> {
        let mut ids = [0_u8; 64]; // Public identities only; no KEKs before intent commit.
        getrandom::fill(&mut ids).map_err(|_| Error::Random)?;
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .flat_map(|b| {
                    [
                        char::from(b"0123456789abcdef"[usize::from(b >> 4)]),
                        char::from(b"0123456789abcdef"[usize::from(b & 15)]),
                    ]
                })
                .collect::<String>()
        };
        Ok(Self {
            version: 1,
            root: root.to_owned(),
            mode: mode_name(mode)?.into(),
            class: mode.strength_class().into(),
            vault_id: hex(&ids[..16]),
            key_ids: std::array::from_fn(|i| hex(&ids[16 + i * 16..32 + i * 16])),
            names: systemd::NAMES.map(str::to_owned),
        })
    }
    fn validate(&self, root: &Path, mode: LinuxVaultMode) -> Result<(), Error> {
        let id_ok = |s: &str| {
            s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.version != 1
            || self.root != root
            || self.mode != mode_name(mode)?
            || self.class != mode.strength_class()
            || self.names != systemd::NAMES.map(str::to_owned)
            || !id_ok(&self.vault_id)
            || !self.key_ids.iter().all(|s| id_ok(s))
            || self.key_ids[0] == self.key_ids[1]
            || self.key_ids[1] == self.key_ids[2]
            || self.key_ids[0] == self.key_ids[2]
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    fn slot(&self, i: usize) -> String {
        format!("{}.{}.cred", self.names[i], self.key_ids[i])
    }
}
fn mode_name(mode: LinuxVaultMode) -> Result<&'static str, Error> {
    match mode {
        LinuxVaultMode::SystemdHost => Ok("systemd-host"),
        LinuxVaultMode::SystemdTpm2 => Ok("systemd-tpm2"),
        LinuxVaultMode::DesktopSecretService => Err(Error::Mode),
    }
}
fn verify(fd: &OwnedFd, directory: bool) -> Result<(), Error> {
    let s = fs::fstat(fd)?;
    if s.st_uid != rustix::process::geteuid().as_raw()
        || s.st_mode & 0o7777 != if directory { 0o700 } else { 0o600 }
        || fs::FileType::from_raw_mode(s.st_mode)
            != if directory { fs::FileType::Directory } else { fs::FileType::RegularFile }
        || (!directory && s.st_nlink != 1)
    {
        return Err(Error::Metadata);
    }
    Ok(())
}
fn root_fd(root: &Path) -> Result<OwnedFd, Error> {
    if !root.is_absolute() || root == Path::new("/") {
        return Err(Error::Metadata);
    }
    let mut fd =
        fs::open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
    for part in root.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(p) => {
                fd = fs::openat(
                    &fd,
                    p,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
            }
            _ => return Err(Error::Metadata),
        }
    }
    verify(&fd, true)?;
    Ok(fd)
}
fn open(dir: &OwnedFd, name: &str, flags: OFlags) -> Result<OwnedFd, Error> {
    let fd = fs::openat(
        dir,
        name,
        flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?;
    verify(&fd, false)?;
    Ok(fd)
}
fn read(dir: &OwnedFd, name: &str, cap: usize) -> Result<Vec<u8>, Error> {
    let fd = open(dir, name, OFlags::RDONLY)?;
    let size = fs::fstat(&fd)?.st_size;
    if size < 1 || size > i64::try_from(cap).map_err(|_| Error::Length)? {
        return Err(Error::Length);
    }
    let mut bytes = Vec::with_capacity(cap + 1); // Encrypted bytes or public metadata only.
    File::from(fd).take((cap + 1) as u64).read_to_end(&mut bytes).map_err(|_| Error::Io)?;
    if bytes.len() > cap {
        return Err(Error::Length);
    }
    Ok(bytes)
}
fn optional(dir: &OwnedFd, name: &str, cap: usize) -> Result<Option<Vec<u8>>, Error> {
    match read(dir, name, cap) {
        Ok(b) => Ok(Some(b)),
        Err(Error::Missing) => Ok(None),
        Err(e) => Err(e),
    }
}
/// Removes unpublished staging; a missing name is already removed.
fn remove(dir: &OwnedFd, name: &str, ops: &dyn DurabilityOps) -> Result<(), Error> {
    match open(dir, name, OFlags::RDONLY) {
        Ok(_) => ops.unlink(dir, name)?,
        Err(Error::Missing) => return Ok(()),
        Err(e) => return Err(e),
    }
    ops.fsync_dir(dir)?;
    Ok(())
}
/// Durable insert-only publication: file fsync, NOREPLACE rename, parent fsync.
fn publish(
    dir: &OwnedFd,
    name: &str,
    bytes: &[u8],
    ops: &dyn DurabilityOps,
    cut: &impl Fn(&str),
) -> Result<(), Error> {
    let temp = format!(".{name}.staging");
    // Only unpublished staging is removed, after caller established destination absence.
    remove(dir, &temp, ops)?;
    let fd = open(dir, &temp, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)?;
    let mut file = File::from(fd);
    file.write_all(bytes).map_err(|_| Error::Io)?;
    cut("before-file-sync");
    ops.fsync_file(&file)?;
    cut("after-file-sync");
    ops.rename(dir, &temp, name, RenameFlags::NOREPLACE)?;
    cut("after-publish");
    ops.fsync_dir(dir)?;
    cut("after-parent-sync");
    Ok(())
}
/// Removes the init intent: unlink, then parent fsync. A missing intent still gets the parent
/// fsync, which reconciles a process killed after the unlink but before that fsync.
fn retire_intent(dir: &OwnedFd, ops: &dyn DurabilityOps, cut: &impl Fn(&str)) -> Result<(), Error> {
    match open(dir, "init.pending", OFlags::RDONLY) {
        Ok(_) => {
            ops.unlink(dir, "init.pending")?;
            cut("intent-unlinked");
        }
        Err(Error::Missing) => {}
        Err(e) => return Err(e),
    }
    ops.fsync_dir(dir)?;
    Ok(())
}
fn parse(bytes: &[u8], root: &Path, mode: LinuxVaultMode) -> Result<Manifest, Error> {
    let m: Manifest = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
    m.validate(root, mode)?;
    if serde_json::to_vec(&m).map_err(|_| Error::Corrupt)? != bytes {
        return Err(Error::Corrupt);
    }
    Ok(m)
}

/// Explicit installation bootstrap; does not change native provider selection.
pub struct LinuxVaultInstallation;
impl LinuxVaultInstallation {
    /// Check an injected read-only, owner-only, exactly 32-byte credential without exporting it.
    /// # Errors
    /// Rejects missing, linked, unsafe or wrong-length credentials.
    pub async fn check_credential(path: PathBuf) -> Result<(), Error> {
        let slot = Slot::acquire()?;
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            Self::read_credential(&path)
        })
        .await
        .map_err(|_| Error::Io)?
    }
    fn read_credential(path: &Path) -> Result<(), Error> {
        if !path.is_absolute() {
            return Err(Error::Metadata);
        }
        let mut fd =
            fs::open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
        let parts: Vec<_> = path.components().collect();
        for (i, part) in parts.iter().enumerate() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let directory = i + 1 != parts.len();
                    fd = fs::openat(
                        &fd,
                        *name,
                        OFlags::RDONLY
                            | OFlags::NOFOLLOW
                            | OFlags::NONBLOCK
                            | OFlags::CLOEXEC
                            | if directory { OFlags::DIRECTORY } else { OFlags::empty() },
                        Mode::empty(),
                    )?;
                }
                _ => return Err(Error::Metadata),
            }
        }
        let stat = fs::fstat(&fd)?;
        if stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o400
            || stat.st_nlink != 1
            || fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
        {
            return Err(Error::Metadata);
        }
        let mut key = Secret::<33>::new("p04-runtime-read");
        let mut file = File::from(fd);
        let mut len = 0;
        while len < 33 {
            let n = file.read(&mut key.bytes_mut()[len..]).map_err(|_| Error::Io)?;
            if n == 0 {
                break;
            }
            len += n;
        }
        if len != 32 {
            return Err(Error::Length);
        }
        Ok(())
    }

    /// Initialize/resume an operator-owned existing private root; retain all published keys.
    /// # Errors
    /// Refuses conflicts, unsafe metadata, contention and provider/deadline failures.
    pub async fn initialize(root: PathBuf, mode: LinuxVaultMode) -> Result<(), Error> {
        Self::run(root, mode, true).await
    }
    /// Verify committed installation and original three keys, without creating anything.
    /// # Errors
    /// Refuses pending/missing/corrupt installations or unavailable original credentials.
    pub async fn status(root: PathBuf, mode: LinuxVaultMode) -> Result<(), Error> {
        Self::run(root, mode, false).await
    }
    async fn run(root: PathBuf, mode: LinuxVaultMode, initialize: bool) -> Result<(), Error> {
        mode_name(mode)?;
        let slot = Slot::acquire()?;
        let (sender, mut cancel) = watch::channel(false);
        let _cancel = Cancel(sender);
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let end = Instant::now() + Duration::from_secs(90);
            runtime.block_on(attempt(&root, mode, initialize, &mut cancel, end, &|_| {}))
        })
        .await
        .map_err(|_| Error::Io)?
    }
}

async fn attempt(
    root: &Path,
    mode: LinuxVaultMode,
    initialize: bool,
    cancel: &mut watch::Receiver<bool>,
    deadline: Instant,
    cut: &impl Fn(&str),
) -> Result<(), Error> {
    let plan = Plan { root, mode, initialize, deadline, ops: &RealDurabilityOps };
    attempt_with(&plan, cancel, cut).await
}
/// Inputs of one initialization attempt; `ops` performs every durability operation.
struct Plan<'a> {
    root: &'a Path,
    mode: LinuxVaultMode,
    initialize: bool,
    deadline: Instant,
    ops: &'a dyn DurabilityOps,
}
async fn attempt_with(
    plan: &Plan<'_>,
    cancel: &mut watch::Receiver<bool>,
    cut: &impl Fn(&str),
) -> Result<(), Error> {
    let Plan { root, mode, initialize, deadline, ops } = *plan;
    systemd::probe(cancel, deadline).await?;
    let dir = root_fd(root)?;
    let lock = open(
        &dir,
        ".init.lock",
        if initialize { OFlags::RDWR | OFlags::CREATE } else { OFlags::RDWR },
    )?;
    fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::Busy)?;
    ops.fsync_dir(&dir)?;
    let pending = optional(&dir, "init.pending", 4096)?;
    let descriptor = optional(&dir, "descriptor.json", 4096)?;
    if !initialize && pending.is_some() {
        return Err(Error::Pending);
    }
    let (manifest, committed) = match (pending, descriptor) {
        (Some(p), Some(d)) => {
            if p != d {
                return Err(Error::Corrupt);
            }
            (parse(&p, root, mode)?, true)
        }
        (Some(p), None) => (parse(&p, root, mode)?, false),
        (None, Some(d)) => (parse(&d, root, mode)?, true),
        (None, None) if !initialize => return Err(Error::Missing),
        (None, None) => {
            // No published orphan can be silently adopted or replaced.
            let mut entries = fs::Dir::read_from(&dir)?;
            for entry in &mut entries {
                let entry = entry?;
                let name = entry.file_name().to_bytes();
                if !matches!(name, b"." | b".." | b".init.lock" | b".init.pending.staging") {
                    return Err(Error::Corrupt);
                }
            }
            let m = Manifest::new(root, mode)?;
            let bytes = serde_json::to_vec(&m).map_err(|_| Error::Corrupt)?;
            if bytes.len() > 4096 {
                return Err(Error::Length);
            }
            publish(&dir, "init.pending", &bytes, ops, cut)?;
            cut("intent-durable");
            (m, false)
        }
    };
    for realm in 0..3 {
        if *cancel.borrow() {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        let name = manifest.slot(realm);
        if let Some(blob) = optional(&dir, &name, systemd::CAP)? {
            let _original = systemd::decrypt(mode, realm, &blob, cancel, deadline).await?;
            cut("existing-readback");
            continue;
        }
        if committed {
            return Err(Error::Corrupt);
        }
        let mut key = Secret::<32>::new("p04-generated-key");
        getrandom::fill(key.bytes_mut()).map_err(|_| Error::Random)?;
        cut("generated");
        let (blob, len) =
            systemd::pipe::<{ systemd::CAP + 1 }>(mode, realm, true, key.bytes(), cancel, deadline)
                .await?;
        cut("encrypted");
        let readback =
            systemd::decrypt(mode, realm, &blob.bytes()[..len], cancel, deadline).await?;
        if &readback.bytes()[..32] != key.bytes() {
            return Err(Error::Corrupt);
        }
        cut("readback");
        publish(&dir, &name, &blob.bytes()[..len], ops, cut)?;
        cut("realm-durable");
    }
    if *cancel.borrow() {
        return Err(Error::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(Error::Timeout);
    }
    if !committed {
        let bytes = serde_json::to_vec(&manifest).map_err(|_| Error::Corrupt)?;
        publish(&dir, "descriptor.json", &bytes, ops, cut)?;
        cut("descriptor-durable");
    }
    if initialize {
        cut("before-intent-remove");
        retire_intent(&dir, ops, cut)?;
        cut("intent-removed");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
