// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified directory handles and bounded ciphertext reads. No secret ownership.
use super::codec::{self, Binding, MAX_RECORD};
use rustix::fs::{self, Mode, OFlags};
use std::{
    fs::File,
    io::Read,
    os::fd::OwnedFd,
    path::{Component, Path},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(super) enum Error {
    #[error("unsafe vault path")]
    Path,
    #[error("unsafe vault metadata")]
    Metadata,
    #[error("vault I/O failed")]
    Io,
    #[error("vault entry missing")]
    Missing,
    #[error("vault entry already exists")]
    Exists,
    #[error("vault busy")]
    Busy,
    #[error("vault realm full")]
    Full,
    #[error("vault generation conflict")]
    Generation,
    #[cfg(test)]
    #[error("vault replacement forbidden")]
    Replacement,
    #[error("invalid vault record: {0}")]
    Record(codec::Error),
}
impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        match e {
            rustix::io::Errno::NOENT => Self::Missing,
            rustix::io::Errno::EXIST => Self::Exists,
            rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => Self::Path,
            rustix::io::Errno::ACCESS | rustix::io::Errno::PERM => Self::Metadata,
            _ => Self::Io,
        }
    }
}
pub(super) fn verify(fd: &OwnedFd, directory: bool) -> Result<(), Error> {
    verify_owner(fd, directory, rustix::process::geteuid().as_raw())
}
pub(super) fn verify_owner(fd: &OwnedFd, directory: bool, uid: u32) -> Result<(), Error> {
    let s = fs::fstat(fd)?;
    let kind = if directory { fs::FileType::Directory } else { fs::FileType::RegularFile };
    if fs::FileType::from_raw_mode(s.st_mode) != kind
        || s.st_uid != uid
        || s.st_mode & 0o7777 != if directory { 0o700 } else { 0o600 }
        || (!directory && s.st_nlink != 1)
    {
        return Err(Error::Metadata);
    }
    Ok(())
}
pub(super) fn open_file(dir: &OwnedFd, name: &str, flags: OFlags) -> Result<OwnedFd, Error> {
    let fd = fs::openat(
        dir,
        name,
        flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?;
    verify(&fd, false)?;
    Ok(fd)
}
fn child(dir: &OwnedFd, name: &str) -> Result<OwnedFd, Error> {
    match fs::mkdirat(dir, name, Mode::RWXU) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(e.into()),
    }
    let fd = fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    verify(&fd, true)?;
    // Also reconcile a previous creator that died before syncing its mkdir.
    fs::fsync(dir)?;
    Ok(fd)
}

pub(super) struct Store {
    pub account_dir: OwnedFd,
    pub realm_dir: OwnedFd,
    pub account: String,
    pub realm: u8,
    pub vault_id: [u8; 16],
    pub key_id: [u8; 16],
}
impl Store {
    pub(super) fn open(
        root: &Path,
        account: &str,
        realm: u8,
        vault_id: [u8; 16],
        key_id: [u8; 16],
    ) -> Result<Self, Error> {
        crate::custody::valid_id(account).map_err(|_| Error::Record(codec::Error::Account))?;
        if !(1..=3).contains(&realm) {
            return Err(Error::Record(codec::Error::Realm));
        }
        if !root.is_absolute() {
            return Err(Error::Path);
        }
        let mut fd =
            fs::open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
        let mut count = 0;
        for c in root.components() {
            match c {
                Component::RootDir => {}
                Component::Normal(name) => {
                    count += 1;
                    fd = fs::openat(
                        &fd,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?;
                }
                _ => return Err(Error::Path),
            }
        }
        if count == 0 {
            return Err(Error::Path);
        }
        verify(&fd, true)?;
        let account_dir = child(&fd, account)?;
        let realm_dir = child(&account_dir, &realm.to_string())?;
        Ok(Self { account_dir, realm_dir, account: account.to_owned(), realm, vault_id, key_id })
    }
    pub(super) fn binding<'a>(
        &'a self,
        kind: u8,
        reference: &'a str,
        generation: u64,
    ) -> Binding<'a> {
        Binding {
            realm: self.realm,
            kind,
            vault_id: self.vault_id,
            generation,
            key_id: self.key_id,
            account: &self.account,
            reference,
        }
    }
    pub(super) fn read(
        &self,
        reference: &str,
        kind: u8,
        generation: u64,
    ) -> Result<Vec<u8>, Error> {
        // Validate reference and cross-fields before interpreting it as a filename.
        self.binding(kind, reference, generation).validate_name().map_err(Error::Record)?;
        let fd = open_file(&self.realm_dir, reference, OFlags::RDONLY)?;
        let size = fs::fstat(&fd)?.st_size;
        if !(97..=8288_i64).contains(&size) {
            return Err(Error::Record(codec::Error::RecordSize));
        }
        let mut bytes = Vec::with_capacity(MAX_RECORD + 1);
        File::from(fd)
            .take((MAX_RECORD + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Io)?;
        codec::validate_record(self.binding(kind, reference, generation), &bytes)
            .map_err(Error::Record)?;
        Ok(bytes)
    }
}
