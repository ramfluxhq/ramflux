// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Descriptor-anchored private filesystem access and atomic, non-replacing publication.

use super::invalid;
use crate::RfError;
use rustix::fs::{AtFlags, Dir, Mode, OFlags, openat};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

fn io(error: rustix::io::Errno) -> RfError {
    std::io::Error::from(error).into()
}

fn checked_file(file: File, secret: bool) -> Result<File, RfError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("custody input must be a regular file, never a symlink or device"));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if (secret && !matches!(mode, 0o600 | 0o400 | 0o640 | 0o440)) || (!secret && mode & 0o022 != 0)
    {
        return Err(invalid("custody input has unsafe file permissions"));
    }
    Ok(file)
}

fn read_file(file: File, limit: u64) -> Result<Zeroizing<Vec<u8>>, RfError> {
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("custody input exceeds its size limit"));
    }
    Ok(bytes)
}

pub(super) fn read_input(
    path: &Path,
    limit: u64,
    secret: bool,
) -> Result<Zeroizing<Vec<u8>>, RfError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io)?;
    read_file(checked_file(File::from(fd), secret)?, limit)
}

pub(super) struct PrivateDir {
    file: File,
}

impl PrivateDir {
    pub(super) fn open(path: &Path) -> Result<Self, RfError> {
        match rustix::fs::mkdir(path, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => (),
            Err(error) => return Err(io(error)),
        }
        let file = File::from(rustix::fs::open(path, Self::flags(), Mode::empty()).map_err(io)?);
        Self::checked(file)
    }

    fn flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
    }

    fn checked(file: File) -> Result<Self, RfError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = file.metadata()?;
        if !metadata.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(invalid(
                "custody output directory must be owned by this user with mode 0700",
            ));
        }
        Ok(Self { file })
    }

    pub(super) fn canonical_path(&self, path: &Path) -> Result<PathBuf, RfError> {
        let canonical = path.canonicalize()?;
        self.check_path(&canonical)?;
        if canonical.to_str().is_none_or(|text| text.contains(['\n', '\r'])) {
            return Err(invalid("custody output path must be UTF-8 without line breaks"));
        }
        Ok(canonical)
    }

    pub(super) fn check_path(&self, path: &Path) -> Result<(), RfError> {
        use std::os::unix::fs::MetadataExt;
        let other = File::from(rustix::fs::open(path, Self::flags(), Mode::empty()).map_err(io)?);
        let current = self.file.metadata()?;
        let named = other.metadata()?;
        if current.dev() != named.dev() || current.ino() != named.ino() {
            return Err(invalid("custody output directory changed during the operation"));
        }
        Ok(())
    }

    pub(super) fn child(&self, name: &str) -> Result<Self, RfError> {
        match rustix::fs::mkdirat(&self.file, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => (),
            Err(error) => return Err(io(error)),
        }
        Self::checked(File::from(
            openat(&self.file, name, Self::flags(), Mode::empty()).map_err(io)?,
        ))
    }

    pub(super) fn check_child(&self, parent: &Self, name: &str) -> Result<(), RfError> {
        use std::os::unix::fs::MetadataExt;
        let named =
            File::from(openat(&parent.file, name, Self::flags(), Mode::empty()).map_err(io)?)
                .metadata()?;
        let current = self.file.metadata()?;
        if current.dev() != named.dev() || current.ino() != named.ino() {
            return Err(invalid("custody output subdirectory changed during the operation"));
        }
        Ok(())
    }

    pub(super) fn names(&self) -> Result<Vec<String>, RfError> {
        Dir::read_from(&self.file)
            .map_err(io)?
            .map(|entry| {
                let entry = entry.map_err(io)?;
                entry
                    .file_name()
                    .to_str()
                    .map(str::to_owned)
                    .map_err(|_| invalid("invalid custody output filename"))
            })
            .collect()
    }

    pub(super) fn exists(&self, name: &str) -> Result<bool, RfError> {
        match rustix::fs::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(io(error)),
        }
    }

    pub(super) fn read(
        &self,
        name: &str,
        limit: u64,
        secret: bool,
    ) -> Result<Zeroizing<Vec<u8>>, RfError> {
        let fd = openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(io)?;
        read_file(checked_file(File::from(fd), secret)?, limit)
    }

    pub(super) fn lock_file(&self) -> Result<(File, bool), RfError> {
        let flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        let (fd, created) = match openat(
            &self.file,
            ".lock",
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => (fd, true),
            Err(rustix::io::Errno::EXIST) => {
                (openat(&self.file, ".lock", flags, Mode::empty()).map_err(io)?, false)
            }
            Err(error) => return Err(io(error)),
        };
        Ok((checked_file(File::from(fd), true)?, created))
    }

    pub(super) fn write_immutable(&self, name: &str, bytes: &[u8]) -> Result<(), RfError> {
        let temporary = format!(
            ".custody-pending-{}",
            ramflux_protocol::encode_base64url(
                ramflux_crypto::random_32().map_err(|error| invalid(error.to_string()))?
            )
        );
        let fd = openat(
            &self.file,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io)?;
        let guard = Temporary { directory: &self.file, name: &temporary };
        let mut file = File::from(fd);
        file.write_all(bytes)?;
        file.sync_all()?;
        rustix::fs::linkat(&self.file, &temporary, &self.file, name, AtFlags::empty())
            .map_err(io)?;
        drop(guard);
        self.file.sync_all()?;
        Ok(())
    }

    pub(super) fn sync(&self) -> Result<(), RfError> {
        self.file.sync_all().map_err(Into::into)
    }

    pub(super) fn remove_abandoned_temporaries(&self) -> Result<(), RfError> {
        for name in self.names()? {
            if let Some(nonce) = name.strip_prefix(".custody-pending-")
                && ramflux_protocol::decode_base64url(nonce).is_ok_and(|bytes| bytes.len() == 32)
            {
                rustix::fs::unlinkat(&self.file, &name, AtFlags::empty()).map_err(io)?;
            }
        }
        Ok(())
    }
}

struct Temporary<'a> {
    directory: &'a File,
    name: &'a str,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        let _ = rustix::fs::unlinkat(self.directory, self.name, AtFlags::empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn failed_publication_removes_its_temporary_file() -> Result<(), RfError> {
        let path = std::env::temp_dir().join(format!(
            "rf-custody-atomic-{}",
            ramflux_protocol::encode_base64url(
                ramflux_crypto::random_32().map_err(|error| invalid(error.to_string()))?
            )
        ));
        let directory = PrivateDir::open(&path)?;
        directory.write_immutable("kept", b"original")?;
        assert!(directory.write_immutable("kept", b"replacement").is_err());
        assert_eq!(&*directory.read("kept", 100, true)?, b"original");
        assert!(!directory.names()?.iter().any(|name| name.starts_with(".custody-pending-")));
        fs::remove_dir_all(path)?;
        Ok(())
    }

    #[test]
    fn directory_replacement_never_redirects_descriptor_relative_writes() -> Result<(), RfError> {
        let parent = std::env::temp_dir().join(format!(
            "rf-custody-fd-{}",
            ramflux_protocol::encode_base64url(
                ramflux_crypto::random_32().map_err(|error| invalid(error.to_string()))?
            )
        ));
        let directory = PrivateDir::open(&parent)?;
        let child = directory.child("records")?;
        fs::rename(parent.join("records"), parent.join("retained"))?;
        directory.child("records")?;
        assert!(child.check_child(&directory, "records").is_err());
        child.write_immutable("anchored", b"original descriptor")?;
        assert_eq!(fs::read(parent.join("retained/anchored"))?, b"original descriptor");
        assert!(!parent.join("records/anchored").exists());
        let renamed = parent.with_extension("retained");
        fs::rename(&parent, &renamed)?;
        PrivateDir::open(&parent)?;
        assert!(directory.check_path(&parent).is_err());
        fs::remove_dir_all(parent)?;
        fs::remove_dir_all(renamed)?;
        Ok(())
    }
}
