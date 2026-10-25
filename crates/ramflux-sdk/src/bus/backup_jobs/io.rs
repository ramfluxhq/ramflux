// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cooperative cancellation, space checks and failure-safe partial-file ownership.
use crate::backup::{BackupFailure, BackupFailureCode};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub(super) fn check_space(path: &Path, needed: u64) -> Result<(), BackupFailure> {
    let available = fs2::available_space(path)
        .map_err(|_| BackupFailure::new(BackupFailureCode::Unreadable))?;
    if available < needed {
        return Err(BackupFailure {
            code: BackupFailureCode::InsufficientSpace,
            needed_bytes: Some(needed),
            available_bytes: Some(available),
            ..BackupFailure::new(BackupFailureCode::InsufficientSpace)
        });
    }
    Ok(())
}
pub(super) struct ProgressIo<T> {
    pub inner: T,
    pub cancel: Arc<AtomicBool>,
    pub bytes: u64,
    pub space: Option<PathBuf>,
    pub notify: Box<dyn FnMut(u64) + Send>,
}
impl<T> ProgressIo<T> {
    fn check(&self, needed: usize) -> std::io::Result<()> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        if let Some(path) = &self.space
            && fs2::available_space(path)? < (needed as u64).saturating_add(1024 * 1024)
        {
            return Err(std::io::ErrorKind::StorageFull.into());
        }
        Ok(())
    }
}
impl<T: Read> Read for ProgressIo<T> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.check(0)?;
        let n = self.inner.read(bytes)?;
        self.bytes += n as u64;
        (self.notify)(self.bytes);
        Ok(n)
    }
}
impl<T: Write> Write for ProgressIo<T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.check(bytes.len())?;
        let n = self.inner.write(bytes)?;
        self.bytes += n as u64;
        (self.notify)(self.bytes);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
pub(super) struct PartialFile {
    pub path: PathBuf,
    pub published: bool,
}
impl Drop for PartialFile {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(super) struct PrivateDirectory {
    pub path: PathBuf,
    pub transferred: bool,
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        if !self.transferred {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn insufficient_space_is_typed_with_estimated_needed_and_observed_available()
    -> Result<(), std::io::Error> {
        let root = std::env::temp_dir();
        let failure = check_space(&root, u64::MAX)
            .err()
            .ok_or_else(|| std::io::Error::other("space unexpectedly unlimited"))?;
        assert_eq!(failure.code, BackupFailureCode::InsufficientSpace);
        assert_eq!(failure.needed_bytes, Some(u64::MAX));
        assert!(failure.available_bytes.is_some_and(|n| n < u64::MAX));
        Ok(())
    }
}
