// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Remove only the Unix socket inode owned by this listener.

use crate::prelude::*;

pub(super) struct SocketFile {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl SocketFile {
    pub(super) fn new(listener: &UnixListener) -> Result<Option<Self>, SdkError> {
        let address = listener.local_addr()?;
        let Some(path) = address.as_pathname() else {
            return Ok(None);
        };
        let metadata = std::fs::metadata(path)?;
        Ok(Some(Self { path: path.to_path_buf(), device: metadata.dev(), inode: metadata.ino() }))
    }
    pub(super) fn remove(&self) -> Result<(), SdkError> {
        match std::fs::metadata(&self.path) {
            Ok(metadata) if metadata.dev() == self.device && metadata.ino() == self.inode => {
                std::fs::remove_file(&self.path)?;
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        Ok(())
    }
}
impl Drop for SocketFile {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            tracing::warn!(%error,"daemon socket cleanup failed");
        }
    }
}
