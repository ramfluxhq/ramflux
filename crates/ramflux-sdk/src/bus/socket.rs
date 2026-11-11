// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Remove only the Unix socket inode owned by this listener.

use crate::platform::listener::BusListener;
use crate::prelude::*;

pub(super) struct SocketFile {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl SocketFile {
    pub(super) fn new(
        listener: &crate::platform::listener::UnixBusListener,
    ) -> Result<Option<Self>, SdkError> {
        let Some((path, device, inode)) = listener.pathname_identity()? else {
            return Ok(None);
        };
        Ok(Some(Self { path, device, inode }))
    }
    pub(super) fn remove(&self) -> Result<(), SdkError> {
        if crate::platform::fs::same_device_inode(&self.path, self.device, self.inode)? {
            std::fs::remove_file(&self.path)?;
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
