// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local-bus listener. The Unix implementation binds a pathname socket and sets mode 0o600.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::SdkError;
use crate::platform::fs::{self, LocalSocketStream};

pub(crate) trait BusListener: Sized {
    type Stream;

    /// # Errors
    /// Returns an error when the carrier cannot be bound or its owner-only mode cannot be set.
    fn bind(path: &Path) -> Result<Self, SdkError>;

    /// # Errors
    /// Returns an error when the bound socket's owner cannot be read.
    fn owner_uid(&self) -> Result<u32, SdkError>;

    /// # Errors
    /// Returns an error when accepting a connection fails.
    async fn accept(&self) -> std::io::Result<Self::Stream>;

    /// Pathname, device and inode of the bound socket. Abstract addresses return `None`.
    ///
    /// # Errors
    /// Returns an error when the local address or its file identity cannot be read.
    fn pathname_identity(&self) -> Result<Option<(PathBuf, u64, u64)>, SdkError>;
}

pub(crate) struct UnixBusListener {
    inner: tokio::net::UnixListener,
    path: PathBuf,
}

impl UnixBusListener {
    /// Adopt a listener the caller already bound. The socket mode is left unchanged.
    #[cfg(test)]
    pub(crate) fn from_bound(inner: tokio::net::UnixListener, path: &Path) -> Self {
        Self { inner, path: path.to_path_buf() }
    }
}

impl BusListener for UnixBusListener {
    type Stream = LocalSocketStream;

    fn bind(path: &Path) -> Result<Self, SdkError> {
        let inner = tokio::net::UnixListener::bind(path)?;
        fs::set_owner_only_file(path)?;
        Ok(Self { inner, path: path.to_path_buf() })
    }

    fn owner_uid(&self) -> Result<u32, SdkError> {
        fs::file_owner_uid(&self.path)
    }

    async fn accept(&self) -> std::io::Result<Self::Stream> {
        let (stream, _) = self.inner.accept().await?;
        Ok(stream)
    }

    fn pathname_identity(&self) -> Result<Option<(PathBuf, u64, u64)>, SdkError> {
        let address = self.inner.local_addr()?;
        let Some(path) = address.as_pathname() else {
            return Ok(None);
        };
        let metadata = std::fs::metadata(path)?;
        Ok(Some((path.to_path_buf(), metadata.dev(), metadata.ino())))
    }
}

pub(crate) async fn connect(path: impl AsRef<Path>) -> Result<LocalSocketStream, SdkError> {
    Ok(LocalSocketStream::connect(path).await?)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[tokio::test]
    async fn unix_listener_is_owner_only_and_rejects_a_different_uid() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let path = dir.path().join("daemon.sock");
        let listener =
            <UnixBusListener as BusListener>::bind(&path).map_err(|err| err.to_string())?;
        let mode =
            std::fs::metadata(&path).map_err(|err| err.to_string())?.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(format!("socket mode {mode:o}"));
        }
        let uid = listener.owner_uid().map_err(|err| err.to_string())?;
        let file_uid = std::fs::metadata(&path).map_err(|err| err.to_string())?.uid();
        if uid != file_uid {
            return Err(format!("listener uid {uid} != file uid {file_uid}"));
        }
        let _client = connect(&path).await.map_err(|err| err.to_string())?;
        let accepted = listener.accept().await.map_err(|err| err.to_string())?;
        fs::verify_peer_uid(&accepted, uid).map_err(|err| err.to_string())?;
        match fs::verify_peer_uid(&accepted, uid.wrapping_add(1)) {
            Err(SdkError::LocalBusPermissionDenied) => {}
            Ok(()) => return Err("a different uid was accepted".to_owned()),
            Err(error) => return Err(error.to_string()),
        }
        let Some((bound, device, inode)) =
            listener.pathname_identity().map_err(|err| err.to_string())?
        else {
            return Err("pathname socket had no path".to_owned());
        };
        if !fs::same_device_inode(&bound, device, inode).map_err(|err| err.to_string())? {
            return Err("listener identity did not match the bound socket".to_owned());
        }
        Ok(())
    }
}
