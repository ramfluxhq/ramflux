// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local-bus listener. The Unix implementation binds a pathname socket and sets mode 0o600.
//! Peer credentials and endpoint identity stay inside this module.

#[cfg(test)]
use std::future::Future;
use std::path::{Path, PathBuf};

use crate::SdkError;
use crate::platform::fs::{self, LocalSocketStream};

/// Opaque same-user credential. The Unix implementation stores a uid.
#[derive(Clone, Copy)]
pub(crate) struct PeerCred {
    unix_uid: u32,
}

/// Opaque bound-socket identity. The Unix implementation stores pathname, device, and inode.
pub(crate) struct EndpointId {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl EndpointId {
    /// Remove the socket file only when it is still the bound inode.
    ///
    /// # Errors
    /// Returns an error when identity cannot be read or the matching file cannot be removed.
    pub(crate) fn remove_if_unchanged(&self) -> Result<(), SdkError> {
        if fs::same_device_inode(&self.path, self.device, self.inode)? {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

/// Byte stream accepted from a [`BusListener`].
pub(crate) trait BusStream: Sized {
    type ReadHalf: tokio::io::AsyncRead + Unpin + 'static;
    type WriteHalf: tokio::io::AsyncWrite + Unpin + 'static;

    fn into_halves(self) -> (Self::ReadHalf, Self::WriteHalf);

    /// # Errors
    /// Returns [`SdkError::LocalBusPermissionDenied`] when the peer is not `expected`.
    fn matches_peer(&self, expected: PeerCred) -> Result<(), SdkError>;
}

impl BusStream for LocalSocketStream {
    type ReadHalf = tokio::net::unix::OwnedReadHalf;
    type WriteHalf = tokio::net::unix::OwnedWriteHalf;

    fn into_halves(self) -> (Self::ReadHalf, Self::WriteHalf) {
        self.into_split()
    }

    fn matches_peer(&self, expected: PeerCred) -> Result<(), SdkError> {
        fs::verify_peer_uid(self, expected.unix_uid)
    }
}

pub(crate) trait BusListener: Sized {
    type Stream: BusStream + 'static;

    /// # Errors
    /// Returns an error when the carrier cannot be bound or its owner-only mode cannot be set.
    fn bind(path: &Path) -> Result<Self, SdkError>;

    /// # Errors
    /// Returns an error when the bound socket's owner cannot be read.
    fn owner(&self) -> Result<PeerCred, SdkError>;

    /// # Errors
    /// Returns an error when accepting a connection fails.
    async fn accept(&self) -> std::io::Result<Self::Stream>;

    /// Bound endpoint. Carriers without a filesystem identity return `None`.
    ///
    /// # Errors
    /// Returns an error when the local address or its file identity cannot be read.
    fn endpoint(&self) -> Result<Option<EndpointId>, SdkError>;
}

/// Bind the Unix pathname listener and set mode 0o600.
///
/// # Errors
/// Returns an error when the socket cannot be bound or the mode cannot be set.
pub(crate) fn bind(path: &Path) -> Result<UnixBusListener, SdkError> {
    <UnixBusListener as BusListener>::bind(path)
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

    fn owner(&self) -> Result<PeerCred, SdkError> {
        Ok(PeerCred { unix_uid: fs::file_owner_uid(&self.path)? })
    }

    async fn accept(&self) -> std::io::Result<Self::Stream> {
        let (stream, _) = self.inner.accept().await?;
        Ok(stream)
    }

    fn endpoint(&self) -> Result<Option<EndpointId>, SdkError> {
        use std::os::unix::fs::MetadataExt;
        let address = self.inner.local_addr()?;
        let Some(path) = address.as_pathname() else {
            return Ok(None);
        };
        let metadata = std::fs::metadata(path)?;
        Ok(Some(EndpointId {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        }))
    }
}

/// # Errors
/// Returns an error when the Unix socket cannot be connected.
pub(crate) async fn connect(path: impl AsRef<Path>) -> Result<LocalSocketStream, SdkError> {
    Ok(LocalSocketStream::connect(path).await?)
}

/// Listener and stream with no Unix types. The core accept loop is instantiated against it in tests.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct StubListener;

#[cfg(test)]
pub(crate) struct StubStream;

#[cfg(test)]
impl BusStream for StubStream {
    type ReadHalf = tokio::io::Empty;
    type WriteHalf = tokio::io::Sink;

    fn into_halves(self) -> (Self::ReadHalf, Self::WriteHalf) {
        (tokio::io::empty(), tokio::io::sink())
    }

    fn matches_peer(&self, _expected: PeerCred) -> Result<(), SdkError> {
        Ok(())
    }
}

#[cfg(test)]
impl BusListener for StubListener {
    type Stream = StubStream;

    fn bind(_path: &Path) -> Result<Self, SdkError> {
        Ok(Self)
    }

    fn owner(&self) -> Result<PeerCred, SdkError> {
        Ok(PeerCred { unix_uid: 0 })
    }

    fn accept(&self) -> impl Future<Output = std::io::Result<Self::Stream>> {
        std::future::ready(Ok(StubStream))
    }

    fn endpoint(&self) -> Result<Option<EndpointId>, SdkError> {
        Ok(None)
    }
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
        let owner = listener.owner().map_err(|err| err.to_string())?;
        let file_uid = std::fs::metadata(&path).map_err(|err| err.to_string())?.uid();
        let uid = owner.unix_uid;
        if uid != file_uid {
            return Err(format!("listener uid {uid} != file uid {file_uid}"));
        }
        let _client = connect(&path).await.map_err(|err| err.to_string())?;
        let accepted = listener.accept().await.map_err(|err| err.to_string())?;
        accepted.matches_peer(owner).map_err(|err| err.to_string())?;
        let other = PeerCred { unix_uid: owner.unix_uid.wrapping_add(1) };
        match accepted.matches_peer(other) {
            Err(SdkError::LocalBusPermissionDenied) => {}
            Ok(()) => return Err("a different uid was accepted".to_owned()),
            Err(error) => return Err(error.to_string()),
        }
        let Some(endpoint) = listener.endpoint().map_err(|err| err.to_string())? else {
            return Err("pathname socket had no path".to_owned());
        };
        if !fs::same_device_inode(&endpoint.path, endpoint.device, endpoint.inode)
            .map_err(|err| err.to_string())?
        {
            return Err("listener identity did not match the bound socket".to_owned());
        }
        Ok(())
    }
}
