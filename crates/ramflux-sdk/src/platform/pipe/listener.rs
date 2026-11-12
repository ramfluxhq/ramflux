// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local-bus listener and client over a Windows named pipe. Same seam as the Unix listener:
//! the frame codec and its limits are the callers', only the byte stream and the peer check
//! differ. Identity is the token's user SID; a process id is never used for authorization.

use std::ffi::{OsStr, OsString};
#[cfg(test)]
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer};

use super::name;
use super::win32::{self, MEDIUM_INTEGRITY_RID, SecurityDescriptor, Sid, TokenFacts};
use crate::SdkError;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_PIPE_BUSY: i32 = 231;
const ERROR_NO_DATA: i32 = 232;
const BUSY_RETRY: Duration = Duration::from_millis(50);
const BUSY_ATTEMPTS: u32 = 100;

/// Opaque same-user credential. The Windows implementation stores the user SID.
#[derive(Clone, Copy)]
pub(crate) struct PeerCred {
    pub(super) sid: Sid,
}

/// Identity of the published name file: its path and the random part it must still hold.
pub(crate) struct EndpointId {
    path: PathBuf,
    nonce: String,
}

impl EndpointId {
    /// Remove the name file only when it still publishes this listener's pipe.
    ///
    /// # Errors
    /// Returns an error when the file cannot be read or the matching file cannot be removed.
    pub(crate) fn remove_if_unchanged(&self) -> Result<(), SdkError> {
        if name::publishes(&self.path, &self.nonce)? {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

/// Byte stream accepted from a [`BusListener`].
pub(crate) trait BusStream: Sized {
    type ReadHalf: AsyncRead + Unpin + 'static;
    type WriteHalf: AsyncWrite + Unpin + 'static;

    fn into_halves(self) -> (Self::ReadHalf, Self::WriteHalf);

    /// # Errors
    /// Returns [`SdkError::LocalBusPermissionDenied`] when the peer is not `expected`.
    fn matches_peer(&self, expected: PeerCred) -> Result<(), SdkError>;
}

pub(crate) trait BusListener: Sized {
    type Stream: BusStream + 'static;

    /// # Errors
    /// Returns an error when the carrier cannot be bound or its owner-only access cannot be set.
    fn bind(path: &Path) -> Result<Self, SdkError>;

    /// # Errors
    /// Returns an error when the listener's owner cannot be read.
    fn owner(&self) -> Result<PeerCred, SdkError>;

    /// # Errors
    /// Returns an error when accepting a connection fails.
    async fn accept(&self) -> std::io::Result<Self::Stream>;

    /// Bound endpoint. Carriers without a filesystem identity return `None`.
    ///
    /// # Errors
    /// Returns an error when the endpoint identity cannot be read.
    fn endpoint(&self) -> Result<Option<EndpointId>, SdkError>;
}

/// The server-side rule: same user SID, not an AppContainer, medium integrity or higher.
/// An elevated process of the same user has the same SID and is accepted.
pub(super) fn authorize(client: &TokenFacts, owner: &Sid) -> Result<(), SdkError> {
    if client.user == *owner
        && !client.app_container
        && client.integrity_rid >= MEDIUM_INTEGRITY_RID
    {
        Ok(())
    } else {
        Err(SdkError::LocalBusPermissionDenied)
    }
}

/// Server end of one connected pipe instance.
pub(crate) struct PipeServerStream {
    inner: NamedPipeServer,
}

impl BusStream for PipeServerStream {
    type ReadHalf = ReadHalf<NamedPipeServer>;
    type WriteHalf = WriteHalf<NamedPipeServer>;

    fn into_halves(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self.inner)
    }

    fn matches_peer(&self, expected: PeerCred) -> Result<(), SdkError> {
        // A client whose token cannot be read is refused, not trusted.
        let client = win32::client_facts(&self.inner).map_err(|error| {
            tracing::debug!(%error, "local bus client token could not be read");
            SdkError::LocalBusPermissionDenied
        })?;
        authorize(&client, &expected.sid)
    }
}

/// Client end of the pipe, returned only after the server was verified.
pub(crate) struct PipeClientStream {
    inner: NamedPipeClient,
}

impl PipeClientStream {
    #[must_use]
    pub(crate) fn into_split(self) -> (ReadHalf<NamedPipeClient>, WriteHalf<NamedPipeClient>) {
        tokio::io::split(self.inner)
    }
}

impl AsyncRead for PipeClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PipeClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Bind the per-user pipe and publish its name in the owner-only file at `path`.
///
/// # Errors
/// Returns [`SdkError::DataRootInUse`] when the pipe name already exists, and an error when the
/// pipe or the name file cannot be created.
pub(crate) fn bind(path: &Path) -> Result<PipeBusListener, SdkError> {
    <PipeBusListener as BusListener>::bind(path)
}

pub(crate) struct PipeBusListener {
    name: OsString,
    descriptor: SecurityDescriptor,
    owner: Sid,
    /// The instance waiting for the next client. One always exists while the listener lives,
    /// so the name never becomes free for another process to create.
    pending: tokio::sync::Mutex<NamedPipeServer>,
    name_file: Option<(PathBuf, String)>,
}

impl PipeBusListener {
    /// Create the first instance of `name`. An existing name is never opened or reused.
    ///
    /// # Errors
    /// Returns [`SdkError::DataRootInUse`] when the name already exists.
    pub(super) fn create(name: OsString, user_sid: &str, owner: Sid) -> Result<Self, SdkError> {
        let descriptor = SecurityDescriptor::from_sddl(&name::pipe_sddl(user_sid))?;
        let first = win32::create_instance(&name, &descriptor, true).map_err(|error| {
            if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
                SdkError::DataRootInUse
            } else {
                SdkError::from(error)
            }
        })?;
        Ok(Self {
            name,
            descriptor,
            owner,
            pending: tokio::sync::Mutex::new(first),
            name_file: None,
        })
    }

    #[cfg(test)]
    pub(super) fn name(&self) -> &OsStr {
        &self.name
    }
}

impl BusListener for PipeBusListener {
    type Stream = PipeServerStream;

    fn bind(path: &Path) -> Result<Self, SdkError> {
        let me = win32::process_facts()?;
        let user_sid = me.user.to_sddl_string()?;
        let nonce = name::fresh_nonce()?;
        let file_descriptor = SecurityDescriptor::from_sddl(&name::name_file_sddl(&user_sid))?;
        let mut listener = Self::create(name::pipe_name(&user_sid, &nonce)?, &user_sid, me.user)?;
        // The name is published only after the pipe exists, so a reader never races the bind.
        name::write_name_file(path, &file_descriptor, &nonce)?;
        listener.name_file = Some((path.to_path_buf(), nonce));
        Ok(listener)
    }

    fn owner(&self) -> Result<PeerCred, SdkError> {
        Ok(PeerCred { sid: self.owner })
    }

    async fn accept(&self) -> std::io::Result<Self::Stream> {
        let mut pending = self.pending.lock().await;
        loop {
            match pending.connect().await {
                Ok(()) => break,
                // The client opened and closed before the connect: recycle the instance.
                Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA) => {
                    pending.disconnect()?
                }
                Err(error) => return Err(error),
            }
        }
        // The next instance is created before the connected one leaves the listener.
        let next = win32::create_instance(&self.name, &self.descriptor, false)?;
        Ok(PipeServerStream { inner: std::mem::replace(&mut *pending, next) })
    }

    fn endpoint(&self) -> Result<Option<EndpointId>, SdkError> {
        Ok(self
            .name_file
            .as_ref()
            .map(|(path, nonce)| EndpointId { path: path.clone(), nonce: nonce.clone() }))
    }
}

/// Refuse a pipe that this user's daemon did not create. Runs before the first frame is sent.
fn verify_server(pipe: &NamedPipeClient, expected: &Sid) -> Result<(), SdkError> {
    let owner = win32::pipe_owner(pipe).map_err(|_| SdkError::LocalBusPermissionDenied)?;
    if owner != *expected {
        return Err(SdkError::LocalBusPermissionDenied);
    }
    // OPEN-VALUE: the design names only the owner SID. The server process token is checked as
    // well, and a server whose token cannot be read is refused.
    let server =
        win32::server_process_user(pipe).map_err(|_| SdkError::LocalBusPermissionDenied)?;
    if server == *expected { Ok(()) } else { Err(SdkError::LocalBusPermissionDenied) }
}

/// Open `name` at identification level and verify the server before returning the stream.
///
/// # Errors
/// Returns [`SdkError::LocalBusPermissionDenied`] when the pipe is not owned by `expected`.
pub(super) async fn connect_named(
    name: &OsStr,
    expected: &Sid,
) -> Result<PipeClientStream, SdkError> {
    let mut attempts = 0_u32;
    let pipe = loop {
        match win32::open_client(name) {
            Ok(pipe) => break pipe,
            Err(error)
                if error.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < BUSY_ATTEMPTS =>
            {
                attempts += 1;
                tokio::time::sleep(BUSY_RETRY).await;
            }
            // A published name with no pipe behind it is a stopped daemon, like a stale socket.
            Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                return Err(
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, error).into()
                );
            }
            Err(error) => return Err(error.into()),
        }
    };
    verify_server(&pipe, expected)?;
    Ok(PipeClientStream { inner: pipe })
}

/// # Errors
/// Returns an error when the name file cannot be read, the pipe cannot be opened, or the pipe
/// or the name file is not owned by this user.
pub(crate) async fn connect(path: impl AsRef<Path>) -> Result<PipeClientStream, SdkError> {
    let me = win32::process_facts()?.user;
    let nonce = name::read_name_file(path.as_ref(), &me)?;
    let pipe_name = name::pipe_name(&me.to_sddl_string()?, &nonce)?;
    connect_named(&pipe_name, &me).await
}

/// Listener and stream with no pipe behind them. The core accept loop is instantiated against
/// it in tests.
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
        Ok(PeerCred { sid: win32::process_facts()?.user })
    }

    fn accept(&self) -> impl Future<Output = std::io::Result<Self::Stream>> {
        std::future::ready(Ok(StubStream))
    }

    fn endpoint(&self) -> Result<Option<EndpointId>, SdkError> {
        Ok(None)
    }
}
