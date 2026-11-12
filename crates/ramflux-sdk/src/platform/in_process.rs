// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-process local-bus carrier. It has no socket and no path: a host thread hands one end
//! of a bounded byte pipe to the supervisor thread. The frame codec, the peer check seam and
//! the admission path are the ones the socket carrier uses.

use std::path::Path;

use tokio::io::DuplexStream;
use tokio::sync::{Mutex, mpsc};

use crate::SdkError;
use crate::platform::listener::{BusListener, BusStream, EndpointId, PeerCred};

/// Pipe buffer per direction. A full pipe applies backpressure; it never drops a frame.
const PIPE_BYTES: usize = 64 * 1024;
/// Connections waiting for the supervisor to accept them.
const PENDING_CONNECTIONS: usize = 16;

/// Supervisor end of one in-process connection.
pub(crate) struct InProcessStream(DuplexStream);

impl BusStream for InProcessStream {
    type ReadHalf = tokio::io::ReadHalf<DuplexStream>;
    type WriteHalf = tokio::io::WriteHalf<DuplexStream>;

    fn into_halves(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self.0)
    }

    /// The pipe is created inside this process and is never reachable from another one.
    fn matches_peer(&self, _expected: PeerCred) -> Result<(), SdkError> {
        Ok(())
    }
}

/// Accept side, owned by the supervisor thread.
pub(crate) struct InProcessListener {
    incoming: Mutex<mpsc::Receiver<InProcessStream>>,
}

/// Connect side, owned by the host handle.
#[derive(Clone)]
pub(crate) struct InProcessConnector {
    outgoing: mpsc::Sender<InProcessStream>,
}

/// Create the two ends of an in-process carrier.
pub(crate) fn pair() -> (InProcessConnector, InProcessListener) {
    let (outgoing, incoming) = mpsc::channel(PENDING_CONNECTIONS);
    (InProcessConnector { outgoing }, InProcessListener { incoming: Mutex::new(incoming) })
}

impl InProcessConnector {
    /// Open one connection and return the host end.
    ///
    /// # Errors
    /// Returns an error when the supervisor is gone or its accept queue is full.
    pub(crate) fn connect(&self) -> Result<DuplexStream, SdkError> {
        let (host, supervisor) = tokio::io::duplex(PIPE_BYTES);
        self.outgoing.try_send(InProcessStream(supervisor)).map_err(|_| {
            SdkError::LocalBus("in-process carrier is not accepting connections".to_owned())
        })?;
        Ok(host)
    }
}

impl BusListener for InProcessListener {
    type Stream = InProcessStream;

    fn bind(_path: &Path) -> Result<Self, SdkError> {
        Err(SdkError::LocalBus("the in-process carrier has no address to bind".to_owned()))
    }

    fn owner(&self) -> Result<PeerCred, SdkError> {
        Ok(PeerCred::current_process())
    }

    async fn accept(&self) -> std::io::Result<Self::Stream> {
        match self.incoming.lock().await.recv().await {
            Some(stream) => Ok(stream),
            // Every connector is gone. The supervisor leaves through its shutdown signal,
            // not through an accept error.
            None => std::future::pending().await,
        }
    }

    fn endpoint(&self) -> Result<Option<EndpointId>, SdkError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn connected_pipe_carries_bytes_both_ways() -> Result<(), String> {
        let (connector, listener) = pair();
        let mut host = connector.connect().map_err(|error| error.to_string())?;
        let accepted = listener.accept().await.map_err(|error| error.to_string())?;
        let owner = listener.owner().map_err(|error| error.to_string())?;
        accepted.matches_peer(owner).map_err(|error| error.to_string())?;
        let (mut reader, mut writer) = accepted.into_halves();
        host.write_all(b"ping").await.map_err(|error| error.to_string())?;
        let mut request = [0_u8; 4];
        reader.read_exact(&mut request).await.map_err(|error| error.to_string())?;
        writer.write_all(b"pong").await.map_err(|error| error.to_string())?;
        let mut response = [0_u8; 4];
        host.read_exact(&mut response).await.map_err(|error| error.to_string())?;
        if &request != b"ping" || &response != b"pong" {
            return Err("pipe changed the bytes".to_owned());
        }
        Ok(())
    }

    #[tokio::test]
    async fn carrier_has_no_filesystem_endpoint_and_cannot_be_bound() -> Result<(), String> {
        let (_connector, listener) = pair();
        if listener.endpoint().map_err(|error| error.to_string())?.is_some() {
            return Err("in-process carrier reported a filesystem endpoint".to_owned());
        }
        match <InProcessListener as BusListener>::bind(Path::new("/unused")) {
            Err(SdkError::LocalBus(_)) => Ok(()),
            Ok(_) => Err("in-process carrier was bound to a path".to_owned()),
            Err(error) => Err(error.to_string()),
        }
    }

    #[tokio::test]
    async fn connect_fails_after_the_supervisor_end_is_dropped() -> Result<(), String> {
        let (connector, listener) = pair();
        drop(listener);
        match connector.connect() {
            Err(SdkError::LocalBus(_)) => Ok(()),
            Ok(_) => Err("connect succeeded without a supervisor".to_owned()),
            Err(error) => Err(error.to_string()),
        }
    }
}
