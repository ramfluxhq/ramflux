// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;
use std::{future::Future, io};

use crate::tls_config::quic_gateway_client_config;
use crate::{GatewayQuicRequest, GatewayQuicResponse, TransportError};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;

const MAX_QUIC_FRAME_BYTES: usize = 1024 * 1024;

pub type GatewaySessionFrameFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

pub trait GatewaySessionFrameSink {
    /// # Errors
    /// Returns an error when the frame is too large or cannot be written to the transport.
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()>;

    /// # Errors
    /// Returns an error when the transport cannot be closed cleanly.
    fn finish(&mut self) -> Result<(), TransportError>;
}

pub trait GatewaySessionFrameSource {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>>;
}

pub trait GatewaySessionTransport: GatewaySessionFrameSink + GatewaySessionFrameSource {}

impl<T> GatewaySessionTransport for T where T: GatewaySessionFrameSink + GatewaySessionFrameSource {}

pub struct QuicGatewayClient {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    timeout: Duration,
}

/// Structured outcome of a pooled connect attempt (see [`QuicGatewayClient::connect_pooled`]). A
/// handshake timeout is distinguished from a handshake failure at the source, not by string
/// matching. quinn does not expose a stable, machine-readable "peer authentication failed" reason
/// separate from other transport-layer handshake failures, so a non-timeout handshake failure is
/// reported uniformly as [`QuicConnectPhase::HandshakeFailed`] rather than guessed from text.
#[derive(Debug)]
pub enum QuicConnectPhase {
    /// Endpoint bind or client-config setup failed before any handshake began.
    Setup(String),
    /// The handshake did not complete within the configured deadline.
    HandshakeTimeout,
    /// The handshake failed (peer unreachable, TLS/cert rejection, transport error).
    HandshakeFailed(String),
}

/// Structured outcome of a pooled request (see [`QuicGatewayClient::request_pooled`]).
#[derive(Debug)]
pub enum QuicRequestPhase {
    /// The request did not receive a complete application response within the deadline.
    RequestTimeout,
    /// The stream/connection failed with no complete application response received.
    ConnectionLost(String),
    /// A complete frame was received but could not be decoded — not a business response.
    Protocol(String),
}

fn quic_request_phase_from_transport(error: TransportError) -> QuicRequestPhase {
    match error {
        TransportError::Codec(codec) => {
            QuicRequestPhase::Protocol(format!("response decode: {codec}"))
        }
        TransportError::FrameTooLarge { len } => {
            QuicRequestPhase::Protocol(format!("response frame too large: {len} bytes"))
        }
        other => QuicRequestPhase::ConnectionLost(other.to_string()),
    }
}

pub struct QuicGatewayBidiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    timeout: Duration,
}

pub type GatewayTcpTlsStream = tokio_rustls::TlsStream<TcpStream>;

pub struct TcpTlsGatewayClient;

pub struct TcpTlsGatewayBidiStream {
    stream: GatewayTcpTlsStream,
    timeout: Duration,
}

impl QuicGatewayClient {
    /// # Errors
    /// Returns an error when the UDP socket, TLS config, or QUIC handshake fails.
    pub async fn connect(
        bind_addr: SocketAddr,
        peer_addr: SocketAddr,
        server_name: &str,
        ca_cert: &Path,
        timeout: Duration,
    ) -> Result<Self, TransportError> {
        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(quic_gateway_client_config(ca_cert)?);
        let connecting = endpoint
            .connect(peer_addr, server_name)
            .map_err(|error| TransportError::Quic(error.to_string()))?;
        let connection = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|error| TransportError::Quic(error.to_string()))?
            .map_err(|error| TransportError::Quic(error.to_string()))?;
        Ok(Self { _endpoint: endpoint, connection, timeout })
    }

    /// Connects with an explicit, pre-built quinn client config and separate handshake/request
    /// timeouts, returning a **structured** [`QuicConnectPhase`] on failure instead of a stringly
    /// `TransportError`. A handshake deadline is reported as [`QuicConnectPhase::HandshakeTimeout`]
    /// directly from the `tokio::time::timeout` `Elapsed` (never inferred from an error message).
    /// Used by the relay QUIC connection pool, which supplies a config that sets
    /// `max_idle_timeout`/`keep_alive_interval` so a pooled connection does not silently idle out
    /// between reuses.
    ///
    /// # Errors
    /// Returns a typed [`QuicConnectPhase`] distinguishing setup (bind/config), handshake timeout,
    /// and handshake failure.
    pub async fn connect_pooled(
        bind_addr: SocketAddr,
        peer_addr: SocketAddr,
        server_name: &str,
        client_config: quinn::ClientConfig,
        handshake_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, QuicConnectPhase> {
        let mut endpoint = quinn::Endpoint::client(bind_addr)
            .map_err(|error| QuicConnectPhase::Setup(error.to_string()))?;
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(peer_addr, server_name)
            .map_err(|error| QuicConnectPhase::Setup(error.to_string()))?;
        match tokio::time::timeout(handshake_timeout, connecting).await {
            Err(_elapsed) => Err(QuicConnectPhase::HandshakeTimeout),
            Ok(Err(error)) => Err(QuicConnectPhase::HandshakeFailed(error.to_string())),
            Ok(Ok(connection)) => {
                Ok(Self { _endpoint: endpoint, connection, timeout: request_timeout })
            }
        }
    }

    /// Sends a single request, returning a **structured** [`QuicRequestPhase`] on failure. A
    /// request deadline is [`QuicRequestPhase::RequestTimeout`] taken directly from the timeout
    /// `Elapsed` (no string parsing); a decode failure is [`QuicRequestPhase::Protocol`] (a
    /// complete-but-invalid frame, never a business response); any other stream/connection error
    /// is [`QuicRequestPhase::ConnectionLost`] (no complete application response). Used by the pool
    /// so its typed error contract does not depend on quinn's error wording.
    ///
    /// # Errors
    /// Returns a typed [`QuicRequestPhase`].
    pub async fn request_pooled(
        &self,
        request: &GatewayQuicRequest,
    ) -> Result<GatewayQuicResponse, QuicRequestPhase> {
        match tokio::time::timeout(self.timeout, async {
            let (mut send, mut recv) = self
                .connection
                .open_bi()
                .await
                .map_err(|error| QuicRequestPhase::ConnectionLost(error.to_string()))?;
            write_quic_json_frame(&mut send, request)
                .await
                .map_err(quic_request_phase_from_transport)?;
            read_quic_json_frame(&mut recv).await.map_err(quic_request_phase_from_transport)
        })
        .await
        {
            Ok(inner) => inner,
            Err(_elapsed) => Err(QuicRequestPhase::RequestTimeout),
        }
    }

    pub fn set_session_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Returns `true` while the underlying QUIC connection has not been closed (locally or by the
    /// peer / idle timeout). The relay pool checks this before reusing a cached connection.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// The quinn stable connection id, for observability (never carries token/grant material).
    #[must_use]
    pub fn stable_id(&self) -> usize {
        self.connection.stable_id()
    }

    /// The peer socket address of the underlying QUIC connection.
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Actively closes the underlying QUIC connection. The relay pool calls this when it evicts a
    /// connection after a transport failure so the old connection cannot be reused.
    pub fn close(&self) {
        self.connection.close(quinn::VarInt::from_u32(0), b"relay pool evict");
    }

    /// # Errors
    /// Returns an error when a QUIC stream cannot exchange a complete gateway request/response.
    pub async fn request(
        &self,
        request: &GatewayQuicRequest,
    ) -> Result<GatewayQuicResponse, TransportError> {
        tokio::time::timeout(self.timeout, async {
            let (mut send, mut recv) = self
                .connection
                .open_bi()
                .await
                .map_err(|error| TransportError::Quic(error.to_string()))?;
            write_quic_json_frame(&mut send, request).await?;
            read_quic_json_frame(&mut recv).await
        })
        .await
        .map_err(|error| TransportError::Quic(error.to_string()))?
    }

    /// # Errors
    /// Returns an error when the gateway cannot open a bidirectional QUIC stream.
    pub async fn open_bidi_stream(&self) -> Result<QuicGatewayBidiStream, TransportError> {
        let (send, recv) = tokio::time::timeout(self.timeout, self.connection.open_bi())
            .await
            .map_err(|error| TransportError::Quic(error.to_string()))?
            .map_err(|error| TransportError::Quic(error.to_string()))?;
        Ok(QuicGatewayBidiStream { send, recv, timeout: self.timeout })
    }

    /// # Errors
    /// Returns an error when the POST request fails or the response cannot be decoded.
    pub async fn post_json<T, R>(&self, path: &str, value: &T) -> Result<R, TransportError>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let response = self
            .request(&GatewayQuicRequest {
                method: "POST".to_owned(),
                path: path.to_owned(),
                body: serde_json::to_value(value)?,
            })
            .await?;
        decode_quic_gateway_response(response)
    }

    /// # Errors
    /// Returns an error when the GET request fails or the response cannot be decoded.
    pub async fn get_json<R>(&self, path: &str) -> Result<R, TransportError>
    where
        R: serde::de::DeserializeOwned,
    {
        let response = self
            .request(&GatewayQuicRequest {
                method: "GET".to_owned(),
                path: path.to_owned(),
                body: serde_json::Value::Null,
            })
            .await?;
        decode_quic_gateway_response(response)
    }
}

/// Validated connection parameters for a client reaching a relay client-facing QUIC surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayClientQuicConfig {
    pub peer_addr: SocketAddr,
    pub server_name: String,
    pub ca_cert: PathBuf,
}

impl RelayClientQuicConfig {
    /// Validates the relay client QUIC connection parameters, failing closed on a malformed peer
    /// address, an empty server name, or a missing CA certificate file. Full CA parsing happens at
    /// connect time (also fail-closed).
    ///
    /// # Errors
    /// Returns an error when the peer address is malformed, the server name is empty, or the CA
    /// certificate file does not exist.
    pub fn new(
        peer_addr: &str,
        server_name: &str,
        ca_cert: impl Into<PathBuf>,
    ) -> Result<Self, TransportError> {
        let parsed = peer_addr.trim().parse::<SocketAddr>().map_err(|error| {
            TransportError::Quic(format!(
                "invalid relay client QUIC peer address {peer_addr:?}: {error}"
            ))
        })?;
        let server_name = server_name.trim();
        if server_name.is_empty() {
            return Err(TransportError::Quic(
                "relay client QUIC server name must not be empty".to_owned(),
            ));
        }
        let ca_cert = ca_cert.into();
        if !ca_cert.is_file() {
            return Err(TransportError::Quic(format!(
                "relay client QUIC CA certificate not found: {}",
                ca_cert.display()
            )));
        }
        Ok(Self { peer_addr: parsed, server_name: server_name.to_owned(), ca_cert })
    }
}

pub(crate) fn relay_client_quic_bind_addr(peer_addr: SocketAddr) -> SocketAddr {
    if peer_addr.is_ipv6() {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
    }
}

/// Performs a health probe against a relay client-facing QUIC surface, reusing the gateway QUIC
/// client primitives (`quic_gateway_client_config` + server-auth connect + JSON request frames).
/// This is a control-plane probe only: it carries no object data and no relay token, and it never
/// falls back to plaintext HTTP.
///
/// # Errors
/// Returns an error when the connection, TLS handshake, or health request/response fails.
pub async fn relay_client_quic_health(
    config: &RelayClientQuicConfig,
    timeout: Duration,
) -> Result<GatewayQuicResponse, TransportError> {
    let bind_addr = relay_client_quic_bind_addr(config.peer_addr);
    let client = QuicGatewayClient::connect(
        bind_addr,
        config.peer_addr,
        &config.server_name,
        &config.ca_cert,
        timeout,
    )
    .await?;
    client
        .request(&GatewayQuicRequest {
            method: "GET".to_owned(),
            path: "/healthz".to_owned(),
            body: serde_json::Value::Null,
        })
        .await
}

impl TcpTlsGatewayClient {
    /// # Errors
    /// Returns an error when the TCP socket, TLS config, or TLS handshake fails.
    pub async fn connect(
        bind_addr: SocketAddr,
        peer_addr: SocketAddr,
        server_name: &str,
        ca_cert: &Path,
        timeout: Duration,
    ) -> Result<(Self, TcpTlsGatewayBidiStream), TransportError> {
        let socket = if peer_addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        socket.bind(bind_addr)?;
        let tcp =
            tokio::time::timeout(timeout, socket.connect(peer_addr)).await.map_err(|error| {
                TransportError::Io(io::Error::new(io::ErrorKind::TimedOut, error))
            })??;
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|error| TransportError::Tls(error.to_string()))?;
        let connector = TlsConnector::from(std::sync::Arc::new(
            crate::tls_config::tcp_gateway_client_config(ca_cert)?,
        ));
        let stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
            .await
            .map_err(|error| TransportError::Io(io::Error::new(io::ErrorKind::TimedOut, error)))?
            .map_err(|error| TransportError::Tls(error.to_string()))?;
        Ok((
            Self,
            TcpTlsGatewayBidiStream { stream: tokio_rustls::TlsStream::Client(stream), timeout },
        ))
    }
}

impl QuicGatewayBidiStream {
    /// # Errors
    /// Returns an error when the frame cannot be serialized or written to the QUIC stream.
    pub async fn write_json_message<T>(&mut self, value: &T) -> Result<(), TransportError>
    where
        T: serde::Serialize,
    {
        let body = serde_json::to_vec(value)?;
        self.send_frame(&body).await
    }

    /// # Errors
    /// Returns an error when the frame cannot be read or decoded from the QUIC stream.
    pub async fn read_json_frame<T>(&mut self) -> Result<T, TransportError>
    where
        T: serde::de::DeserializeOwned,
    {
        let body = self.recv_frame().await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// # Errors
    /// Returns an error when the QUIC send stream cannot be gracefully finished.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        GatewaySessionFrameSink::finish(self)
    }
}

impl TcpTlsGatewayBidiStream {
    #[must_use]
    pub fn split(self) -> (ReadHalf<GatewayTcpTlsStream>, WriteHalf<GatewayTcpTlsStream>) {
        tokio::io::split(self.stream)
    }
}

impl GatewaySessionFrameSink for QuicGatewayBidiStream {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, write_quic_raw_frame(&mut self.send, frame))
                .await
                .map_err(|error| TransportError::Quic(error.to_string()))?
        })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        quinn::SendStream::finish(&mut self.send)
            .map_err(|error| TransportError::Quic(error.to_string()))
    }
}

impl GatewaySessionFrameSource for QuicGatewayBidiStream {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, read_quic_raw_frame(&mut self.recv))
                .await
                .map_err(|error| TransportError::Quic(error.to_string()))?
        })
    }
}

impl GatewaySessionFrameSink for TcpTlsGatewayBidiStream {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, write_tcp_raw_frame(&mut self.stream, frame))
                .await
                .map_err(|error| TransportError::Io(io::Error::new(io::ErrorKind::TimedOut, error)))?
        })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for TcpTlsGatewayBidiStream {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, read_tcp_raw_frame(&mut self.stream)).await.map_err(
                |error| TransportError::Io(io::Error::new(io::ErrorKind::TimedOut, error)),
            )?
        })
    }
}

impl GatewaySessionFrameSink for quinn::SendStream {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move { write_quic_raw_frame(self, frame).await })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        quinn::SendStream::finish(self).map_err(|error| TransportError::Quic(error.to_string()))
    }
}

impl GatewaySessionFrameSource for quinn::RecvStream {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move { read_quic_raw_frame(self).await })
    }
}

impl GatewaySessionFrameSink for WriteHalf<GatewayTcpTlsStream> {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move { write_tcp_raw_frame(self, frame).await })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for ReadHalf<GatewayTcpTlsStream> {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move { read_tcp_raw_frame(self).await })
    }
}

/// # Errors
/// Returns an error when serialization fails or the frame cannot be written to the transport.
pub async fn write_gateway_session_json<T>(
    sink: &mut (impl GatewaySessionFrameSink + ?Sized),
    value: &T,
) -> Result<(), TransportError>
where
    T: serde::Serialize,
{
    let body = serde_json::to_vec(value)?;
    sink.send_frame(&body).await
}

/// # Errors
/// Returns an error when the frame cannot be read or the JSON payload cannot be decoded.
pub async fn read_gateway_session_json<T>(
    source: &mut (impl GatewaySessionFrameSource + ?Sized),
) -> Result<T, TransportError>
where
    T: serde::de::DeserializeOwned,
{
    let body = source.recv_frame().await?;
    Ok(serde_json::from_slice(&body)?)
}
/// # Errors
/// Returns an error when the frame cannot be serialized or written to the QUIC stream.
pub async fn write_quic_json_frame<T>(
    send: &mut quinn::SendStream,
    value: &T,
) -> Result<(), TransportError>
where
    T: serde::Serialize,
{
    write_gateway_session_json(send, value).await?;
    GatewaySessionFrameSink::finish(send)?;
    Ok(())
}

/// # Errors
/// Returns an error when the frame cannot be serialized or written to the QUIC stream.
pub async fn write_quic_json_message<T>(
    send: &mut quinn::SendStream,
    value: &T,
) -> Result<(), TransportError>
where
    T: serde::Serialize,
{
    let body = serde_json::to_vec(value)?;
    write_quic_raw_frame(send, &body).await
}

/// # Errors
/// Returns an error when the QUIC stream frame is malformed, too large, or invalid JSON.
pub async fn read_quic_json_frame<T>(recv: &mut quinn::RecvStream) -> Result<T, TransportError>
where
    T: serde::de::DeserializeOwned,
{
    let body = read_quic_raw_frame(recv).await?;
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) async fn write_quic_raw_frame(
    send: &mut quinn::SendStream,
    frame: &[u8],
) -> Result<(), TransportError> {
    let len = u32::try_from(frame.len())
        .map_err(|_error| TransportError::FrameTooLarge { len: frame.len() })?;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|error| TransportError::Quic(error.to_string()))?;
    send.write_all(frame).await.map_err(|error| TransportError::Quic(error.to_string()))?;
    Ok(())
}

pub(crate) async fn read_quic_raw_frame(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<u8>, TransportError> {
    tracing::trace!("quinn QUIC reading JSON frame length");
    let mut len_bytes = [0_u8; 4];
    recv.read_exact(&mut len_bytes).await.map_err(|error| match error {
        quinn::ReadExactError::ReadError(error) => TransportError::Quic(error.to_string()),
        quinn::ReadExactError::FinishedEarly(size) => TransportError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("gateway frame ended after {size} bytes"),
        )),
    })?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_QUIC_FRAME_BYTES {
        return Err(TransportError::FrameTooLarge { len });
    }
    tracing::trace!(len, "quinn QUIC reading JSON frame body");
    let mut body = vec![0_u8; len];
    recv.read_exact(&mut body).await.map_err(|error| match error {
        quinn::ReadExactError::ReadError(error) => TransportError::Quic(error.to_string()),
        quinn::ReadExactError::FinishedEarly(size) => TransportError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("gateway frame ended after {size} of {len} bytes"),
        )),
    })?;
    Ok(body)
}

async fn write_tcp_raw_frame<W>(send: &mut W, frame: &[u8]) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let len = u32::try_from(frame.len())
        .map_err(|_error| TransportError::FrameTooLarge { len: frame.len() })?;
    send.write_all(&len.to_be_bytes()).await.map_err(TransportError::Io)?;
    send.write_all(frame).await.map_err(TransportError::Io)?;
    send.flush().await.map_err(TransportError::Io)
}

async fn read_tcp_raw_frame<R>(recv: &mut R) -> Result<Vec<u8>, TransportError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut len_bytes = [0_u8; 4];
    recv.read_exact(&mut len_bytes).await.map_err(TransportError::Io)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_QUIC_FRAME_BYTES {
        return Err(TransportError::FrameTooLarge { len });
    }
    let mut body = vec![0_u8; len];
    recv.read_exact(&mut body).await.map_err(TransportError::Io)?;
    Ok(body)
}

fn decode_quic_gateway_response<T>(response: GatewayQuicResponse) -> Result<T, TransportError>
where
    T: serde::de::DeserializeOwned,
{
    if (200..300).contains(&response.status) {
        Ok(serde_json::from_value(response.body)?)
    } else {
        Err(TransportError::Quic(format!(
            "gateway QUIC status {}: {}",
            response.status, response.body
        )))
    }
}

#[cfg(test)]
mod relay_client_quic_config_tests {
    use super::RelayClientQuicConfig;
    use std::io::Write as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn temp_ca_file() -> Result<std::path::PathBuf, std::io::Error> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir()
            .join(format!("ramflux-relay-client-ca-{}-{nanos}.pem", std::process::id()));
        let mut file = std::fs::File::create(&path)?;
        file.write_all(b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")?;
        Ok(path)
    }

    #[test]
    fn accepts_valid_parameters() -> TestResult {
        let ca = temp_ca_file()?;
        let config = RelayClientQuicConfig::new("127.0.0.1:17447", " ramflux-relay ", &ca)?;
        assert_eq!(config.peer_addr.port(), 17447);
        assert_eq!(config.server_name, "ramflux-relay");
        assert_eq!(config.ca_cert, ca);
        let _ = std::fs::remove_file(ca);
        Ok(())
    }

    #[test]
    fn rejects_malformed_peer_address() -> TestResult {
        let ca = temp_ca_file()?;
        assert!(RelayClientQuicConfig::new("not-an-address", "ramflux-relay", &ca).is_err());
        assert!(RelayClientQuicConfig::new("", "ramflux-relay", &ca).is_err());
        let _ = std::fs::remove_file(ca);
        Ok(())
    }

    #[test]
    fn rejects_empty_server_name() -> TestResult {
        let ca = temp_ca_file()?;
        assert!(RelayClientQuicConfig::new("127.0.0.1:17447", "   ", &ca).is_err());
        let _ = std::fs::remove_file(ca);
        Ok(())
    }

    #[test]
    fn rejects_missing_ca_certificate() {
        assert!(
            RelayClientQuicConfig::new(
                "127.0.0.1:17447",
                "ramflux-relay",
                "/nonexistent/relay-client-ca.pem",
            )
            .is_err()
        );
    }
}
