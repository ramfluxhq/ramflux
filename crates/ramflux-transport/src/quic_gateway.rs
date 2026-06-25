use std::net::SocketAddr;
use std::path::Path;
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

    pub fn set_session_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
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

async fn write_quic_raw_frame(
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

async fn read_quic_raw_frame(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, TransportError> {
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
