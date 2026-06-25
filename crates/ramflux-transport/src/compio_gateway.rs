use std::net::SocketAddr;

use compio_buf::bytes::Bytes;
use serde::{Serialize, de::DeserializeOwned};

use crate::tls_config::compio_quic_gateway_server_config;
use crate::{MeshTlsConfig, TransportError};

const COMP_IO_GATEWAY_FRAME_MAX_BYTES: usize = 1024 * 1024;

pub struct CompioGatewayQuicServer {
    endpoint: compio_quic::Endpoint,
}

pub struct CompioGatewayQuicConnection {
    connection: compio_quic::Connection,
}

pub struct CompioGatewayBidiStream {
    send: compio_quic::SendStream,
    recv: compio_quic::RecvStream,
}

pub struct CompioGatewaySendStream {
    send: compio_quic::SendStream,
}

pub struct CompioGatewayRecvStream {
    recv: compio_quic::RecvStream,
}

impl CompioGatewayQuicServer {
    /// # Errors
    /// Returns an error when the UDP socket cannot bind or the gateway TLS material is invalid.
    pub async fn bind(addr: &str, tls: &MeshTlsConfig) -> Result<Self, TransportError> {
        let endpoint = compio_quic::Endpoint::server(addr, compio_quic_gateway_server_config(tls)?)
            .await
            .map_err(TransportError::Io)?;
        Ok(Self { endpoint })
    }

    /// # Errors
    /// Returns an error when the local UDP address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// # Errors
    /// Returns an error if the endpoint cannot gracefully shut down.
    pub async fn shutdown(self) -> Result<(), TransportError> {
        self.endpoint.shutdown().await.map_err(TransportError::Io)
    }

    /// # Errors
    /// Returns an error when QUIC accept or handshake fails.
    pub async fn accept_connection(&self) -> Result<CompioGatewayQuicConnection, TransportError> {
        let incoming = self.endpoint.wait_incoming().await.ok_or_else(|| {
            TransportError::Quic("compio gateway QUIC endpoint closed".to_owned())
        })?;
        let connection = incoming.await.map_err(|error| TransportError::Quic(error.to_string()))?;
        Ok(CompioGatewayQuicConnection { connection })
    }
}

impl CompioGatewayQuicConnection {
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// # Errors
    /// Returns an error when a bidirectional gateway stream cannot be accepted.
    pub async fn accept_bidi(&self) -> Result<CompioGatewayBidiStream, TransportError> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|error| TransportError::Quic(error.to_string()))?;
        Ok(CompioGatewayBidiStream { send, recv })
    }
}

impl CompioGatewayBidiStream {
    #[must_use]
    pub fn from_streams(send: compio_quic::SendStream, recv: compio_quic::RecvStream) -> Self {
        Self { send, recv }
    }

    #[must_use]
    pub fn split(self) -> (CompioGatewaySendStream, CompioGatewayRecvStream) {
        (CompioGatewaySendStream { send: self.send }, CompioGatewayRecvStream { recv: self.recv })
    }
}

impl CompioGatewaySendStream {
    /// # Errors
    /// Returns an error when a frame cannot be written to the local compio QUIC stream.
    pub async fn write_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        compio_write_raw_frame(&mut self.send, frame).await
    }

    /// # Errors
    /// Returns an error when a JSON frame cannot be serialized or written.
    pub async fn write_json_message<T>(&mut self, value: &T) -> Result<(), TransportError>
    where
        T: Serialize,
    {
        let body = serde_json::to_vec(value)?;
        self.write_frame(&body).await
    }

    /// # Errors
    /// Returns an error when the compio QUIC send stream cannot be gracefully finished.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        self.send.finish().map_err(|error| TransportError::Quic(error.to_string()))
    }
}

impl CompioGatewayRecvStream {
    /// # Errors
    /// Returns an error when a frame cannot be read from the local compio QUIC stream.
    pub async fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        compio_read_raw_frame(&mut self.recv).await
    }

    /// # Errors
    /// Returns an error when a JSON frame cannot be read or decoded.
    pub async fn read_json_frame<T>(&mut self) -> Result<T, TransportError>
    where
        T: DeserializeOwned,
    {
        let body = self.read_frame().await?;
        Ok(serde_json::from_slice(&body)?)
    }
}

async fn compio_write_raw_frame(
    send: &mut compio_quic::SendStream,
    frame: &[u8],
) -> Result<(), TransportError> {
    let len = u32::try_from(frame.len())
        .map_err(|_error| TransportError::FrameTooLarge { len: frame.len() })?;
    if frame.len() > COMP_IO_GATEWAY_FRAME_MAX_BYTES {
        return Err(TransportError::FrameTooLarge { len: frame.len() });
    }
    let mut encoded = Vec::with_capacity(4 + frame.len());
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(frame);
    let mut chunks = [Bytes::from(encoded)];
    send.write_all_chunks(&mut chunks)
        .await
        .map_err(|error| TransportError::Quic(error.to_string()))?;
    Ok(())
}

async fn compio_read_raw_frame(
    recv: &mut compio_quic::RecvStream,
) -> Result<Vec<u8>, TransportError> {
    let mut len_bytes = [0_u8; 4];
    compio_read_exact(recv, &mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > COMP_IO_GATEWAY_FRAME_MAX_BYTES {
        return Err(TransportError::FrameTooLarge { len });
    }
    let mut body = vec![0_u8; len];
    compio_read_exact(recv, &mut body).await?;
    Ok(body)
}

async fn compio_read_exact(
    recv: &mut compio_quic::RecvStream,
    out: &mut [u8],
) -> Result<(), TransportError> {
    let mut filled = 0;
    while filled < out.len() {
        let max_len = out.len() - filled;
        match recv.read_chunk(max_len, true).await {
            Ok(Some(chunk)) => {
                let bytes = chunk.bytes;
                let len = bytes.len();
                out[filled..filled + len].copy_from_slice(&bytes);
                filled += len;
            }
            Ok(None) => {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("compio gateway frame ended after {filled} of {} bytes", out.len()),
                )));
            }
            Err(error) => return Err(TransportError::Quic(error.to_string())),
        }
    }
    Ok(())
}
