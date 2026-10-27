// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live TLS exporter access and separately bounded custody framing.

use crate::{GatewayTcpTlsStream, TransportError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Export the exact client-facing TLS 1.3 material after the handshake completes.
/// # Errors
/// Rejects TLS 1.2, incomplete handshakes and unavailable exporters in every mode.
pub fn custody_tcp_exporter(
    stream: &GatewayTcpTlsStream,
    nonce: &[u8; 32],
) -> Result<[u8; 32], TransportError> {
    let common = stream.get_ref().1;
    if common.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || common.is_handshaking()
    {
        return Err(TransportError::Tls("custody requires a completed TLS 1.3 handshake".into()));
    }
    let label = ramflux_protocol::domain::CUSTODY_BRANCH_EXPORTER.as_bytes();
    match stream {
        tokio_rustls::TlsStream::Client(tls) => {
            tls.get_ref().1.export_keying_material([0; 32], label, Some(nonce))
        }
        tokio_rustls::TlsStream::Server(tls) => {
            tls.get_ref().1.export_keying_material([0; 32], label, Some(nonce))
        }
    }
    .map_err(|error| TransportError::Tls(error.to_string()))
}

/// Export from the actual QUIC TLS connection, never another stream or transport hop.
/// # Errors
/// Rejects exporters unavailable before handshake completion; no 0-RTT exporter is used.
pub fn custody_quic_exporter(
    connection: &quinn::Connection,
    nonce: &[u8; 32],
) -> Result<[u8; 32], TransportError> {
    let mut output = [0; 32];
    connection
        .export_keying_material(
            &mut output,
            ramflux_protocol::domain::CUSTODY_BRANCH_EXPORTER.as_bytes(),
            nonce,
        )
        .map_err(|_| TransportError::Tls("custody TLS exporter unavailable".into()))?;
    Ok(output)
}

/// Write a custody frame only after a bounded custody-open preface was accepted.
/// # Errors
/// Rejects oversized frames and stream errors. Legacy frame limits are unchanged.
pub async fn write_custody_tcp_frame<W: AsyncWrite + Unpin + ?Sized>(
    stream: &mut W,
    body: &[u8],
) -> Result<(), TransportError> {
    if body.len() > ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES {
        return Err(TransportError::FrameTooLarge { len: body.len() });
    }
    let count =
        u32::try_from(body.len()).map_err(|_| TransportError::FrameTooLarge { len: body.len() })?;
    stream.write_all(&count.to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}
/// Read a separately bounded custody frame, checking length before allocation.
/// # Errors
/// Rejects oversized frames, truncated lengths/bodies and stream errors.
pub async fn read_custody_tcp_frame<R: AsyncRead + Unpin + ?Sized>(
    stream: &mut R,
) -> Result<Vec<u8>, TransportError> {
    let mut count = [0; 4];
    stream.read_exact(&mut count).await?;
    let len = u32::from_be_bytes(count) as usize;
    if len > ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES {
        return Err(TransportError::FrameTooLarge { len });
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn actual_client_and_server_exporters_match_only_the_same_connection_and_context()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = Root(
            std::env::temp_dir()
                .join(format!("ramflux-custody-tls-{}-{suffix}", std::process::id())),
        );
        std::fs::create_dir(&root.0)?;
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let ca = root.0.join("ca.pem");
        let certificate = root.0.join("server.pem");
        let key = root.0.join("server.key");
        std::fs::write(&ca, generated.cert.pem())?;
        std::fs::write(&certificate, generated.cert.pem())?;
        std::fs::write(&key, generated.signing_key.serialize_pem())?;
        let tls = crate::MeshTlsConfig {
            ca_cert: ca.clone(),
            service_cert: certificate,
            service_key: key,
        };
        let acceptor =
            tokio_rustls::TlsAcceptor::from(Arc::new(crate::tcp_gateway_server_config(&tls)?));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let mut exports = Vec::new();
            for _ in 0..2 {
                let (socket, _) = listener.accept().await?;
                let stream = acceptor.accept(socket).await?;
                let mut stream = GatewayTcpTlsStream::Server(stream);
                let mut ready = [0; 1];
                stream.read_exact(&mut ready).await?;
                exports.push(custody_tcp_exporter(&stream, &[5; 32])?);
            }
            Ok::<_, TransportError>(exports)
        });
        let mut clients = Vec::new();
        for _ in 0..2 {
            let (_, stream) = crate::TcpTlsGatewayClient::connect(
                "127.0.0.1:0".parse()?,
                address,
                "localhost",
                &ca,
                Duration::from_secs(10),
            )
            .await?;
            let mut stream = stream.into_tls_stream();
            let material = custody_tcp_exporter(&stream, &[5; 32])?;
            assert_ne!(material, custody_tcp_exporter(&stream, &[6; 32])?);
            clients.push(material);
            stream.write_all(&[1]).await?;
        }
        let servers = server.await??;
        assert_eq!(clients, servers);
        assert_ne!(clients[0], clients[1]);
        Ok(())
    }
}
