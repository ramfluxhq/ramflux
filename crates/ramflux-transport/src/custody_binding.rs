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
    read_bounded_frame(stream, ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES).await
}
/// Read the small native-only open preface before allocating an operation frame.
/// # Errors
/// Rejects prefices above 4096 bytes and transport failures.
pub async fn read_custody_open_frame<R: AsyncRead + Unpin + ?Sized>(
    stream: &mut R,
) -> Result<Vec<u8>, TransportError> {
    read_bounded_frame(stream, 4096).await
}
async fn read_bounded_frame<R: AsyncRead + Unpin + ?Sized>(
    stream: &mut R,
    limit: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut count = [0; 4];
    stream.read_exact(&mut count).await?;
    let len = u32::from_be_bytes(count) as usize;
    if len > limit {
        return Err(TransportError::FrameTooLarge { len });
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// SHA-256 of the first certificate's DER bytes for a separately provisioned public listener.
/// # Errors
/// Rejects missing, oversized or malformed certificate files.
fn certificate_file(
    path: &std::path::Path,
) -> Result<rustls::pki_types::CertificateDer<'static>, TransportError> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(TransportError::Tls("certificate file too large".into()));
    }
    let cert = rustls_pemfile::certs(&mut std::io::Cursor::new(bytes))
        .next()
        .transpose()?
        .ok_or_else(|| TransportError::Tls("public listener certificate missing".into()))?;
    Ok(cert)
}
/// Hash the public listener leaf certificate DER, as committed by node metadata.
/// # Errors
/// Rejects missing, oversized or malformed certificate files.
pub fn custody_certificate_file_hash(path: &std::path::Path) -> Result<String, TransportError> {
    Ok(certificate_hash(certificate_file(path)?.as_ref()))
}
/// Compare public listener and mesh credentials without reading either private key.
/// # Errors
/// Rejects absent or malformed leaf certificates.
pub fn custody_certificate_public_key_hash(
    path: &std::path::Path,
) -> Result<String, TransportError> {
    use x509_parser::prelude::FromDer;
    let der = certificate_file(path)?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
        .map_err(|_| TransportError::Tls("invalid custody public certificate".into()))?;
    Ok(certificate_hash(cert.public_key().raw))
}
fn certificate_hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    ramflux_protocol::encode_base64url(Sha256::digest(bytes))
}
/// Authenticate the actual peer's leaf certificate against signed receiving-node metadata.
/// # Errors
/// Rejects absent peer certificates and a different public listener certificate.
pub fn verify_custody_peer_certificate(
    stream: &GatewayTcpTlsStream,
    expected: &str,
) -> Result<(), TransportError> {
    let certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or_else(|| TransportError::Tls("custody peer certificate absent".into()))?;
    if certificate_hash(certificate.as_ref()) != expected {
        return Err(TransportError::Tls("custody public certificate pin mismatch".into()));
    }
    Ok(())
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
            verify_custody_peer_certificate(
                &stream,
                &custody_certificate_file_hash(&tls.service_cert)?,
            )?;
            assert!(
                verify_custody_peer_certificate(
                    &stream,
                    &ramflux_protocol::encode_base64url([55; 32])
                )
                .is_err()
            );
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
