// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use rustls::{ServerConfig, ServerConnection};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::perf_metrics::record_mesh_server_tls_handshake;
use crate::tls_config::{mesh_server_config, mesh_server_config_with_pem_roots};
use crate::{MeshTlsConfig, TransportError};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

pub type MeshTlsServerStream = rustls::StreamOwned<ServerConnection, TcpStream>;

pub struct MeshTlsAcceptedStream {
    pub stream: MeshTlsServerStream,
    pub peer_spiffe_uri: Option<String>,
}

pub struct MeshTlsServer {
    listener: TcpListener,
    config: Arc<ServerConfig>,
}

impl MeshTlsServer {
    /// # Errors
    /// Returns an error when the listener cannot bind or TLS material cannot be loaded.
    pub fn bind(addr: &str, tls: &MeshTlsConfig) -> Result<Self, TransportError> {
        let listener = TcpListener::bind(addr)?;
        let config = Arc::new(mesh_server_config(tls)?);
        Ok(Self { listener, config })
    }

    /// Clone the immutable TLS configuration for a connection worker.
    #[must_use]
    pub fn handshake_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }

    /// # Errors
    /// Returns an error when the listener local address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.listener.local_addr()?)
    }

    /// Configure whether listener acceptance is nonblocking.
    ///
    /// # Errors
    /// Returns an error when the socket option cannot be changed.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), TransportError> {
        Ok(self.listener.set_nonblocking(nonblocking)?)
    }

    /// # Errors
    /// Returns an error when TCP accept or the TLS handshake fails.
    pub fn accept(&self) -> Result<MeshTlsServerStream, TransportError> {
        Ok(self.accept_authenticated()?.stream)
    }

    /// # Errors
    /// Returns an error when TCP accept, TLS handshake, or peer certificate parsing fails.
    pub fn accept_authenticated(&self) -> Result<MeshTlsAcceptedStream, TransportError> {
        let stream = self.accept_tcp_stream()?;
        authenticate_tcp_stream(stream, Arc::clone(&self.config))
    }

    /// # Errors
    /// Returns an error when TCP accept, TLS handshake, peer root loading, or peer certificate
    /// parsing fails.
    pub fn accept_authenticated_with_pem_roots(
        &self,
        tls: &MeshTlsConfig,
        root_pems: &[String],
    ) -> Result<MeshTlsAcceptedStream, TransportError> {
        let stream = self.accept_tcp_stream()?;
        authenticate_tcp_stream(
            stream,
            Arc::new(mesh_server_config_with_pem_roots(tls, root_pems)?),
        )
    }

    /// # Errors
    /// Returns an error when TCP accept, root loading, TLS handshake, or peer certificate parsing
    /// fails.
    pub fn accept_authenticated_with_pem_roots_provider<F>(
        &self,
        tls: &MeshTlsConfig,
        root_pems_provider: F,
    ) -> Result<MeshTlsAcceptedStream, TransportError>
    where
        F: FnOnce() -> Result<Vec<String>, TransportError>,
    {
        let stream = self.accept_tcp_stream()?;
        let root_pems = root_pems_provider()?;
        authenticate_tcp_stream(
            stream,
            Arc::new(mesh_server_config_with_pem_roots(tls, &root_pems)?),
        )
    }

    /// Accept TCP without performing any handshake on the listener thread.
    ///
    /// # Errors
    /// Returns a TCP accept or socket-option error.
    pub fn accept_tcp_stream(&self) -> Result<TcpStream, TransportError> {
        let (stream, _peer_addr) = self.listener.accept()?;
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(stream)
    }
}

/// Authenticate an already accepted socket on its connection thread with a total 10 s deadline.
///
/// # Errors
/// Returns TLS, certificate parsing, timeout, or socket errors.
pub fn authenticate_tcp_stream(
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<MeshTlsAcceptedStream, TransportError> {
    let connection =
        ServerConnection::new(config).map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut HandshakeIo { socket: &mut stream.sock, deadline })?;
    }
    stream.sock.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.sock.set_write_timeout(Some(Duration::from_secs(30)))?;
    record_mesh_server_tls_handshake();
    let peer_spiffe_uri = stream
        .conn
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(extract_spiffe_uri_from_certificate)
        .transpose()?
        .flatten();
    Ok(MeshTlsAcceptedStream { stream, peer_spiffe_uri })
}

/// Authenticate an accepted connection using dynamically pinned peer roots.
///
/// # Errors
/// Returns TLS configuration, handshake, timeout, or certificate errors.
pub fn authenticate_tcp_stream_with_pem_roots(
    stream: TcpStream,
    tls: &MeshTlsConfig,
    root_pems: &[String],
) -> Result<MeshTlsAcceptedStream, TransportError> {
    authenticate_tcp_stream(stream, Arc::new(mesh_server_config_with_pem_roots(tls, root_pems)?))
}

/// # Errors
/// Returns an error when the peer certificate DER or SAN extension cannot be parsed.
pub fn extract_spiffe_uri_from_certificate(
    certificate: &rustls::pki_types::CertificateDer<'_>,
) -> Result<Option<String>, TransportError> {
    let (_remaining, certificate) = x509_parser::certificate::X509Certificate::from_der(
        certificate.as_ref(),
    )
    .map_err(|error| TransportError::Tls(format!("cannot parse peer certificate: {error}")))?;
    let Some(san) = certificate.subject_alternative_name().map_err(|error| {
        TransportError::Tls(format!("cannot parse peer certificate SAN: {error}"))
    })?
    else {
        return Ok(None);
    };
    Ok(san.value.general_names.iter().find_map(|name| match name {
        GeneralName::URI(uri) if uri.starts_with("spiffe://") => Some((*uri).to_owned()),
        _ => None,
    }))
}

struct HandshakeIo<'a> {
    socket: &'a mut TcpStream,
    deadline: std::time::Instant,
}

impl HandshakeIo<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "mesh TLS handshake deadline",
            ));
        }
        Ok(remaining)
    }
}

impl std::io::Read for HandshakeIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        std::io::Read::read(self.socket, bytes)
    }
}
impl std::io::Write for HandshakeIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        std::io::Write::write(self.socket, bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(self.socket)
    }
}
