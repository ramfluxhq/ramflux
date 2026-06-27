// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::{WebPkiClientVerifier, danger::ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, ServerConfig,
    SignatureScheme, client::danger::HandshakeSignatureValid,
};
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::Path;
use std::sync::{Arc, Once};

use crate::{MeshTlsConfig, TransportError};

pub(crate) type MeshRootPemProvider =
    Arc<dyn Fn() -> Result<Vec<String>, TransportError> + Send + Sync>;

static RUSTLS_PROVIDER: Once = Once::new();

/// # Errors
/// Returns an error when the mesh CA, certificate, or private key cannot be loaded or validated.
pub fn mesh_server_config(tls: &MeshTlsConfig) -> Result<ServerConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    let root_store = mesh_root_store(&tls.ca_cert)?;
    mesh_server_config_from_root_store(tls, root_store)
}

pub(crate) fn mesh_server_config_with_pem_roots(
    tls: &MeshTlsConfig,
    root_pems: &[String],
) -> Result<ServerConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    let mut root_store = mesh_root_store(&tls.ca_cert)?;
    add_pem_roots(&mut root_store, root_pems)?;
    mesh_server_config_from_root_store(tls, root_store)
}

pub(crate) fn mesh_server_config_with_dynamic_pem_roots(
    tls: &MeshTlsConfig,
    root_pems_provider: MeshRootPemProvider,
) -> Result<ServerConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    let verifier =
        Arc::new(DynamicMeshClientVerifier::new(tls.ca_cert.clone(), root_pems_provider)?);
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(load_certs(&tls.service_cert)?, load_private_key(&tls.service_key)?)
        .map_err(|error| TransportError::Tls(error.to_string()))
}

fn mesh_server_config_from_root_store(
    tls: &MeshTlsConfig,
    root_store: RootCertStore,
) -> Result<ServerConfig, TransportError> {
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(load_certs(&tls.service_cert)?, load_private_key(&tls.service_key)?)
        .map_err(|error| TransportError::Tls(error.to_string()))
}

pub(crate) fn mesh_client_config(tls: &MeshTlsConfig) -> Result<ClientConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    mesh_client_config_from_root_store(tls, mesh_root_store(&tls.ca_cert)?)
}

pub(crate) fn mesh_client_config_with_pem_roots(
    tls: &MeshTlsConfig,
    root_pems: &[String],
) -> Result<ClientConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    mesh_client_config_from_root_store(tls, mesh_root_store_from_pems(root_pems)?)
}

fn mesh_client_config_from_root_store(
    tls: &MeshTlsConfig,
    root_store: RootCertStore,
) -> Result<ClientConfig, TransportError> {
    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(load_certs(&tls.service_cert)?, load_private_key(&tls.service_key)?)
        .map_err(|error| TransportError::Tls(error.to_string()))
}

pub(crate) fn mesh_quic_server_config_with_dynamic_pem_roots(
    tls: &MeshTlsConfig,
    root_pems_provider: MeshRootPemProvider,
) -> Result<quinn::ServerConfig, TransportError> {
    let server_config = mesh_server_config_with_dynamic_pem_roots(tls, root_pems_provider)?;
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_config)))
}

pub(crate) fn mesh_quic_client_config_with_pem_roots(
    tls: &MeshTlsConfig,
    root_pems: &[String],
) -> Result<quinn::ClientConfig, TransportError> {
    let client_config = mesh_client_config_with_pem_roots(tls, root_pems)?;
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_config)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
pub(crate) fn compio_mesh_quic_server_config_with_dynamic_pem_roots(
    tls: &MeshTlsConfig,
    root_pems_provider: MeshRootPemProvider,
) -> Result<compio_quic::ServerConfig, TransportError> {
    let server_config = mesh_server_config_with_dynamic_pem_roots(tls, root_pems_provider)?;
    let quic_config = compio_quic::crypto::rustls::QuicServerConfig::try_from(server_config)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    Ok(compio_quic::ServerConfig::with_crypto(Arc::new(quic_config)))
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
pub(crate) fn compio_mesh_quic_client_config_with_pem_roots(
    tls: &MeshTlsConfig,
    root_pems: &[String],
) -> Result<compio_quic::ClientConfig, TransportError> {
    let client_config = mesh_client_config_with_pem_roots(tls, root_pems)?;
    let quic_config = compio_quic::crypto::rustls::QuicClientConfig::try_from(client_config)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    Ok(compio_quic::ClientConfig::new(Arc::new(quic_config)))
}

#[cfg(all(target_os = "linux", feature = "compio-gateway"))]
pub(crate) fn compio_quic_gateway_server_config(
    tls: &MeshTlsConfig,
) -> Result<compio_quic::ServerConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certs(&tls.service_cert)?, load_private_key(&tls.service_key)?)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let quic_config = compio_quic::crypto::rustls::QuicServerConfig::try_from(server_config)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    Ok(compio_quic::ServerConfig::with_crypto(Arc::new(quic_config)))
}

struct DynamicMeshClientVerifier {
    local_ca_cert: std::path::PathBuf,
    root_pems_provider: MeshRootPemProvider,
    base_verifier: Arc<dyn ClientCertVerifier>,
    root_hint_subjects: Vec<rustls::DistinguishedName>,
}

impl std::fmt::Debug for DynamicMeshClientVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicMeshClientVerifier")
            .field("local_ca_cert", &self.local_ca_cert)
            .finish_non_exhaustive()
    }
}

impl DynamicMeshClientVerifier {
    fn new(
        local_ca_cert: std::path::PathBuf,
        root_pems_provider: MeshRootPemProvider,
    ) -> Result<Self, TransportError> {
        let base_verifier =
            WebPkiClientVerifier::builder(Arc::new(mesh_root_store(&local_ca_cert)?))
                .build()
                .map_err(|error| TransportError::Tls(error.to_string()))?;
        Ok(Self {
            local_ca_cert,
            root_pems_provider,
            base_verifier,
            root_hint_subjects: Vec::new(),
        })
    }

    fn current_verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
        let mut root_store = mesh_root_store(&self.local_ca_cert)
            .map_err(|error| TlsError::General(error.to_string()))?;
        let root_pems =
            (self.root_pems_provider)().map_err(|error| TlsError::General(error.to_string()))?;
        add_pem_roots(&mut root_store, &root_pems)
            .map_err(|error| TlsError::General(error.to_string()))?;
        WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|error| TlsError::General(error.to_string()))
    }
}

impl ClientCertVerifier for DynamicMeshClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, TlsError> {
        self.current_verifier()?.verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.base_verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.base_verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.base_verifier.supported_verify_schemes()
    }
}

/// # Errors
/// Returns an error when the gateway certificate or key cannot produce a QUIC server config.
pub fn quic_gateway_server_config(
    tls: &MeshTlsConfig,
) -> Result<quinn::ServerConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    quinn::ServerConfig::with_single_cert(
        load_certs(&tls.service_cert)?,
        load_private_key(&tls.service_key)?,
    )
    .map_err(|error| TransportError::Tls(error.to_string()))
}

/// # Errors
/// Returns an error when the CA bundle cannot produce a QUIC client config.
pub fn quic_gateway_client_config(ca_cert: &Path) -> Result<quinn::ClientConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    quinn::ClientConfig::with_root_certificates(Arc::new(mesh_root_store(ca_cert)?))
        .map_err(|error| TransportError::Tls(error.to_string()))
}

/// # Errors
/// Returns an error when the gateway certificate or key cannot produce a TCP-TLS server config.
pub fn tcp_gateway_server_config(tls: &MeshTlsConfig) -> Result<ServerConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certs(&tls.service_cert)?, load_private_key(&tls.service_key)?)
        .map_err(|error| TransportError::Tls(error.to_string()))
}

/// # Errors
/// Returns an error when the CA bundle cannot produce a TCP-TLS client config.
pub fn tcp_gateway_client_config(ca_cert: &Path) -> Result<ClientConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    Ok(ClientConfig::builder()
        .with_root_certificates(mesh_root_store(ca_cert)?)
        .with_no_client_auth())
}

pub(crate) fn ensure_ring_crypto_provider_installed() {
    RUSTLS_PROVIDER.call_once(|| {
        let _result = rustls::crypto::ring::default_provider().install_default();
    });
}

fn mesh_root_store(path: &Path) -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(path)? {
        roots.add(cert).map_err(|error| TransportError::Tls(error.to_string()))?;
    }
    Ok(roots)
}

fn mesh_root_store_from_pems(pems: &[String]) -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    add_pem_roots(&mut roots, pems)?;
    if roots.is_empty() {
        return Err(TransportError::Tls("missing trusted mesh root certificates".to_owned()));
    }
    Ok(roots)
}

fn add_pem_roots(roots: &mut RootCertStore, pems: &[String]) -> Result<(), TransportError> {
    for pem in pems {
        let mut reader = Cursor::new(pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            roots
                .add(cert.map_err(TransportError::Io)?)
                .map_err(|error| TransportError::Tls(error.to_string()))?;
        }
    }
    Ok(())
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>().map_err(TransportError::Io)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TransportError> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| TransportError::Tls(format!("missing private key in {}", path.display())))
}
