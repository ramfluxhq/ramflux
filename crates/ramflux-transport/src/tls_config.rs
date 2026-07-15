// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use quinn::VarInt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::{WebPkiClientVerifier, danger::ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, ServerConfig,
    SignatureScheme, client::danger::HandshakeSignatureValid,
};
use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::path::Path;
use std::sync::{Arc, Once};

use crate::{MeshTlsConfig, TransportError};

pub(crate) type MeshRootPemProvider =
    Arc<dyn Fn() -> Result<Vec<String>, TransportError> + Send + Sync>;

static RUSTLS_PROVIDER: Once = Once::new();
const MESH_QUIC_MAX_CONCURRENT_BIDI_STREAMS_ENV: &str =
    "RAMFLUX_MESH_QUIC_MAX_CONCURRENT_BIDI_STREAMS";
const MESH_QUIC_MAX_CONCURRENT_BIDI_STREAMS_DEFAULT: u32 = 4096;
const MESH_QUIC_RECEIVE_WINDOW_ENV: &str = "RAMFLUX_MESH_QUIC_RECEIVE_WINDOW";
const MESH_QUIC_STREAM_RECEIVE_WINDOW_ENV: &str = "RAMFLUX_MESH_QUIC_STREAM_RECEIVE_WINDOW";
const MESH_QUIC_SEND_WINDOW_ENV: &str = "RAMFLUX_MESH_QUIC_SEND_WINDOW";
const GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS_ENV: &str =
    "RAMFLUX_GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS";
const GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS_DEFAULT: u32 = 4096;
const GATEWAY_QUIC_RECEIVE_WINDOW_ENV: &str = "RAMFLUX_GATEWAY_QUIC_RECEIVE_WINDOW";
const GATEWAY_QUIC_STREAM_RECEIVE_WINDOW_ENV: &str = "RAMFLUX_GATEWAY_QUIC_STREAM_RECEIVE_WINDOW";
const GATEWAY_QUIC_SEND_WINDOW_ENV: &str = "RAMFLUX_GATEWAY_QUIC_SEND_WINDOW";
const MESH_TLS_FILE_PREFLIGHT_ENV: &str = "RAMFLUX_MESH_TLS_FILE_PREFLIGHT";
const QUIC_RECEIVE_WINDOW_DEFAULT: u64 = 16 * 1024 * 1024;
const QUIC_STREAM_RECEIVE_WINDOW_DEFAULT: u64 = 1024 * 1024;
const QUIC_SEND_WINDOW_DEFAULT: u64 = 16 * 1024 * 1024;

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
    mesh_tls_file_preflight("ca_cert", &tls.ca_cert);
    mesh_tls_file_preflight("service_cert", &tls.service_cert);
    mesh_tls_file_preflight("service_key", &tls.service_key);
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
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    server_config.transport_config(mesh_quic_transport_config());
    Ok(server_config)
}

pub(crate) fn mesh_quic_client_config_with_pem_roots(
    tls: &MeshTlsConfig,
    root_pems: &[String],
) -> Result<quinn::ClientConfig, TransportError> {
    let client_config = mesh_client_config_with_pem_roots(tls, root_pems)?;
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_config)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    client_config.transport_config(mesh_quic_transport_config());
    Ok(client_config)
}

fn mesh_quic_transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    apply_quic_transport_limits(
        &mut transport,
        QuicTransportLimitEnv {
            max_concurrent_bidi_streams: MESH_QUIC_MAX_CONCURRENT_BIDI_STREAMS_ENV,
            receive_window: MESH_QUIC_RECEIVE_WINDOW_ENV,
            stream_receive_window: MESH_QUIC_STREAM_RECEIVE_WINDOW_ENV,
            send_window: MESH_QUIC_SEND_WINDOW_ENV,
        },
        MESH_QUIC_MAX_CONCURRENT_BIDI_STREAMS_DEFAULT,
    );
    Arc::new(transport)
}

fn mesh_tls_file_preflight(label: &'static str, path: &Path) {
    if std::env::var(MESH_TLS_FILE_PREFLIGHT_ENV).as_deref() != Ok("1") {
        return;
    }
    let path_display = path.display().to_string();
    match std::fs::metadata(path) {
        Ok(metadata) => {
            tracing::info!(
                label,
                file_path = path_display.as_str(),
                len = metadata.len(),
                readonly = metadata.permissions().readonly(),
                "mesh TLS file preflight: metadata OK"
            );
        }
        Err(error) => {
            tracing::error!(
                label,
                file_path = path_display.as_str(),
                os_error = ?error.raw_os_error(),
                %error,
                "mesh TLS file preflight: metadata FAILED"
            );
            return;
        }
    }
    match File::open(path) {
        Ok(mut file) => {
            let mut buffer = [0_u8; 1];
            match file.read(&mut buffer) {
                Ok(bytes_read) => {
                    tracing::info!(
                        label,
                        file_path = path_display.as_str(),
                        bytes_read,
                        "mesh TLS file preflight: read OK"
                    );
                }
                Err(error) => {
                    tracing::error!(
                        label,
                        file_path = path_display.as_str(),
                        os_error = ?error.raw_os_error(),
                        %error,
                        "mesh TLS file preflight: read FAILED"
                    );
                }
            }
        }
        Err(error) => {
            tracing::error!(
                label,
                file_path = path_display.as_str(),
                os_error = ?error.raw_os_error(),
                %error,
                "mesh TLS file preflight: open FAILED"
            );
        }
    }
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
    let mut config = quinn::ServerConfig::with_single_cert(
        load_certs(&tls.service_cert)?,
        load_private_key(&tls.service_key)?,
    )
    .map_err(|error| TransportError::Tls(error.to_string()))?;
    config.transport_config(gateway_quic_transport_config());
    Ok(config)
}

/// # Errors
/// Returns an error when the CA bundle cannot produce a QUIC client config.
pub fn quic_gateway_client_config(ca_cert: &Path) -> Result<quinn::ClientConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    let mut config =
        quinn::ClientConfig::with_root_certificates(Arc::new(mesh_root_store(ca_cert)?))
            .map_err(|error| TransportError::Tls(error.to_string()))?;
    config.transport_config(gateway_quic_transport_config());
    Ok(config)
}

fn gateway_quic_transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    apply_quic_transport_limits(
        &mut transport,
        QuicTransportLimitEnv {
            max_concurrent_bidi_streams: GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS_ENV,
            receive_window: GATEWAY_QUIC_RECEIVE_WINDOW_ENV,
            stream_receive_window: GATEWAY_QUIC_STREAM_RECEIVE_WINDOW_ENV,
            send_window: GATEWAY_QUIC_SEND_WINDOW_ENV,
        },
        GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS_DEFAULT,
    );
    Arc::new(transport)
}

/// Builds a QUIC client config for a pooled relay connection. Unlike
/// [`quic_gateway_client_config`], this sets an explicit `max_idle_timeout` and
/// `keep_alive_interval` so a pooled connection kept alive across reuses does not silently hit
/// quinn's 30s default idle timeout with no keep-alive (the s60 idle-timeout failure mode). The
/// stream/window limits still honor the same `RAMFLUX_GATEWAY_QUIC_*` env overrides as the gateway
/// client. Idle/keepalive durations are validated by the caller (nonzero, keepalive &lt; idle).
///
/// # Errors
/// Returns an error when the CA bundle cannot be loaded/validated or the idle timeout exceeds the
/// QUIC-representable maximum.
pub fn relay_quic_pool_client_config(
    ca_cert: &Path,
    max_idle_timeout: std::time::Duration,
    keep_alive_interval: std::time::Duration,
) -> Result<quinn::ClientConfig, TransportError> {
    ensure_ring_crypto_provider_installed();
    let mut config =
        quinn::ClientConfig::with_root_certificates(Arc::new(mesh_root_store(ca_cert)?))
            .map_err(|error| TransportError::Tls(error.to_string()))?;
    config
        .transport_config(relay_quic_pool_transport_config(max_idle_timeout, keep_alive_interval)?);
    Ok(config)
}

fn relay_quic_pool_transport_config(
    max_idle_timeout: std::time::Duration,
    keep_alive_interval: std::time::Duration,
) -> Result<Arc<quinn::TransportConfig>, TransportError> {
    let mut transport = quinn::TransportConfig::default();
    apply_quic_transport_limits(
        &mut transport,
        QuicTransportLimitEnv {
            max_concurrent_bidi_streams: GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS_ENV,
            receive_window: GATEWAY_QUIC_RECEIVE_WINDOW_ENV,
            stream_receive_window: GATEWAY_QUIC_STREAM_RECEIVE_WINDOW_ENV,
            send_window: GATEWAY_QUIC_SEND_WINDOW_ENV,
        },
        GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS_DEFAULT,
    );
    let idle_timeout = quinn::IdleTimeout::try_from(max_idle_timeout).map_err(|error| {
        TransportError::Quic(format!("invalid relay QUIC pool idle timeout: {error}"))
    })?;
    transport.max_idle_timeout(Some(idle_timeout));
    transport.keep_alive_interval(Some(keep_alive_interval));
    Ok(Arc::new(transport))
}

#[derive(Clone, Copy)]
struct QuicTransportLimitEnv {
    max_concurrent_bidi_streams: &'static str,
    receive_window: &'static str,
    stream_receive_window: &'static str,
    send_window: &'static str,
}

fn apply_quic_transport_limits(
    transport: &mut quinn::TransportConfig,
    env: QuicTransportLimitEnv,
    default_stream_limit: u32,
) {
    let stream_limit = positive_u32_from_value(
        std::env::var(env.max_concurrent_bidi_streams).ok().as_deref(),
        default_stream_limit,
    );
    let receive_window = quic_varint_env(env.receive_window, QUIC_RECEIVE_WINDOW_DEFAULT);
    let stream_receive_window =
        quic_varint_env(env.stream_receive_window, QUIC_STREAM_RECEIVE_WINDOW_DEFAULT);
    let send_window = positive_u64_env(env.send_window, QUIC_SEND_WINDOW_DEFAULT);
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(stream_limit))
        .receive_window(receive_window)
        .stream_receive_window(stream_receive_window)
        .send_window(send_window);
}

fn quic_varint_env(name: &str, default: u64) -> VarInt {
    quic_varint_from_value(std::env::var(name).ok().as_deref(), default)
}

fn quic_varint_from_value(value: Option<&str>, default: u64) -> VarInt {
    let value = value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
        .min(VarInt::MAX.into_inner());
    VarInt::from_u64(value).unwrap_or(VarInt::MAX)
}

fn positive_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn positive_u32_from_value(value: Option<&str>, default: u32) -> u32 {
    value.and_then(|value| value.parse::<u32>().ok()).filter(|value| *value > 0).unwrap_or(default)
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

#[cfg(test)]
mod tests {
    use super::{
        GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS_DEFAULT, QUIC_RECEIVE_WINDOW_DEFAULT,
        QUIC_SEND_WINDOW_DEFAULT, QUIC_STREAM_RECEIVE_WINDOW_DEFAULT, positive_u32_from_value,
        quic_varint_from_value,
    };

    #[test]
    fn gateway_quic_stream_limit_parse_positive_env_value() {
        assert_eq!(positive_u32_from_value(Some("8192"), 4096), 8192);
        assert_eq!(positive_u32_from_value(Some("0"), 4096), 4096);
        assert_eq!(positive_u32_from_value(Some("bad"), 4096), 4096);
        assert_eq!(
            positive_u32_from_value(None, GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS_DEFAULT),
            4096
        );
    }

    #[test]
    fn quic_flow_control_window_defaults_are_high_bandwidth_safe() {
        assert_eq!(QUIC_RECEIVE_WINDOW_DEFAULT, 16 * 1024 * 1024);
        assert_eq!(QUIC_SEND_WINDOW_DEFAULT, 16 * 1024 * 1024);
        assert_eq!(QUIC_STREAM_RECEIVE_WINDOW_DEFAULT, 1024 * 1024);
        assert_eq!(
            quic_varint_from_value(None, QUIC_RECEIVE_WINDOW_DEFAULT).into_inner(),
            16 * 1024 * 1024
        );
        assert_eq!(
            quic_varint_from_value(Some("0"), QUIC_RECEIVE_WINDOW_DEFAULT).into_inner(),
            16 * 1024 * 1024
        );
        assert_eq!(
            quic_varint_from_value(Some("8388608"), QUIC_RECEIVE_WINDOW_DEFAULT).into_inner(),
            8 * 1024 * 1024
        );
    }
}
