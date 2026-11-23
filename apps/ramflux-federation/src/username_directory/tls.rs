// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dedicated reporting listener: defer only discovery-root selection, never TLS key possession.
use super::{Result, refuse};
use ramflux_node_core::username_directory as directory;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::{
    io::{Cursor, Read},
    path::Path,
    sync::Arc,
};

pub const ALPN: &[u8] = b"ramflux-username-v1";
pub const EXPORTER: &[u8] = b"EXPORTER-ramflux-username-v1";

#[derive(Debug)]
struct DiscoveryRoots;

impl ClientCertVerifier for DiscoveryRoots {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, Error> {
        // The actor verifies this exact chain against signed discovery before admitting a call.
        if end.len() > 16384 || chain.len() > 4 || chain.iter().any(|c| c.len() > 16384) {
            return Err(Error::General("directory certificate bound".into()));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return refuse("directory file bound");
    }
    Ok(bytes)
}

pub fn certs(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let values: Vec<_> =
        rustls_pemfile::certs(&mut Cursor::new(bytes)).collect::<std::io::Result<_>>()?;
    if values.is_empty() || values.len() > 4 {
        return refuse("directory certificate count");
    }
    Ok(values)
}

fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut Cursor::new(read_file(path, 16384)?))?
        .ok_or_else(|| super::error("directory private key"))
}

pub fn server(config: &ramflux_node_core::NodeServiceConfig) -> Result<rustls::ServerConfig> {
    let _installed = rustls::crypto::ring::default_provider().install_default();
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(DiscoveryRoots))
        .with_single_cert(
            certs(&read_file(Path::new(&config.mesh.service_cert), 65536)?)?,
            private_key(Path::new(&config.mesh.service_key))?,
        )?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    Ok(tls)
}

/// Finish trust selection on the same key-possession-authenticated TLS connection.
pub fn verify_reporter(
    chain: &[CertificateDer<'static>],
    evidence: &directory::ReportingEvidence,
    now: u64,
) -> Result<()> {
    let (leaf, intermediates) =
        chain.split_first().ok_or_else(|| super::error("missing reporting certificate"))?;
    let mut roots = RootCertStore::empty();
    for cert in certs(evidence.discovery.node_ca_cert_pem.as_bytes())? {
        roots.add(cert)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    verifier.verify_client_cert(
        leaf,
        intermediates,
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(now)),
    )?;
    let uri = ramflux_transport::extract_spiffe_uri_from_certificate(leaf)?
        .ok_or_else(|| super::error("missing reporting service identity"))?;
    let expected = format!("spiffe://{}/ramflux-federation", evidence.discovery.node_id);
    if uri != expected {
        return refuse("reporting service identity mismatch");
    }
    Ok(())
}
