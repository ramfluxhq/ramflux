// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! TLS of the web listener: its own Web PKI certificate, TLS 1.3 only, ALPN `http/1.1`
//! only, and a key that is provably not the mesh service key.

use super::config::WebIngressConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;

pub(crate) const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

fn private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", path.display()))
}

fn certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    let chain = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() {
        anyhow::bail!("no certificate in {}", path.display());
    }
    Ok(chain)
}

/// The `SubjectPublicKeyInfo` of a private key, independent of its PEM encoding.
fn public_key(key: &PrivateKeyDer<'_>) -> anyhow::Result<Vec<u8>> {
    let signing = rustls::crypto::ring::sign::any_supported_type(key)?;
    let public = signing
        .public_key()
        .ok_or_else(|| anyhow::anyhow!("cannot derive the public key of a TLS private key"))?;
    Ok(public.as_ref().to_vec())
}

/// Listener-key separation: a certificate shared by mistake must not start the listener.
///
/// # Errors
/// Fails when the two keys are the same key or when either cannot be compared.
pub(crate) fn ensure_distinct_keys(
    web: &PrivateKeyDer<'_>,
    mesh: &PrivateKeyDer<'_>,
) -> anyhow::Result<()> {
    if public_key(web)? == public_key(mesh)? {
        anyhow::bail!("the web listener key must not be the mesh service key");
    }
    Ok(())
}

/// Build the web listener's TLS configuration.
///
/// # Errors
/// Fails on unreadable material, on a key shared with the mesh, or on a bad chain.
pub(crate) fn server_config(
    config: &WebIngressConfig,
    mesh_service_key: &Path,
) -> anyhow::Result<rustls::ServerConfig> {
    let key = private_key(&config.tls_key)?;
    ensure_distinct_keys(&key, &private_key(mesh_service_key)?)?;
    build(certificates(&config.tls_cert)?, key)
}

pub(crate) fn build(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    // No HTTP/2 and no HTTP/3 on this listener.
    server.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
    Ok(server)
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
