// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Prekey probe trust: the directory client's public roots, never the node CA.
use super::probe_prekey_tls;
use crate::SdkError;
use crate::node::{NodeGateway, NodePinSource, NodeProfile, NodeRelay};
use crate::prekey::http_async::TEST_PREKEY_TRUST_ROOT;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::collections::BTreeSet;
use std::time::Duration;

const FIXTURE_DEADLINE: Duration = Duration::from_secs(30);
const RESPONSE_READ_LIMIT: usize = 4096;

struct Identity {
    ca_pem: String,
    leaf: rustls::pki_types::CertificateDer<'static>,
    key: Vec<u8>,
}

struct AbortOnDrop(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Identity {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        ca.distinguished_name.push(rcgen::DnType::CommonName, label);
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca, ca_key);
        let mut leaf = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate()?;
        let cert = leaf.signed_by(&key, &issuer)?;
        Ok(Self { ca_pem: ca_cert.pem(), leaf: cert.der().clone(), key: key.serialize_der() })
    }
}

fn profile(ca_pem: &str, prekey_http_url: &str) -> NodeProfile {
    NodeProfile {
        discovery_url: String::new(),
        node_id: "node.example".to_owned(),
        node_public_key: "key".to_owned(),
        pin_source: NodePinSource::Operator,
        ca_cert_pem: ca_pem.to_owned(),
        gateway: NodeGateway {
            quic_addr: "127.0.0.1:1".to_owned(),
            tcp_addr: "127.0.0.1:1".to_owned(),
            server_name: "gateway.example".to_owned(),
        },
        relay: NodeRelay {
            quic_addr: "127.0.0.1:1".to_owned(),
            server_name: "relay.example".to_owned(),
        },
        prekey_http_url: prekey_http_url.to_owned(),
        signaling_turn_addr: String::new(),
        protocol_versions: Vec::new(),
        client_capabilities: Vec::new(),
        discovered_at: 1,
        expires_at: 2,
        enabled: true,
        builtin: false,
        safety_warnings: BTreeSet::new(),
    }
}

async fn serve(identity: &Identity) -> Result<(String, AbortOnDrop), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(
        vec![identity.leaf.clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key.clone()).into(),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return Ok(());
        };
        let mut request = [0_u8; RESPONSE_READ_LIMIT];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await?;
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
        .await
    });
    Ok((format!("https://{addr}/"), AbortOnDrop(task)))
}

#[tokio::test]
async fn public_tls_prekey_probe_succeeds_when_the_node_ca_does_not_match() {
    let outcome = tokio::time::timeout(FIXTURE_DEADLINE, async {
        let server = Identity::new("prekey-public")?;
        let node_ca = Identity::new("prekey-node-ca")?;
        let (url, _server) = serve(&server).await?;
        let profile = profile(&node_ca.ca_pem, &url);
        TEST_PREKEY_TRUST_ROOT.scope(server.ca_pem, probe_prekey_tls(&profile)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;
    outcome
        .expect("test: public TLS prekey probe deadline")
        .expect("test: public TLS prekey probe");
}

#[tokio::test]
async fn wrong_ca_prekey_probe_is_a_transport_security_error() {
    let outcome = tokio::time::timeout(FIXTURE_DEADLINE, async {
        let server = Identity::new("prekey-untrusted")?;
        let (url, _server) = serve(&server).await?;
        // The stored node CA is this server's issuer. Trusting it would accept the handshake.
        let profile = profile(&server.ca_pem, &url);
        let error = probe_prekey_tls(&profile)
            .await
            .expect_err("test: untrusted prekey certificate must be refused");
        let SdkError::Transport(transport) = error else {
            return Err(format!("test: wrong CA must be a transport error, got {error:?}").into());
        };
        if !transport.is_tls_failure() {
            return Err(format!("test: wrong CA must be a TLS failure, got {transport:?}").into());
        }
        let code = crate::bus::io::local_bus_error_code(&SdkError::Transport(transport));
        if code != "TransportSecurity" {
            return Err(format!("test: wrong CA code was {code}").into());
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;
    outcome.expect("test: wrong CA prekey probe deadline").expect("test: wrong CA prekey probe");
}
