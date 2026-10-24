// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real peer verification failures must survive the transport and SDK error boundaries.
use super::io::local_bus_error_code;
use crate::SdkError;
use ramflux_transport::{MeshQuicServer, MeshTlsConfig, TransportError};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Certificates {
    root: PathBuf,
    tls: MeshTlsConfig,
    ca_pem: String,
    leaf: rustls::pki_types::CertificateDer<'static>,
    key: Vec<u8>,
}
impl Certificates {
    fn new(label: &str) -> TestResult<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = PathBuf::from("/tmp").join(format!(
            "rf-r8-{label}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        std::fs::create_dir_all(&root)?;
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        ca.distinguished_name.push(rcgen::DnType::CommonName, label);
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca.self_signed(&ca_key)?;
        let ca_pem = ca_cert.pem();
        let issuer = Issuer::new(ca, ca_key);
        let mut leaf = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
        leaf.subject_alt_names
            .push(rcgen::SanType::URI("spiffe://test-node/ramflux-gateway".try_into()?));
        leaf.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let key = KeyPair::generate()?;
        let cert = leaf.signed_by(&key, &issuer)?;
        let tls = MeshTlsConfig {
            ca_cert: root.join("ca.pem"),
            service_cert: root.join("service.pem"),
            service_key: root.join("key.pem"),
        };
        std::fs::write(&tls.ca_cert, &ca_pem)?;
        std::fs::write(&tls.service_cert, cert.pem())?;
        std::fs::write(&tls.service_key, key.serialize_pem())?;
        Ok(Self { root, tls, ca_pem, leaf: cert.der().clone(), key: key.serialize_der() })
    }
    fn mesh(&self, client_ca: String) -> TestResult<(String, tokio::task::JoinHandle<()>)> {
        let server = MeshQuicServer::bind_with_pem_roots_provider(
            "127.0.0.1:0",
            &self.tls,
            Arc::new(move || Ok(vec![client_ca.clone()])),
        )?;
        let addr = server.local_addr()?.to_string();
        let task = tokio::spawn(async move {
            loop {
                let Ok(connection) = server.accept_connection().await else { continue };
                if let Ok(request) = MeshQuicServer::accept_request_on_connection(&connection).await
                {
                    let _ = request.write_json_response(200, &serde_json::json!({"ok":true})).await;
                }
                // Keep the accepted connection alive until the test shuts this server down.
                std::future::pending::<()>().await;
            }
        });
        Ok((addr, task))
    }
    async fn https(&self) -> TestResult<(String, tokio::task::JoinHandle<std::io::Result<()>>)> {
        let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(
            vec![self.leaf.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(self.key.clone()).into(),
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let Ok(mut stream) = acceptor.accept(stream).await else { return Ok(()) };
            let mut request = [0; 4096];
            tokio::io::AsyncReadExt::read(&mut stream, &mut request).await?;
            tokio::io::AsyncWriteExt::write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            )
            .await
        });
        Ok((format!("https://{addr}/"), task))
    }
}
impl Drop for Certificates {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn assert_security(error: TransportError) {
    let error = SdkError::Transport(error);
    assert_eq!(local_bus_error_code(&error), "TransportSecurity", "{error:?}");
    assert!(!crate::error_policy::approval_retryable(&error));
    let wrapped = SdkError::ContactUnavailable(Box::new(error));
    assert_eq!(local_bus_error_code(&wrapped), "TransportSecurity");
    assert!(!crate::error_policy::approval_retryable(&wrapped));
}
#[tokio::test]
async fn r8_real_mesh_quic_wrong_ca_is_a_security_refusal_and_does_not_poison_valid_trust()
-> TestResult {
    let server = Certificates::new("quic-server")?;
    let client = Certificates::new("quic-client")?;
    let (endpoint, task) = server.mesh(client.ca_pem.clone())?;
    for _ in 0..2 {
        let result =
            ramflux_transport::mesh_quic_get_json_with_peer_ca_pems_async::<serde_json::Value>(
                &endpoint,
                "/probe",
                &client.tls,
                "localhost",
                std::slice::from_ref(&client.ca_pem),
            )
            .await;
        let error = result.err().ok_or("untrusted QUIC server accepted")?;
        assert_security(error);
    }
    let result =
        ramflux_transport::mesh_quic_get_json_with_peer_ca_pems_async::<serde_json::Value>(
            &endpoint,
            "/probe",
            &client.tls,
            "localhost",
            std::slice::from_ref(&server.ca_pem),
        )
        .await?;
    assert_eq!(result["ok"], true);
    task.abort();
    let _ = task.await;
    Ok(())
}
#[tokio::test]
async fn r8_real_gateway_quic_wrong_ca_is_a_security_refusal() -> TestResult {
    let server = Certificates::new("gateway-server")?;
    let client = Certificates::new("gateway-client")?;
    let (endpoint, task) = server.mesh(client.ca_pem.clone())?;
    let result = ramflux_transport::QuicGatewayClient::connect(
        "127.0.0.1:0".parse()?,
        endpoint.parse()?,
        "localhost",
        &client.tls.ca_cert,
        Duration::from_secs(3),
    )
    .await;
    let error = result.err().ok_or("untrusted gateway accepted")?;
    assert_security(error);
    task.abort();
    let _ = task.await;
    Ok(())
}
#[tokio::test]
async fn r8_real_https_wrong_ca_is_security_even_when_reqwest_marks_it_connect() -> TestResult {
    let server = Certificates::new("https-server")?;
    let wrong = Certificates::new("https-wrong")?;
    let (url, task) = server.https().await?;
    let good = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(server.ca_pem.as_bytes())?)
        .build()?;
    assert_eq!(good.get(url).send().await?.status(), 200);
    task.await??;
    for normalize in [false, true] {
        let (url, task) = server.https().await?;
        let bad = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .add_root_certificate(reqwest::Certificate::from_pem(wrong.ca_pem.as_bytes())?)
            .build()?;
        let error = bad.get(url).send().await.err().ok_or("untrusted HTTPS accepted")?;
        assert!(error.is_connect(), "{error:?}");
        if normalize {
            let error = TransportError::from(error);
            assert!(matches!(&error, TransportError::Tls(_)), "{error:?}");
            assert_security(error);
        } else {
            assert_security(TransportError::HttpClient(error));
        }
        task.await??;
    }
    Ok(())
}

#[tokio::test]
async fn r8_real_quic_rejected_client_certificate_is_a_security_refusal() -> TestResult {
    let server = Certificates::new("client-reject-server")?;
    let client = Certificates::new("client-reject-client")?;
    let (endpoint, task) = server.mesh(server.ca_pem.clone())?;
    let result =
        ramflux_transport::mesh_quic_get_json_with_peer_ca_pems_async::<serde_json::Value>(
            &endpoint,
            "/probe",
            &client.tls,
            "localhost",
            std::slice::from_ref(&server.ca_pem),
        )
        .await;
    assert_security(result.err().ok_or("untrusted client accepted")?);
    task.abort();
    let _ = task.await;
    Ok(())
}
#[tokio::test]
async fn r8_real_pooled_quic_wrong_ca_keeps_its_security_phase() -> TestResult {
    let server = Certificates::new("pooled-server")?;
    let client = Certificates::new("pooled-client")?;
    let (endpoint, task) = server.mesh(client.ca_pem.clone())?;
    let config = ramflux_transport::quic_gateway_client_config(&client.tls.ca_cert)?;
    let result = ramflux_transport::QuicGatewayClient::connect_pooled(
        "127.0.0.1:0".parse()?,
        endpoint.parse()?,
        "localhost",
        config,
        Duration::from_secs(3),
        Duration::from_secs(3),
    )
    .await;
    let error = result.err().ok_or("untrusted pooled gateway accepted")?;
    assert!(
        matches!(error, ramflux_transport::QuicConnectPhase::HandshakeSecurity(_)),
        "{error:?}"
    );
    task.abort();
    let _ = task.await;
    Ok(())
}

#[test]
fn r8_http_throttling_statuses_are_retryable() {
    for status in [408, 429] {
        let error =
            SdkError::Transport(TransportError::Http(format!("HTTP {status}: retry later")));
        assert_eq!(local_bus_error_code(&error), "Unavailable");
        assert!(crate::error_policy::approval_retryable(&error));
    }
}

#[tokio::test]
async fn r8_a_real_interrupted_http_response_body_is_retryable() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = [0; 4096];
        tokio::io::AsyncReadExt::read(&mut stream, &mut request).await?;
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nConnection: close\r\n\r\nshort",
        )
        .await
    });
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?
        .get(format!("http://{addr}/"))
        .send()
        .await?;
    let error = response.bytes().await.err().ok_or("truncated body accepted")?;
    assert!(error.is_body() || error.is_decode(), "{error:?}");
    let error = SdkError::Transport(TransportError::from(error));
    assert_eq!(local_bus_error_code(&error), "Unavailable");
    assert!(crate::error_policy::approval_retryable(&error));
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn r8_gateway_stream_preserves_a_tls_client_auth_rejection() -> TestResult {
    use ramflux_transport::GatewaySessionFrameSource;
    let server = Certificates::new("stream-auth-server")?;
    let (endpoint, task) = server.mesh(server.ca_pem.clone())?;
    // The server is trusted, but requires a client certificate. Client-side QUIC
    // readiness can precede the server's rejection of the empty certificate flight.
    let client = ramflux_transport::QuicGatewayClient::connect(
        "127.0.0.1:0".parse()?,
        endpoint.parse()?,
        "localhost",
        &server.tls.ca_cert,
        Duration::from_secs(3),
    )
    .await?;
    let mut stream = client.open_bidi_stream().await?;
    let error =
        stream.recv_frame().await.err().ok_or("client authentication unexpectedly succeeded")?;
    assert_security(error);
    task.abort();
    let _ = task.await;
    Ok(())
}
