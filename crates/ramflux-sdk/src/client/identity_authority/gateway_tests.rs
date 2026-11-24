// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Malicious framed gateway response through the production TLS manifest-fetch path.
use super::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[tokio::test]
async fn r8_malicious_server_bundle_substitution_fails_before_key_admission_or_session_creation()
-> TestResult {
    let owner = Actor::new("alice", "alice", 131, 132, 1)?;
    let peer = Actor::new("bob", "bob", 141, 142, 1)?;
    let mut forged = owner.manifest()?;
    let expected = forged.principal_commitment.clone();
    let attacker = ramflux_crypto::create_device_branch("alice", "alice", 1, [151; 32]);
    forged.devices[0].branch_public_key =
        ramflux_protocol::encode_base64url(attacker.signing_key.verifying_key().to_bytes());
    forged.devices[0].prekey_bundle = ramflux_crypto::create_prekey_bundle(
        &attacker,
        &X25519KeyPair::from_seed([152; 32]),
        "signed",
        &X25519KeyPair::from_seed([153; 32]),
        None,
        None,
    )?;
    let (gateway, server) = manifest_server(&peer.path, forged).await?;
    assert!(
        peer.client
            .cache_verified_device_manifest(&gateway, &expected, "malicious_gateway")
            .await
            .is_err()
    );
    server.await??;
    assert!(peer.client.account_db()?.client_record("device", "alice")?.is_none());
    // Reject the forged manifest atomically, before any authority or ready-key admission.
    assert!(
        peer.client.observed_device_set(&expected)?.is_none(),
        "forged manifest admitted authority"
    );
    assert_eq!(
        peer.client.account_db()?.pair_peer_devices(&peer.client.local_device_identity("bob")?)?,
        Vec::<String>::new()
    );
    Ok(())
}

pub(super) async fn manifest_server(
    path: &std::path::Path,
    forged: crate::prekey::SdkDeviceManifestResponse,
) -> Result<
    (GatewaySessionConfig, tokio::task::JoinHandle<std::io::Result<()>>),
    Box<dyn std::error::Error>,
> {
    let certified = rcgen::generate_simple_self_signed(vec!["malicious.test".into()])?;
    let ca = path.join("ca.pem");
    std::fs::write(&ca, certified.cert.pem())?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (socket, _) =
            tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept()).await??;
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(socket).await?;
        let len = stream.read_u32().await?;
        if len > 65536 {
            return Err(std::io::Error::other("oversized test request"));
        }
        let mut bytes = vec![0; len as usize];
        stream.read_exact(&mut bytes).await?;
        let request: ramflux_transport::GatewayQuicRequest = serde_json::from_slice(&bytes)?;
        assert_eq!(request.method, "GET");
        assert!(request.path.starts_with("/mvp1/device-manifest/"));
        let response = serde_json::to_vec(&ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(forged)?,
        })?;
        stream.write_u32(u32::try_from(response.len()).map_err(std::io::Error::other)?).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
        Ok::<_, std::io::Error>(())
    });
    let gateway = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: address,
        server_name: "malicious.test".into(),
        ca_cert: ca,
        principal_id: "bob".into(),
        device_id: "bob".into(),
        target_delivery_id: "bob".into(),
        prekey_http_url: None,
    });
    Ok((gateway, server))
}
