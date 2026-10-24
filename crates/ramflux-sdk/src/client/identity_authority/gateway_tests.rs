// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Malicious framed gateway response through the production TLS manifest-fetch path.
use super::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[tokio::test]
async fn r8_malicious_server_bundle_substitution_fails_before_trust_or_session_creation()
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
    let certified = rcgen::generate_simple_self_signed(vec!["malicious.test".into()])?;
    let ca = peer.path.join("ca.pem");
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
        let (socket, _) = listener.accept().await?;
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
    assert!(
        peer.client
            .cache_verified_device_manifest(&gateway, &expected, "malicious_gateway")
            .await
            .is_err()
    );
    server.await??;
    assert!(peer.client.account_db()?.client_record("device", "alice")?.is_none());
    assert!(peer.client.observed_device_set(&expected)?.is_none());
    assert_eq!(peer.client.account_db()?.pair_peer_devices("bob")?, Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn mismatching_revocation_ack_fences_local_traffic_and_retries_the_identical_signed_record()
-> TestResult {
    let owner = Actor::new("alice", "alice", 161, 162, 1)?;
    let manifest = owner.manifest()?;
    observe(&owner.client, &manifest)?;
    let old = manifest.signed_device_set.ok_or("set")?;
    let pair = ramflux_crypto::DmSession::initiator(
        [1; 32],
        dm_device_id_hash("alice"),
        dm_device_id_hash("peer"),
        [2; 32],
    )?;
    owner.client.persist_pair("alice", "peer", &[3; 32], &pair)?;
    let certified = rcgen::generate_simple_self_signed(vec!["retry.test".into()])?;
    let ca = owner.path.join("ca.pem");
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
        let mut first = None;
        for index in 0..4 {
            let (socket, _) = listener.accept().await?;
            let mut stream =
                tokio_rustls::TlsAcceptor::from(Arc::new(config.clone())).accept(socket).await?;
            let len = stream.read_u32().await?;
            if len > 65536 {
                return Err(std::io::Error::other("oversized test request"));
            }
            let mut bytes = vec![0; len as usize];
            stream.read_exact(&mut bytes).await?;
            let request: ramflux_transport::GatewayQuicRequest = serde_json::from_slice(&bytes)?;
            let body = if index % 2 == 0 {
                assert_eq!(request.method, "GET");
                serde_json::to_value(&old)?
            } else {
                assert_eq!(request.method, "POST");
                let record: SignedDeviceSetRecord =
                    serde_json::from_value(request.body["record"].clone())?;
                if let Some(first) = &first {
                    assert_eq!(&record, first);
                } else {
                    first = Some(record.clone());
                }
                if index == 1 { serde_json::to_value(&old)? } else { serde_json::to_value(record)? }
            };
            let response =
                serde_json::to_vec(&ramflux_transport::GatewayQuicResponse { status: 200, body })?;
            stream.write_u32(u32::try_from(response.len()).map_err(std::io::Error::other)?).await?;
            stream.write_all(&response).await?;
            stream.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });
    let gateway = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: address,
        server_name: "retry.test".into(),
        ca_cert: ca,
        principal_id: "alice".into(),
        device_id: "alice".into(),
        target_delivery_id: "alice".into(),
        prekey_http_url: None,
    });
    assert!(owner.client.revoke_owned_device(&gateway, "alice").await.is_err());
    assert_eq!(
        owner.client.account_db()?.load_actor_state::<bool>("device/revoked/alice")?,
        Some(true)
    );
    assert_eq!(owner.client.account_db()?.pair_peer_devices("alice")?, Vec::<String>::new());
    let pending = owner
        .client
        .account_db()?
        .load_actor_state::<SignedDeviceSetRecord>("identity/owned_pending_set")?
        .ok_or("pending")?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let accepted = owner.client.revoke_owned_device(&gateway, "alice").await?;
    assert_eq!(accepted, pending);
    assert_eq!(accepted.device_set_epoch, 2);
    assert!(
        owner
            .client
            .account_db()?
            .load_actor_state::<SignedDeviceSetRecord>("identity/owned_pending_set")?
            .is_none()
    );
    server.await??;
    Ok(())
}
