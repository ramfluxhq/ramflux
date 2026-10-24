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
    // The genuine signed set is independently admitted; substituted ready keys are not.
    assert!(peer.client.observed_device_set(&expected)?.is_some());
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
    seed_owned_peer_pair(&owner)?;
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
            let (socket, _) =
                tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                    .await??;
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
        owner
            .client
            .account_db()?
            .load_actor_state::<bool>(&owner.client.device_revocation_key("alice")?)?,
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

#[tokio::test]
async fn own_device_import_rejects_a_revoked_siblings_replayed_manifest_before_history_fetch()
-> TestResult {
    let source = Actor::new("alice", "one", 81, 82, 1)?;
    let target = Actor::new("alice", "two", 81, 83, 1)?;
    let mut old = source.manifest()?;
    old.devices.extend(target.manifest()?.devices);
    sign_set(&source, &mut old, 1)?;
    observe(&target.client, &old)?;
    let mut current = old.clone();
    let mut entries = old.signed_device_set.as_ref().ok_or("set")?.devices.clone();
    let revoked = entries.iter_mut().find(|entry| entry.device_id == "one").ok_or("source")?;
    revoked.status = DeviceSetStatus::Revoked;
    revoked.revoked_at = Some(now_unix_timestamp());
    current.signed_device_set = Some(ramflux_crypto::sign_device_set(
        source.client.identity_root.as_ref().ok_or("root")?,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: PrincipalKind::Human,
            device_set_epoch: 2,
            devices: entries,
        },
    )?);
    current.devices.retain(|device| device.device_id != "one");
    observe(&target.client, &current)?;
    let mut envelope = crate::client::own_device_sync::tests::envelope("one", "two");
    envelope.principal_commitment = old.principal_commitment.clone();
    envelope.created_at = now_unix_timestamp();
    envelope.expires_at = envelope.created_at + 3600;
    envelope.history_ref.key_slot.conversation_id =
        crate::own_device_sync::own_device_sync_slot_conversation_id(
            &envelope.snapshot_id,
            &envelope.history_ref.object_id,
            &envelope.target_device_id,
        );
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        source.client.device_branch.as_ref().ok_or("branch")?,
        &crate::own_device_sync::own_device_sync_signing_body(&envelope),
    )?;
    let before = target.client.observed_device_set(&old.principal_commitment)?;
    let (gateway, server) = manifest_server(&target.path, old.clone()).await?;
    let error = target
        .client
        .verify_own_device_sync_envelope(&gateway, &old.principal_commitment, &envelope)
        .await
        .err()
        .ok_or("revoked source with old manifest was accepted")?;
    server.await??;
    assert!(error.to_string().contains("epoch"), "{error}");
    assert_eq!(target.client.observed_device_set(&old.principal_commitment)?, before);
    assert!(
        target
            .client
            .require_cached_root_authority(&ramflux_protocol::qualified_device_id(
                &old.principal_commitment,
                "one"
            )?)
            .is_err()
    );
    assert_eq!(
        target.client.account_db()?.client_directory_ids("object", "", 100)?,
        Vec::<String>::new()
    );
    Ok(())
}

fn seed_owned_peer_pair(owner: &Actor) -> TestResult {
    let pair = ramflux_crypto::DmSession::initiator(
        [1; 32],
        dm_device_id_hash("alice"),
        dm_device_id_hash("peer"),
        [2; 32],
    )?;
    let peer = ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
        owner.client.identity_root.as_ref().ok_or("root")?,
        "peer",
    )?;
    owner.client.persist_pair("alice", peer.storage_key(), &[3; 32], &pair)?;
    Ok(())
}
