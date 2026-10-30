// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Slow directory responses must finish before automatic sibling discovery is projected.
use super::*;
use crate::bus::runtime_tests;
use crate::client::identity_authority::test_support;
use std::sync::{Arc, atomic::AtomicBool};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn slow_own_manifest_refresh_persists_sibling_and_expands_group_without_epoch_change()
-> TestResult {
    let root = runtime_tests::root("slow-own-manifest");
    let mut owner = runtime_tests::account(
        &root.join("owner"),
        "owner",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let mut sibling = runtime_tests::account(
        &root.join("sibling"),
        "sibling",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    sibling.client.create_identity_root(
        "owner",
        ramflux_crypto::blake3_256("ramflux.test.account.root.v1", b"owner"),
    );
    sibling.client.create_device_branch("owner", "device-sibling", 1, [0x73; 32]);
    let previous = test_support::public_manifest(&owner.client)?;
    owner.client.persist_identity_directory(&previous)?;
    owner.client.shared_group_create("group", "thread", None, "target")?;
    assert_eq!(owner.client.group_state("group")?.members.len(), 1);
    let mut updated = previous;
    updated.devices.extend(test_support::public_manifest(&sibling.client)?.devices);
    test_support::sign_manifest(
        owner.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut updated,
        2,
    )?;
    let expected_root = updated.principal_commitment.clone();
    let (config, server) = slow_directory(&root, owner.gateway_config.clone(), updated).await?;
    owner.engine = None;
    owner.gateway_config = config;
    let result = drive(&owner).await;
    if result.is_err() {
        server.abort();
    }
    result?;
    server.await??;
    let observed = owner.client.observed_device_set(&expected_root)?.ok_or("device set missing")?;
    assert_eq!(observed.device_set_epoch, 2);
    assert!(observed.devices.iter().any(|device| device.device_id == "device-sibling"));
    let persisted: crate::prekey::SdkDeviceManifestResponse = owner
        .client
        .account_db()?
        .load_actor_state(&format!("identity/manifest-root/{expected_root}"))?
        .ok_or("manifest was not persisted")?;
    assert_eq!(persisted.devices.len(), 2);
    let group = owner.client.group_state("group")?;
    assert_eq!(group.group_epoch, 1);
    assert!(group.members.contains("device-sibling"));
    assert_eq!(group.members.len(), 2);
    drop((owner, sibling));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(crate) async fn slow_directory(
    root: &Path,
    mut config: GatewaySessionConfig,
    manifest: crate::prekey::SdkDeviceManifestResponse,
) -> TestResult<(GatewaySessionConfig, tokio::task::JoinHandle<Result<(), SdkError>>)> {
    let certificate = rcgen::generate_simple_self_signed(vec!["slow-directory.test".into()])?;
    let ca = root.join("slow-directory.pem");
    std::fs::write(&ca, certificate.cert.pem())?;
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let mut stream = tokio_rustls::TlsStream::Server(acceptor.accept(socket).await?);
        let request: ramflux_transport::GatewayQuicRequest =
            ramflux_transport::read_gateway_session_json(&mut stream).await?;
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            format!("/mvp1/device-manifest/{}", manifest.principal_commitment)
        );
        // Delay after the request is received: the previous 250ms caller budget must cancel it.
        tokio::time::sleep(Duration::from_millis(400)).await;
        ramflux_transport::write_gateway_session_json(
            &mut stream,
            &ramflux_transport::GatewayQuicResponse {
                status: 200,
                body: serde_json::to_value(manifest)?,
            },
        )
        .await?;
        Ok(())
    });
    config.transport_kind = GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "slow-directory.test".into();
    config.ca_cert = ca;
    config.timeout = Duration::from_secs(5);
    Ok((config, task))
}
