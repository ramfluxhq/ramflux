// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Slow directory responses must finish before automatic sibling discovery is projected.
use super::*;
use crate::bus::runtime_tests;
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn slow_own_manifest_refresh_persists_sibling_and_expands_group_without_epoch_change()
-> TestResult {
    use crate::client::native_test_support::{
        Fixture as Native, activation_send::tests::publish_layer_four, bus,
    };
    let root = runtime_tests::root("slow-own-manifest");
    std::fs::create_dir_all(&root)?;
    let mut native = Box::pin(Native::with_principal("owner", "device-owner", "owner")).await?;
    Box::pin(publish_layer_four(&mut native)).await?;
    let mut owner = native.into_bus();
    let anchor = owner.client.own_account_anchor()?;
    let custody_key = format!("identity/custody/{anchor}");
    let manifest_key = format!("identity/manifest-root/{anchor}");
    let stale_custody: serde_json::Value =
        owner.client.account_db()?.load_actor_state(&custody_key)?.ok_or("custody cache")?;
    let stale_manifest: Option<serde_json::Value> =
        owner.client.account_db()?.load_actor_state(&manifest_key)?;
    // A real second device joins the certified root; the owner's cache then rolls back to the
    // roster it knew before, so only the slow directory reply can teach it the sibling.
    let sibling = Box::pin(bus::sibling(&mut owner, "owner", "device-sibling")).await?;
    let updated =
        owner.client.native_bus_fixture.as_ref().ok_or("native manifest")?.manifest.clone();
    let db = owner.client.account_db()?;
    db.persist_actor_state(&custody_key, &stale_custody)?;
    match &stale_manifest {
        Some(value) => db.persist_actor_state(&manifest_key, value)?,
        None => db.remove_actor_state(&manifest_key)?,
    }
    let sibling_member = sibling.client.owned_device_identity()?.device_id().to_owned();
    let own_member = owner.client.owned_device_identity()?.device_id().to_owned();
    owner.client.fixture_group_create("group", "thread", None, "device-owner")?;
    let before = owner.client.group_state("group")?;
    assert_eq!(before.members.len(), 1);
    assert!(before.members.contains(&own_member));
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
    let authority = owner
        .client
        .current_custody_authority(&expected_root, crate::custody::network_now()?)?
        .ok_or("custody authority missing")?;
    assert!(authority.envelope().body.device_set_epoch >= 2);
    assert!(
        authority.envelope().body.devices.iter().any(|device| device.device_id == "device-sibling")
    );
    let persisted: crate::prekey::SdkDeviceManifestResponse = owner
        .client
        .account_db()?
        .load_actor_state(&format!("identity/manifest-root/{expected_root}"))?
        .ok_or("manifest was not persisted")?;
    assert_eq!(persisted.devices.len(), 2);
    let group = owner.client.group_state("group")?;
    assert_eq!(group.group_epoch, 1);
    assert!(group.members.contains(&sibling_member));
    assert_eq!(group.members.len(), 2);
    drop((owner, sibling));
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
