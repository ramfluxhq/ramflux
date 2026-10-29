// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real TLS public-directory refresh precedes branch-vault loading and account proofs.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use std::sync::atomic::Ordering;
async fn refresh(fixture: &Fixture, body: serde_json::Value) -> TestResult<Result<(), SdkError>> {
    refresh_at(&fixture.root.0, &fixture.config, &fixture.manifest.principal_commitment, body).await
}
async fn refresh_at(
    root: &std::path::Path,
    gateway: &GatewaySessionConfig,
    anchor: &str,
    body: serde_json::Value,
) -> TestResult<Result<(), SdkError>> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let ca = root.join("public-ca.pem");
    let cert = root.join("public-tls.pem");
    let key = root.join("public-tls.key");
    std::fs::write(&ca, certificate.cert.pem())?;
    std::fs::write(&cert, certificate.cert.pem())?;
    std::fs::write(&key, certificate.signing_key.serialize_pem())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        ramflux_transport::tcp_gateway_server_config(&ramflux_transport::MeshTlsConfig {
            ca_cert: ca.clone(),
            service_cert: cert,
            service_key: key,
        })?,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let anchor = anchor.to_owned();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = tokio_rustls::TlsStream::Server(acceptor.accept(stream).await?);
        let request: ramflux_transport::GatewayQuicRequest =
            ramflux_transport::read_gateway_session_json(&mut stream).await?;
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, format!("/mvp1/device-manifest/{anchor}"));
        assert!(request.body.is_null());
        ramflux_transport::write_gateway_session_json(
            &mut stream,
            &ramflux_transport::GatewayQuicResponse { status: 200, body },
        )
        .await?;
        Ok::<_, SdkError>(())
    });
    let mut config = gateway.clone();
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "localhost".into();
    config.ca_cert = ca;
    config.timeout = std::time::Duration::from_secs(2);
    let result =
        refresh_local_publication(&config, config.custody.as_ref().ok_or("custody")?).await;
    server.await??;
    Ok(result)
}
#[tokio::test]
async fn native_public_tls_refresh_updates_local_head_without_accessing_branch_vault() -> TestResult
{
    let fixture = Fixture::new("native-public-head-tls").await?;
    let mut native = fixture.manifest.custody.as_ref().ok_or("native")?.clone();
    let primary = fixture.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = native.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
    body.device_set_epoch += 1;
    body.profile.display_name = "TLS current head".into();
    native.publication.record = primary.sign_record(body)?;
    fixture.vault.fail.store(true, Ordering::SeqCst);
    assert!(fixture.vault.preflight().is_err());
    refresh(&fixture, serde_json::to_value(&native)?).await??;
    let loaded = crate::custody::load_account(
        &fixture.root.0,
        &fixture.client.account_db()?.local_account_id,
        crate::custody::network_now()?,
    )?;
    assert_eq!(loaded.record(), &native.publication.record);
    assert!(
        fixture
            .client
            .require_current_device_authorization(&fixture.client.owned_device_identity()?)
            .is_err()
    );
    fixture.client.persist_fetched_identity_directory(
        &crate::prekey::SdkDeviceManifestResponse::from_native(*native)?,
    )?;
    fixture
        .client
        .require_current_device_authorization(&fixture.client.owned_device_identity()?)?;
    Ok(())
}
#[tokio::test]
async fn native_public_tls_refresh_refuses_bad_signature_and_missing_previously_live_head()
-> TestResult {
    let fixture = Fixture::new("native-public-refusal-tls").await?;
    let mut native = fixture.manifest.custody.as_ref().ok_or("native")?.clone();
    native.publication.record.body.profile.display_name = "Unauthenticated update".into();
    assert!(refresh(&fixture, serde_json::to_value(native)?).await?.is_err());
    let id = &fixture.client.account_db()?.local_account_id;
    let now = crate::custody::network_now()?;
    let loaded = crate::custody::load_account(&fixture.root.0, id, now)?;
    assert_eq!(
        loaded.record(),
        &fixture.manifest.custody.as_ref().ok_or("native")?.publication.record
    );
    assert!(refresh(&fixture, serde_json::Value::Null).await?.is_ok());
    crate::custody::tests::mark_live(&fixture.root.0, id, now)?;
    assert!(refresh(&fixture, serde_json::Value::Null).await?.is_err());
    Ok(())
}

#[tokio::test]
async fn native_pending_recovery_publishes_before_refreshing_the_old_directory_head() -> TestResult
{
    let fixture = Fixture::new("recovery-directory-config").await?;
    let root = crate::custody::tests::Root::new()?;
    let vault = Arc::new(crate::custody::tests::TestVault::default());
    let now = crate::custody::network_now()?;
    let (original, phrase) =
        crate::custody::tests::create_with_phrase(&root.0, "recovery", vault.as_ref(), now)?;
    let anchor = original.record().body.account_anchor.clone();
    let old_directory = crate::prekey::SdkDeviceManifestResponse::from_native(
        ramflux_protocol::custody::CustodyManifest {
            publication: original.publication(),
            custodian_publication: None,
            devices: Vec::new(),
        },
    )?;
    let mut config = fixture.config.clone();
    config.custody = Some(GatewayCustodyConfig {
        account_root: root.0.clone(),
        account_id: "recovery".into(),
        node_id: "fixture-node".into(),
        node_public_key: ramflux_protocol::encode_base64url([7; 32]),
        vault: vault.clone(),
    });
    let pending = crate::custody::RecoveryCeremony::begin(&root.0, "recovery", now)?;
    let recovered = pending.confirm(&phrase, &anchor, vault.as_ref(), now)?;
    assert!(recovered.recovery_publication_pending(&root.0)?);
    let mut forged = old_directory.clone();
    forged.custody.as_mut().ok_or("native")?.publication.record.body.profile.display_name =
        "forged predecessor".into();
    assert!(refresh_at(&root.0, &config, &anchor, serde_json::to_value(forged)?).await?.is_err());
    // The directory necessarily still serves the predecessor before the recovery publish.
    refresh_at(&root.0, &config, &anchor, serde_json::to_value(&old_directory)?).await??;
    let loaded = crate::custody::load_account(&root.0, "recovery", now)?;
    assert_eq!(loaded.record(), recovered.record());
    assert!(loaded.recovery_publication_pending(&root.0)?);
    assert_eq!(loaded.state(), crate::custody::CreationState::NetworkingPending);
    crate::custody::tests::mark_live(&root.0, "recovery", now)?;
    assert!(
        refresh_at(&root.0, &config, &anchor, serde_json::to_value(old_directory)?).await?.is_err()
    );
    Ok(())
}
