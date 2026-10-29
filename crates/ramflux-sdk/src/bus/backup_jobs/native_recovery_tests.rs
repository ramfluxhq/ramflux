// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh data restore, explicit phrase recovery and exact durable publication over real TLS.
use super::*;
use crate::custody::{CreationState, CustodyConnection, CustodyNetworkConfig, RecoveryCeremony};
use ramflux_protocol::custody::{BindingMode, CustodyRefusal};
use std::{path::Path, sync::Arc, time::Duration};

fn network(
    root: &Path,
    id: &str,
    device: &str,
    address: std::net::SocketAddr,
    ca: &Path,
) -> CustodyNetworkConfig {
    CustodyNetworkConfig {
        account_root: root.into(),
        account_id: id.into(),
        device_id: device.into(),
        gateway_address: address,
        server_name: "localhost".into(),
        ca_certificate: ca.into(),
        node_id: "node".into(),
        node_public_key: ramflux_crypto::fixture_public_key_base64url(),
        audience: "node".into(),
        binding_mode: BindingMode::DirectExporter,
        allow_no_channel_binding: false,
        allow_experimental_native_dm: false,
        timeout: Duration::from_secs(30),
    }
}
fn source_with_history(
    root: &Path,
    vault: &TestVault,
) -> TestResult<(crate::custody::BornAccount, zeroize::Zeroizing<String>)> {
    let (account, phrase) = crate::custody::tests::create_with_phrase(
        root,
        "account",
        vault,
        crate::custody::network_now()?,
    )?;
    let mut data = RamfluxClient::new();
    data.open_account_index(root)?;
    data.seal_new_account_data(
        "account",
        &account.record().body.account_anchor,
        LOCAL_SECRET.as_bytes(),
    )?;
    data.unlock_account("account", LOCAL_SECRET.as_bytes())?;
    data.account_db()?.store_message_content("thread", "history", b"restored inbound history")?;
    Ok((account, phrase))
}
async fn install_archive(
    source_root: &Path,
    target_root: &Path,
    vault: Arc<TestVault>,
) -> TestResult<String> {
    let source = supervisor(source_root)?;
    let archive = source_root.join("fresh-recovery.rfb");
    make_archive(&source, &archive).await?;
    source.shutdown().await?;
    let mut config = LocalBusConfig::new(target_root.join("bus.sock"), target_root);
    config.custody_vault = Some(vault);
    let target = Supervisor::new(config)?;
    let id = verify(&target, &archive).await?;
    call(&target, "account.restore.install", None, json!({"job_id":id,"passphrase":LOCAL_SECRET}))
        .await?;
    let installed = finished(&target, &id, crate::backup::BackupJobState::Done).await?;
    target.shutdown().await?;
    Ok(installed.archive.ok_or("preview")?.local_account_id)
}
fn assert_restored_history(root: &Path, id: &str) -> TestResult {
    let mut data = RamfluxClient::new();
    data.open_account_index(root)?;
    data.unlock_account(id, LOCAL_SECRET.as_bytes())?;
    assert_eq!(
        data.account_db()?.message_content("history")?,
        Some(b"restored inbound history".to_vec())
    );
    assert!(data.identity_root.is_none());
    Ok(())
}
fn assert_durable_authority(root: &Path, anchor: &str, expected: &str) -> TestResult {
    let durable = ramflux_node_core::RouterRedbStore::open(root.join("router.redb"))?;
    let router = durable.load_router()?.ok_or("durable router")?;
    let authority = router
        .custody_record(anchor, crate::custody::network_now()?)?
        .ok_or("durable authority")?;
    assert_eq!(ramflux_protocol::custody::object_hash(&authority.record)?, expected);
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn native_fresh_restore_requires_phrase_recovery_and_exact_ack_before_live() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let source_root = Root::new()?;
            let target_root = Root::new()?;
            let server_root = Root::new()?;
            let server_root = crate::custody::network_tests::Root(server_root.0.clone());
            let (address, ca, server) =
                crate::custody::network_tests::start_server_with_ack_fault(&server_root, true)
                    .await
                    .map_err(|error| -> Box<dyn std::error::Error> { error })?;
            let vault = Arc::new(TestVault::default());
            let (source_account, phrase) = source_with_history(&source_root.0, vault.as_ref())?;
            let old = CustodyConnection::connect(
                network(&source_root.0, "account", "primary", address, &ca),
                vault.clone(),
            )
            .await?;
            let local = install_archive(&source_root.0, &target_root.0, vault.clone()).await?;
            let pending = crate::custody::load_account(
                &target_root.0,
                &local,
                crate::custody::network_now()?,
            )?;
            let device = pending.local_device_id()?.to_owned();
            assert!(pending.branch_pending());
            assert_eq!(pending.state(), CreationState::NetworkingPending);
            assert_ne!(device, "primary");
            assert!(matches!(
                CustodyConnection::connect(
                    network(&target_root.0, &local, &device, address, &ca),
                    vault.clone()
                )
                .await,
                Err(SdkError::NetworkingPending)
            ));
            // An already available old primary did not certify this installation's fresh branch.
            vault.primary_for_public_key(
                &source_account.record().body.master_certificate.body.self_signing_public_key,
            )?;
            let recovery =
                RecoveryCeremony::begin(&target_root.0, &local, crate::custody::network_now()?)?;
            let recovered = recovery.confirm(
                &phrase,
                &pending.record().body.account_anchor,
                vault.as_ref(),
                crate::custody::network_now()?,
            )?;
            assert_eq!(recovered.local_device_id()?, device);
            assert!(matches!(
                CustodyConnection::connect(
                    network(&target_root.0, &local, &device, address, &ca),
                    vault.clone()
                )
                .await,
                Err(SdkError::CustodySetupInvalid)
            ));
            assert_eq!(
                crate::custody::load_account(
                    &target_root.0,
                    &local,
                    crate::custody::network_now()?
                )?
                .state(),
                CreationState::NetworkingPending
            );
            let live = CustodyConnection::connect(
                network(&target_root.0, &local, &device, address, &ca),
                vault.clone(),
            )
            .await?;
            assert_eq!(live.account().state(), CreationState::Live);
            // A fresh proof using the retained old key is refused independently of session expiry.
            assert!(matches!(
                CustodyConnection::connect(
                    network(&source_root.0, "account", "primary", address, &ca),
                    vault.clone()
                )
                .await,
                Err(SdkError::CustodyNetwork(
                    CustodyRefusal::InvalidInput | CustodyRefusal::PersistenceUnavailable
                ))
            ));
            let accepted_hash = ramflux_protocol::custody::object_hash(live.account().record())?;
            let accepted_anchor = live.account().record().body.account_anchor.clone();
            crate::custody::finish_recovery(
                &target_root.0,
                &local,
                vault.as_ref(),
                crate::custody::network_now()?,
            )?;
            assert_restored_history(&target_root.0, &local)?;
            drop(live);
            drop(old);
            server.await?.map_err(|error| -> Box<dyn std::error::Error> { error })?;
            assert_durable_authority(&server_root.0, &accepted_anchor, &accepted_hash)?;
            Ok(())
        }))
        .await
}
