// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh data restore, explicit phrase recovery and exact durable publication over real TLS.
use super::*;
use crate::custody::{CreationState, CustodyConnection, CustodyNetworkConfig, RecoveryCeremony};
use ramflux_protocol::custody::{BindingMode, CustodyRefusal};
use ramflux_protocol::message as g;
use std::{path::Path, sync::Arc, time::Duration};

fn network(
    root: &Path,
    id: &str,
    device: &str,
    address: std::net::SocketAddr,
    ca: &Path,
) -> CustodyNetworkConfig {
    CustodyNetworkConfig {
        pairing_admission: None,
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
    let result = installed.installed_account.ok_or("installed account result")?;
    assert_eq!(result.networking, Some(CreationState::NetworkingPending));
    let local = result.local_account_id;
    let listing = call(&target, "account.list", None, json!({})).await?;
    assert!(listing["account_details"].as_array().ok_or("account details")?.iter().any(|row| {
        row["local_account_id"] == local && row["networking"] == "networking_pending"
    }));
    let status = call(&target, "account.status", Some(&local), json!({})).await?;
    assert_eq!(status["networking"], "networking_pending");
    assert_eq!(status["state"], "locked");
    target.shutdown().await?;
    Ok(local)
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
async fn prepare_ordinary_branch(
    root: &Path,
    id: &str,
    device: &str,
    vault: Arc<TestVault>,
) -> TestResult {
    let mut ordinary = RamfluxClient::new();
    ordinary.open_account_index(root)?;
    ordinary.unlock_account(id, LOCAL_SECRET.as_bytes())?;
    ordinary.initialize_born_v3_branch(device, vault).await?;
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
            // Ordinary activation prepares the certified branch before publishing recovery.
            prepare_ordinary_branch(&target_root.0, &local, &device, vault.clone()).await?;
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

fn persist_outbound_history(client: &RamfluxClient, sender: &str) -> TestResult {
    let identity = client.allocate_generated_identity(
        "outbound-thread",
        u64::try_from(crate::time::now_unix_timestamp())?.saturating_mul(1000),
        false,
    )?;
    persist_generated_fixture(
        client,
        &identity,
        sender,
        b"opaque encrypted outbound envelope",
        "restored outgoing history",
    )?;
    Ok(())
}

async fn assert_restored_outbound_history(reader: &RamfluxClient) -> TestResult {
    let messages = reader.direct_messages("outbound-thread")?;
    let stored = messages.first().ok_or("test: outbound history missing")?;
    assert_eq!(
        stored.encrypted_body, b"opaque encrypted outbound envelope",
        "restore must retain outgoing ciphertext"
    );
    {
        let method = "message.read";
        let request = LocalBusFrame::request(
            "restored-outbound-history",
            None,
            "message",
            method,
            json!({"conversation_id":"outbound-thread","read_model":true}),
        );
        let page =
            crate::bus::readers::test_account_reader_request(reader.account_db()?, request).await?;
        assert_eq!(
            page["schema"], "ramflux.message.read_model.v1",
            "reader must expose the activated contract"
        );
        let messages = page["messages"].as_array().ok_or("test: unified message page missing")?;
        let [message] = messages.as_slice() else {
            return Err("test: restored outgoing message count differs".into());
        };
        assert_eq!(
            message["text"], "restored outgoing history",
            "restored raw Inner must reach the unified reader"
        );
    }
    Ok(())
}

async fn recover_read_projection(
    root: &Path,
    id: &str,
    phrase: &zeroize::Zeroizing<String>,
    vault: Arc<TestVault>,
    reader: &mut RamfluxClient,
) -> TestResult {
    let recovery = RecoveryCeremony::begin(root, id, crate::custody::network_now()?)?;
    let anchor = recovery.account_anchor().to_owned();
    let recovered =
        recovery.confirm(phrase, &anchor, vault.as_ref(), crate::custody::network_now()?)?;
    reader.initialize_born_v3_branch(recovered.local_device_id()?, vault).await?;
    assert_eq!(
        crate::custody::load_account(root, id, crate::custody::network_now()?)?.state(),
        CreationState::NetworkingPending
    );
    assert_restored_outbound_history(reader).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_backup_fresh_restore_completes_offline_and_lists_pending_account() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let source = Root::new()?;
            let target = Root::new()?;
            let source_vault = Arc::new(TestVault::default());
            let (account, phrase) = source_with_history(&source.0, source_vault.as_ref())?;
            let mut data = RamfluxClient::new();
            data.open_account_index(&source.0)?;
            data.unlock_account("account", LOCAL_SECRET.as_bytes())?;
            data.initialize_born_v3_branch(account.local_device_id()?, source_vault.clone())
                .await?;
            let owner = data.owned_device_identity()?;
            persist_outbound_history(&data, owner.storage_key())
                .map_err(|error| format!("capture outbound fixture: {error}"))?;
            drop(data);
            // A distinct empty vault has no source signing credential and no configured node.
            let target_vault = Arc::new(TestVault::default());
            let id = install_archive(&source.0, &target.0, target_vault.clone())
                .await
                .map_err(|error| format!("install archive: {error}"))?;
            assert_restored_history(&target.0, &id)?;
            let mut restored = RamfluxClient::new();
            restored.open_account_index(&target.0)?;
            restored.unlock_account(&id, LOCAL_SECRET.as_bytes())?;
            let pending =
                crate::custody::load_account(&target.0, &id, crate::custody::network_now()?)?;
            assert!(pending.branch_pending());
            assert_eq!(pending.state(), CreationState::NetworkingPending);
            recover_read_projection(&target.0, &id, &phrase, target_vault, &mut restored)
                .await
                .map_err(|error| format!("recover read projection: {error}"))?;
            Ok(())
        }))
        .await
}

fn persist_generated_fixture(
    client: &RamfluxClient,
    identity: &g::EventIdentity,
    sender: &str,
    encrypted: &[u8],
    text: &str,
) -> TestResult<String> {
    let exact = RamfluxClient::encode_generated_inner(
        identity.clone(),
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: text.into(),
                ..Default::default()
            })),
        },
    )?;
    persist_generated_fixture_exact(client, identity, sender, encrypted, &exact)
}

fn persist_generated_fixture_exact(
    client: &RamfluxClient,
    identity: &g::EventIdentity,
    sender: &str,
    encrypted: &[u8],
    exact: &[u8],
) -> TestResult<String> {
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let db = client.account_db()?;
    db.write_transaction(|| {
        db.send_direct_message(&identity.conversation_id, &id, sender, encrypted)?;
        db.store_message_content(&identity.conversation_id, &id, exact)?;
        db.persist_message_actor_state(&id, &format!("routed/generated-identity/{id}"), &identity)?;
        let own_anchor = client.own_account_anchor()?;
        if identity.author.as_ref().is_some_and(|author| author.account_anchor == own_anchor) {
            db.mark_generated_message_owned(&id, &client.owned_device_identity()?)?;
        }
        db.persist_message_actor_state(
            &id,
            &format!("routed/generated-order/{id}"),
            &identity.hlc,
        )?;
        db.persist_message_actor_state(
            &id,
            &format!("routed/generated-display-hlc/{id}"),
            &identity.hlc,
        )?;
        client.journal_generated_receive_updates(exact)?;
        Ok::<_, SdkError>(())
    })?;
    Ok(id)
}

/// Real backup create -> verify -> install into a NEW root: archived peer authority is historical
/// evidence only. Neither its pins nor any network observation become live state in the new root.
#[tokio::test(flavor = "current_thread")]
async fn native_restore_into_a_new_root_imports_no_peer_authority_and_no_freshness() -> TestResult {
    crate::client::native_test_support::watchdog::within(LocalSet::new().run_until(Box::pin(
        async {
            let source_root = Root::new()?;
            let target_root = Root::new()?;
            let vault = Arc::new(TestVault::default());
            let (_account, _phrase) = source_with_history(&source_root.0, vault.as_ref())?;
            let peer = crate::client::native_test_support::Fixture::new("restore-pin-peer").await?;
            let root = peer.manifest.principal_commitment.clone();
            let record = peer
                .manifest
                .custody
                .as_ref()
                .ok_or("test: native peer")?
                .publication
                .record
                .clone();
            {
                let mut holder = RamfluxClient::new();
                holder.open_account_index(&source_root.0)?;
                holder.unlock_account("account", LOCAL_SECRET.as_bytes())?;
                holder.persist_observed_identity_directory_now(&peer.manifest)?;
                assert!(
                    holder.account_db()?.actor_state_exists(&format!("identity/custody/{root}"))?,
                    "test: the source must hold a retained peer authority to archive"
                );
            }
            let restored_id = install_archive(&source_root.0, &target_root.0, vault).await?;
            let mut restored = RamfluxClient::new();
            restored.open_account_index(&target_root.0)?;
            restored.unlock_account(&restored_id, LOCAL_SECRET.as_bytes())?;
            assert!(
                !restored.account_db()?.actor_state_exists(&format!("identity/custody/{root}"))?,
                "archived peer authority must not be installed as live state in the new root"
            );
            assert!(
                restored
                    .require_fresh_custody_head(
                        crate::client::identity_authority::HeadUse::NewAuthorization,
                        &root,
                        &record,
                    )
                    .is_err(),
                "a restore must not carry a network observation into the new root"
            );
            Ok(())
        },
    )))
    .await
    .map_err(|_| "test: deadline exceeded")?
}
