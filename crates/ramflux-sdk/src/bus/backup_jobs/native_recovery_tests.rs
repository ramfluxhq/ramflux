// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh data restore, explicit phrase recovery and exact durable publication over real TLS.
use super::*;
use crate::custody::{CreationState, CustodyConnection, CustodyNetworkConfig, RecoveryCeremony};
use prost::Message as _;
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
    for method in ["message.list", "message.read"] {
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

fn assert_restored_group_history(
    reader: &RamfluxClient,
    expected: &ramflux_protocol::GroupStateSnapshot,
) -> TestResult {
    let state =
        reader.account_db()?.shared_group_state("restore-group")?.ok_or("reader signed group")?;
    assert_eq!(*state.snapshot(), *expected);
    assert_eq!(reader.groups()?.len(), 1);
    assert!(
        matches!(reader.shared_group_selected_devices(&state), Err(SdkError::InboundPending(_))),
        "historical display must not supply current roster authority"
    );
    let rows = reader.direct_messages("restore-group-thread")?;
    let mut history = false;
    let mut fences = 0_u32;
    for message in &rows {
        let exact = reader
            .account_db()?
            .message_content(&message.message_id)?
            .ok_or("test: restored group Inner missing")?;
        let (_, content) = RamfluxClient::decode_generated_inner(&exact)?;
        match content.value {
            Some(g::content::Value::Message(value)) if value.text == "restored group history" => {
                history = true;
            }
            Some(g::content::Value::Service(_)) => {
                let stored = reader.account_db()?.service_body_fence(&message.message_id)?;
                let expected = ramflux_crypto::blake3_256("ramflux.group-service-body.v1", &exact);
                if stored.as_deref() != Some(expected.as_slice()) {
                    return Err("test: restored service body fence differs".into());
                }
                fences = fences.saturating_add(1);
            }
            _ => return Err("test: restored group row is not history or a service event".into()),
        }
    }
    if !history {
        return Err("test: restored group history missing".into());
    }
    if fences == 0 {
        return Err("test: restored service body fence is missing".into());
    }
    Ok(())
}

async fn recover_group_read_projection(
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
    let view = crate::bus::read_model::row(reader, "conversation", "restore-group-thread")?;
    assert_eq!(view["group_id"], "restore-group");
    assert_eq!(view["participants"].as_array().map(Vec::len), Some(2));
    assert!(
        view["member_routes"]
            .as_array()
            .ok_or("member routes")?
            .iter()
            .all(|row| row["delivery_target_known"] == false)
    );
    let state = reader.account_db()?.shared_group_state("restore-group")?.ok_or("signed group")?;
    assert!(
        reader.shared_group_member_routes(&state).is_err(),
        "read projection granted send authority"
    );
    assert_eq!(
        crate::custody::load_account(root, id, crate::custody::network_now()?)?.state(),
        CreationState::NetworkingPending
    );
    let page = reader.generated_message_view_page("restore-group-thread", None, 100)?;
    let repeated = reader.generated_message_view_page("restore-group-thread", None, 100)?;
    assert_eq!(
        serde_json::to_value(&page)?,
        serde_json::to_value(&repeated)?,
        "repeated reads must preserve the restored durable view"
    );
    let history = page
        .messages
        .iter()
        .find(|message| message.text.as_deref() == Some("restored group history"))
        .ok_or("test: restored group history missing from the view")?;
    assert_eq!(
        history.text.as_deref(),
        Some("restored group history"),
        "restored group raw Inner must render"
    );
    assert!(
        page.messages.iter().any(|message| message.kind == "service"),
        "restored service rows must stay beside the generated message"
    );
    assert!(
        reader.generated_message_view_page("unbound-thread", None, 100)?.messages.is_empty(),
        "history must remain scoped to its signed conversation"
    );
    assert_restored_outbound_history(reader).await?;
    Ok(())
}

fn persist_group_driver_progress(data: &RamfluxClient) -> TestResult {
    // A drained native daemon retains operational cursors beside signed group snapshots.
    let db = data.account_db()?;
    db.persist_actor_state("group-state/driver-progress", &"group-state/send/cmVzdG9yZS1ncm91cA")?;
    db.persist_actor_state(
        "group-state/recovery-progress",
        &json!({
            "device_set_epoch": 1, "after": "restore-group", "complete": true,
        }),
    )?;
    Ok(())
}

fn history_manifest(
    data: &RamfluxClient,
    account: &crate::custody::BornAccount,
) -> TestResult<crate::prekey::SdkDeviceManifestResponse> {
    let owner = data.owned_device_identity()?;
    let manifest = crate::prekey::SdkDeviceManifestResponse::from_native(
        ramflux_protocol::custody::CustodyManifest {
            publication: account.publication(),
            custodian_publication: None,
            devices: vec![ramflux_protocol::custody::CustodyManifestDevice {
                device_ref: ramflux_protocol::custody::DeviceRef {
                    account_anchor: owner.root_commitment().into(),
                    device_id: owner.device_id().into(),
                    device_epoch: 1,
                },
                target_delivery_id: owner.storage_key().into(),
                prekey_bundle: serde_json::to_value(data.load_x3dh_private_state(&owner)?.bundle)?,
                message_layer: None,
            }],
        },
    )?;
    Ok(manifest)
}

async fn source_group_history(
    data: &RamfluxClient,
    account: &crate::custody::BornAccount,
    vault: &TestVault,
) -> TestResult<ramflux_protocol::GroupStateSnapshot> {
    let owner = data.owned_device_identity()?;
    let primary = account.group_primary(vault)?;
    let peer = crate::client::native_test_support::Fixture::with_device(
        "restore-group-peer",
        "peer-device",
    )
    .await?;
    data.persist_fetched_identity_directory(&peer.manifest)
        .map_err(|error| format!("cache peer authority: {error}"))?;
    let owner_manifest = history_manifest(data, account)
        .map_err(|error| format!("source own authority: {error}"))?;
    data.persist_fetched_identity_directory(&owner_manifest)
        .map_err(|error| format!("cache own authority: {error}"))?;
    peer.client
        .persist_fetched_identity_directory(&owner_manifest)
        .map_err(|error| format!("cache owner at peer: {error}"))?;
    data.shared_group_create_with_primary(
        "restore-group",
        "restore-group-thread",
        Some("Restored group".into()),
        owner.storage_key(),
        Some(&primary),
    )
    .map_err(|error| format!("construct source group: {error}"))?;
    let member = peer.client.owned_device_identity()?;
    let group = data
        .shared_group_change_with_primary(
            "restore-group",
            owner.storage_key(),
            ramflux_protocol::GroupStateChange::Add {
                member: peer.client.owned_group_actor(member.storage_key())?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
            Some(&primary),
        )
        .map_err(|error| format!("construct source group: {error}"))?;
    peer.client
        .accept_shared_group_state(&group, member.storage_key())
        .map_err(|error| format!("accept group snapshot: {error}"))?;
    let distribution = zeroize::Zeroizing::new(
        peer.client
            .export_group_sender_key_distribution("restore-group", member.device_id())
            .map_err(|error| format!("export peer group key: {error}"))?,
    );
    data.import_group_sender_key_distribution(&distribution)
        .map_err(|error| format!("import sender key: {error}"))?;
    let mut identity = peer.client.allocate_generated_identity(
        "restore-group-thread",
        u64::try_from(crate::time::now_unix_timestamp())?.saturating_mul(1000),
        false,
    )?;
    identity.group_id = Some("restore-group".into());
    identity.group_epoch = Some(group.view().epoch);
    let exact = RamfluxClient::encode_generated_inner(
        identity.clone(),
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "restored group history".into(),
                ..Default::default()
            })),
        },
    )?;
    let inner = g::Inner::decode(exact.as_slice())?;
    let wrapped = peer.client.encrypt_generated_group_message(
        "restore-group",
        member.device_id(),
        &g::Message::decode(inner.body.as_slice())?,
    )?;
    let sealed = wrapped.sealed_group.as_ref().ok_or("native group wrapper")?;
    let native = crate::client::generated_group::to_native(sealed)?;
    let event_id = ramflux_protocol::encode_base64url(&identity.id);
    let plaintext = data.decrypt_group_envelope_for_identity(&native, &event_id, &member)?;
    assert_eq!(
        plaintext, inner.body,
        "native group crypto must preserve the exact prepared Message before backup"
    );
    let encrypted = g::Inner { body: wrapped.encode_to_vec(), ..inner }.encode_to_vec();
    persist_generated_fixture_exact(data, &identity, member.storage_key(), &encrypted, &exact)?;
    persist_group_driver_progress(data)?;
    persist_outbound_history(data, owner.storage_key())
        .map_err(|error| format!("capture outbound fixture: {error}"))?;
    Ok(group.snapshot().clone())
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
            let expected_group =
                Box::pin(source_group_history(&data, &account, source_vault.as_ref())).await?;
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
            assert_restored_group_history(&restored, &expected_group)
                .map_err(|error| format!("read restored group: {error}"))?;
            let pending =
                crate::custody::load_account(&target.0, &id, crate::custody::network_now()?)?;
            assert!(pending.branch_pending());
            assert_eq!(pending.state(), CreationState::NetworkingPending);
            recover_group_read_projection(&target.0, &id, &phrase, target_vault, &mut restored)
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
