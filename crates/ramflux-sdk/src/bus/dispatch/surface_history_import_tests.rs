// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed own-history import commits plaintext/group state and a bounded idempotency receipt.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, atomic::AtomicBool};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

async fn cached_history(
    source: &LocalBusAccountState,
    target: &mut LocalBusAccountState,
    config: GatewaySessionConfig,
) -> TestResult<crate::own_device_sync::SdkOwnDeviceSyncEnvelope> {
    let root = super::fixture::manifest(&source.client)?.principal_commitment;
    let bundle = serde_json::json!({"schema":"ramflux.sdk.own_device_history_bundle.v1","version":1,"principal_commitment":root,"source_device_id":"device-sender","target_device_id":"device-sibling","snapshot_id":"history-retry","messages":source.client.direct_messages("history-thread")?,"contents":{"history-message":b"private restored text".to_vec()},"dm_sessions":[],"groups":[{"group_id":"history-group","group_epoch":2,"max_members":128,"new_member_history":"none","local_role":"member","local_joined_epoch":1,"members":[{"member_id":"device-sender","role":"owner","joined_epoch":1},{"member_id":"device-sibling","role":"member","joined_epoch":1}],"routes":[]}],"sender_key_distributions_base64":[]});
    let object =
        target.client.put_encrypted_object("history-object", &serde_json::to_vec(&bundle)?)?;
    let slot_conversation = crate::own_device_sync::own_device_sync_slot_conversation_id(
        "history-retry",
        &object.object_id,
        "device-sibling",
    );
    let request: LocalBusMessageSubmitRequest = serde_json::from_value(
        json!({"conversation_id":slot_conversation,"message_id":"history-retry","envelope_id":"history-retry","source_principal_id":"sender","sender_id":"device-sender","recipient_device_id":"device-sibling","recipient_principal_commitment":root,"target_delivery_id":"sibling","encrypted_body_base64":"","created_at":now_unix_timestamp(),"ttl":3600}),
    )?;
    let mut engine = GatewaySessionEngine::with_test_transport(
        config,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let key = zeroize::Zeroizing::new(
        target
            .client
            .account_db()?
            .load_object::<Value>(&object.object_id)?
            .and_then(|(_, key)| key)
            .ok_or("cached key")?,
    );
    let slot = source
        .client
        .make_pair_object_slot(
            &mut engine,
            &request.into_gateway_message_with_body(Vec::new()),
            &object.object_id,
            &key,
            &slot_conversation,
        )
        .await?;
    let mut envelope = crate::own_device_sync::SdkOwnDeviceSyncEnvelope {
        schema: "ramflux.sdk.own_device_sync.v1".into(),
        version: 1,
        principal_commitment: root,
        source_device_id: "device-sender".into(),
        target_device_id: "device-sibling".into(),
        snapshot_id: "history-retry".into(),
        snapshot_kind: "history_bundle".into(),
        created_at: now_unix_timestamp(),
        expires_at: now_unix_timestamp() + 3600,
        nonce: "history-nonce".into(),
        history_ref: crate::dm::SdkDmAttachmentRef {
            schema: "ramflux.sdk.dm_attachment_ref.v1".into(),
            version: 1,
            object_id: object.object_id,
            manifest_hash: object.manifest_hash,
            plaintext_hash: object.plaintext_hash,
            cipher_size: u64::try_from(object.ciphertext.len())?,
            chunk_size: 4096,
            total_chunks: 1,
            relay_endpoint: "http://127.0.0.1:1".into(),
            owner_home_node_id: None,
            relay_audience_node_id: None,
            owner_principal_id: String::new(),
            owner_device_epoch: 0,
            access_grant: None,
            key_slot: slot,
        },
        signed: sdk_device_signed_fields("device-sender", ""),
    };
    envelope.signed.signature = ramflux_crypto::sign_with_device_branch(
        source.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &crate::own_device_sync::own_device_sync_signing_body(&envelope),
    )?;
    Ok(envelope)
}
#[tokio::test]
async fn signed_cached_own_history_import_commits_and_replays_without_weakening_auth() -> TestResult
{
    let root = runtime_tests::root("history-import-receipt");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (mut target, config, receiver, directory) =
        super::own_tests::sibling_fixture(&root, &mut source).await?;
    source.client.send_direct_message(
        "history-thread",
        "history-message",
        "device-sender",
        b"ciphertext",
    )?;
    let envelope = Box::pin(cached_history(&source, &mut target, config)).await?;
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let mut engine = GatewaySessionEngine::with_test_transport(
        receiver,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let result = target
        .client
        .import_own_device_sync(&mut engine, &pool, &envelope.principal_commitment, &envelope, None)
        .await?;
    assert_eq!(result.imported_messages, 1);
    assert_eq!(result.imported_groups, 1);
    assert!(target.client.group_state("history-group")?.members.contains("device-sibling"));
    assert_eq!(
        target.client.account_db()?.message_content("history-message")?.as_deref(),
        Some(b"private restored text".as_slice())
    );
    let replay = target
        .client
        .import_own_device_sync(&mut engine, &pool, &envelope.principal_commitment, &envelope, None)
        .await?;
    assert_eq!(serde_json::to_value(replay)?, serde_json::to_value(&result)?);
    assert_eq!(target.client.direct_messages("history-thread")?.len(), 1);
    let mut forged = envelope.clone();
    forged.signed.signature = "invalid".into();
    assert!(
        target
            .client
            .import_own_device_sync(
                &mut engine,
                &pool,
                &envelope.principal_commitment,
                &forged,
                None
            )
            .await
            .is_err()
    );
    assert_eq!(target.client.direct_messages("history-thread")?.len(), 1);
    let db = target.client.account_db()?;
    let receipt = RamfluxClient::own_sync_receipt_key(&envelope)?;
    assert!(
        db.prune_surface_records("own-device/imported/", 512, 256 * 1024, &receipt).is_err(),
        "surface namespace authorization must stay strict"
    );
    db.persist_actor_state(
        "own-device/imported-neighbor/keep",
        &json!({"expires_at":now_unix_timestamp()+3600}),
    )?;
    for index in 0..4 {
        let mut large = envelope.clone();
        large.snapshot_id = format!("{}-{index}", "x".repeat(100_000));
        let mut cached = result.clone();
        cached.snapshot_id = large.snapshot_id.clone();
        target.client.cache_own_sync_import_receipt(&large, &cached)?;
        let (rows, bytes) = db.actor_state_usage("own-device/imported/")?;
        assert!(rows <= 512 && bytes <= 256 * 1024);
        assert!(db.actor_state_exists(&RamfluxClient::own_sync_receipt_key(&large)?)?);
    }
    assert!(db.actor_state_exists("own-device/imported-neighbor/keep")?);
    directory.abort();
    drop(target);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn retired_relay_keys_refuse_device_sync_ipc_before_cached_receipts_or_session_work()
-> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(20), Box::pin(async {
        let directory = tempfile::TempDir::new()?;
        let root = directory.path();
        let mut source = runtime_tests::account(
            &root.join("source"), "sender", None, Arc::new(AtomicBool::new(false)),
        )?;
        let (mut target, config, receiver, server) =
            super::own_tests::sibling_fixture(root, &mut source).await?;
        source.client.send_direct_message(
            "history-thread", "history-message", "device-sender", b"ciphertext",
        )?;
        let envelope = Box::pin(cached_history(&source, &mut target, config)).await?;
        let pool = ramflux_transport::RelayQuicPool::new(
            ramflux_transport::RelayQuicPoolConfig::functional_default()?,
        );
        let mut engine = GatewaySessionEngine::with_test_transport(
            receiver, Box::new(super::fixture::RecordingGateway::new(Arc::default())),
        );
        target.client.import_own_device_sync(
            &mut engine, &pool, &envelope.principal_commitment, &envelope, None,
        ).await?;
        server.abort();
        let receipt = RamfluxClient::own_sync_receipt_key(&envelope)?;
        let before = serde_json::to_value(target.client.account_db()?.load_actor_state::<Value>(&receipt)?)?;
        assert!(!before.is_null(), "test: real import must populate its durable receipt");
        let messages = serde_json::to_value(target.client.direct_messages("history-thread")?)?;
        let object = serde_json::to_value(target.client.object_store_object(&envelope.history_ref.object_id)?)?;
        let engine_present = target.engine.is_some();
        let mut state = LocalBusDaemonState {
            config: LocalBusConfig::new(root.join("bus.sock"), root),
            account_index: None, nodes: crate::node::NodeStore::default(),
            accounts: BTreeMap::from([("target".into(), target)]),
            active_account_id: Some("target".into()), attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        };
        for (method, body) in [
            ("device.sync.export", json!({"target_device_id":"device-sender","relay_endpoint":"quic://127.0.0.1:1","relay_service_key_base64":"retired-test-key","chunk_size":4096})),
            ("device.sync.import", json!({"envelope":envelope,"relay_service_key_base64":"retired-test-key"})),
        ] {
            let request = LocalBusFrame::request("retired-sync", Some("target".into()), "device", method, body);
            let error = super::super::device::dispatch_device_bus_request(&request, &mut state)
                .await.err().ok_or("test: retired key was accepted by device sync IPC")?;
            match error {
                SdkError::CapabilityDenied(message) => assert_eq!(message,
                    "relay service keys are unsupported; use gateway-issued QUIC tokens",
                    "device sync must return the exact retired-key refusal"),
                other => return Err(format!("test: unexpected device sync refusal: {other}").into()),
            }
            let account = state.accounts.get("target").ok_or("test: target account")?;
            assert_eq!(account.engine.is_some(), engine_present, "refusal must not create a session");
            assert!(account.relay_quic_pool.is_none(), "refusal must not create a relay pool");
            assert_eq!(serde_json::to_value(account.client.account_db()?.load_actor_state::<Value>(&receipt)?)?, before, "refusal must preserve the cached receipt");
            assert_eq!(serde_json::to_value(account.client.direct_messages("history-thread")?)?, messages, "refusal must preserve imported history");
            assert_eq!(serde_json::to_value(account.client.object_store_object(&envelope.history_ref.object_id)?)?, object, "refusal must preserve the cached object");
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })).await?
}
