// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Delivery-confirmed context, independent target retries and exact committed replay coverage.
use super::*;
#[path = "retry.rs"]
mod retry;
use crate::client::surface::{CONTROL_PREFIX, ControlKind, SurfaceControl};

fn due(client: &RamfluxClient) -> Result<(), SdkError> {
    let db = client.account_db()?;
    for key in db.actor_state_key_page("own-device/send/", 256)? {
        let mut work: Value = db
            .load_actor_state(&key)?
            .ok_or_else(|| SdkError::LocalBus("copy work disappeared".into()))?;
        work["next_at"] = json!(0);
        if let Some(targets) = work["targets"].as_array_mut() {
            for target in targets {
                target["next_at"] = json!(0);
            }
        }
        db.persist_actor_state(&key, &work)?;
    }
    Ok(())
}

fn context(bytes: &[u8]) -> Result<SurfaceControl, SdkError> {
    Ok(ramflux_protocol::parse_i_json(
        bytes
            .strip_prefix(CONTROL_PREFIX)
            .ok_or_else(|| SdkError::LocalBus("surface control prefix".into()))?,
    )?)
}

#[tokio::test]
async fn context_marker_requires_confirmation_and_failure_restores_context() -> TestResult {
    let root = runtime_tests::root("context-confirmation");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory) = sibling_fixture(&root, &mut source).await?;
    let create = super::super::dm_tests::create_carrier(&source.client)?;
    assert!(source.client.queue_surface_own_copy(&create, None)?);
    let db = source.client.account_db()?;
    assert_eq!(db.actor_state_usage("surface/own_context_announced/")?.0, 0);
    assert_eq!(db.actor_state_usage("own-device/context-delivered/")?.0, 0);
    let mut failed = super::super::fixture::RecordingGateway::new(Arc::default());
    failed.fail_own_ack = true;
    let own = Arc::clone(&failed.own);
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(failed),
    ));
    assert_eq!(crate::bus::own_device_copy::flush(&mut source).await?, 0);
    assert_eq!(
        source.client.account_db()?.actor_state_usage("own-device/context-delivered/")?.0,
        0
    );
    let first = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0].clone();
    assert!(sibling.client.receive_own_device_message(&receiver, &entry(first, 1)).await?);
    due(&source.client)?;
    let mut healthy = super::super::fixture::RecordingGateway::new(Arc::default());
    healthy.own = own;
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(healthy),
    ));
    assert_eq!(crate::bus::own_device_copy::flush(&mut source).await?, 1);
    assert_eq!(
        source.client.account_db()?.actor_state_usage("own-device/context-delivered/")?.0,
        1
    );

    // A confirmed context is reusable, but a failed subsequent fanout invalidates its marker.
    assert_eq!(send(&mut source, &create).await?["delivery_state"], "submitted");
    let next = append(&source.client, &create, 2)?;
    let mut failed = super::super::fixture::RecordingGateway::new(Arc::default());
    failed.fail_own_ack = true;
    source
        .install_test_session(GatewaySessionEngine::with_test_transport(config, Box::new(failed)));
    assert_eq!(send(&mut source, &next).await?["own_device_copy_state"], "pending");
    assert_eq!(
        source.client.account_db()?.actor_state_usage("own-device/context-delivered/")?.0,
        0
    );
    let key = source.client.account_db()?.actor_state_key_page("own-device/send/", 1)?.remove(0);
    let pending: Value = source.client.account_db()?.load_actor_state(&key)?.ok_or("pending")?;
    assert_eq!(pending["context_delivery"]["included"], false);
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn confirmed_context_is_scoped_to_the_prepared_active_target_set() -> TestResult {
    let root = runtime_tests::root("context-target-set");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, _, _, directory) = sibling_fixture(&root, &mut source).await?;
    let carrier = super::super::dm_tests::create_carrier(&source.client)?;
    let body = source.client.surface_control_packet(&carrier, ControlKind::Own, None)?.bytes()?;
    let targets = vec!["active-sibling".to_owned()];
    let (first, delivery) = source.client.prepare_own_surface_context(&body, &targets)?;
    assert!(context(&first)?.context.is_some());
    let delivery = delivery.ok_or("context delivery")?;
    assert!(
        context(&source.client.prepare_own_surface_context(&body, &targets)?.0)?.context.is_some()
    );
    source.client.finish_own_surface_context(&delivery, true)?;
    assert!(
        context(&source.client.prepare_own_surface_context(&body, &targets)?.0)?.context.is_none()
    );
    let changed = vec!["active-sibling".into(), "new-sibling".into()];
    assert!(
        context(&source.client.prepare_own_surface_context(&body, &changed)?.0)?.context.is_some()
    );
    source.client.finish_own_surface_context(&delivery, false)?;
    assert!(
        context(&source.client.prepare_own_surface_context(&body, &targets)?.0)?.context.is_some()
    );
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn a_dead_prepared_target_is_parked_while_a_live_sibling_gets_the_next_copy() -> TestResult {
    let root = runtime_tests::root("own-target-parking");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory) = sibling_fixture(&root, &mut source).await?;
    let create = super::super::dm_tests::create_carrier(&source.client)?;
    let mut failed = super::super::fixture::RecordingGateway::new(Arc::default());
    failed.fail_own_ack = true;
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(failed),
    ));
    assert_eq!(send(&mut source, &create).await?["own_device_copy_state"], "pending");
    let key = source.client.account_db()?.actor_state_key_page("own-device/send/", 1)?.remove(0);
    let mut work: Value = source.client.account_db()?.load_actor_state(&key)?.ok_or("prepared")?;
    // Model a target revoked after packet preparation. The healthy slot remains real ciphertext.
    let packet = &mut work["packet"];
    let mut dead = packet["slots"][0].clone();
    dead["recipient_device_id"] = json!("dead-sibling");
    packet["slots"].as_array_mut().ok_or("slots")?.push(dead);
    packet.as_object_mut().ok_or("packet")?.remove("signature");
    packet["signature"] = json!(ramflux_crypto::sign_with_device_branch(
        source.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &json!({"domain":crate::client::own_device_copy::DOMAIN,"body":packet}),
    )?);
    work["targets"] = json!([]);
    work["next_at"] = json!(0);
    source.client.account_db()?.persist_actor_state(&key, &work)?;
    let mut partial = super::super::fixture::RecordingGateway::new(Arc::default());
    partial.fail_own_target = Some("dead-sibling".into());
    let own = Arc::clone(&partial.own);
    source
        .install_test_session(GatewaySessionEngine::with_test_transport(config, Box::new(partial)));
    let attempted_at = now_unix_timestamp();
    assert_eq!(crate::bus::own_device_copy::flush(&mut source).await?, 0);
    let mut parked: Value = source.client.account_db()?.load_actor_state(&key)?.ok_or("parked")?;
    for target in parked["targets"].as_array_mut().ok_or("targets")? {
        if target["device"] == "dead-sibling" {
            assert!(target["next_at"].as_i64().is_some_and(|at| at > attempted_at));
            target["next_at"] = json!(now_unix_timestamp() + 60);
        }
    }
    source.client.account_db()?.persist_actor_state(&key, &parked)?;
    let next = append(&source.client, &create, 2)?;
    assert_eq!(send(&mut source, &next).await?["own_device_copy_state"], "submitted");
    let captures = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(
        captures.len(),
        2,
        "backed-off target must not be retried while the later copy runs"
    );
    for (index, envelope) in captures.into_iter().enumerate() {
        assert!(
            sibling
                .client
                .receive_own_device_message(&receiver, &entry(envelope, index as u64 + 1))
                .await?
        );
    }
    assert_eq!(sibling.client.surface_get("surface", 0, None)?["version"], 2);
    let parked: Value = source.client.account_db()?.load_actor_state(&key)?.ok_or("parked")?;
    let targets = parked["targets"].as_array().ok_or("targets")?;
    assert!(
        targets
            .iter()
            .any(|target| target["device"] == "device-sibling" && target["acknowledged"] == true)
    );
    assert!(targets.iter().any(|target| target["device"] == "dead-sibling"
        && target["acknowledged"] == false
        && target["next_at"].as_i64().is_some_and(|at| at > attempted_at)));
    retry::exhaust_parked_target(&mut source, &key, &own).await?;
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn an_acknowledged_copy_replays_after_receipt_eviction_without_reprojection() -> TestResult {
    let root = runtime_tests::root("own-copy-receipt-eviction");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, mut receiver, directory) = sibling_fixture(&root, &mut source).await?;
    let gateway = super::super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    source
        .install_test_session(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    let create = super::super::dm_tests::create_carrier(&source.client)?;
    assert_eq!(
        send(&mut source, &create).await.map_err(|error| format!("send own copy: {error:?}"))?["own_device_copy_state"],
        "submitted"
    );
    let envelope = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0].clone();
    let incoming = entry(envelope.clone(), 1);
    assert!(
        sibling
            .client
            .receive_own_device_message(&receiver, &incoming)
            .await
            .map_err(|error| format!("first receive: {error:?}"))?
    );
    let before = sibling.client.surface_get("surface", 0, None)?;
    let db = sibling.client.account_db()?;
    let receipt_key = db.actor_state_key_page("own-device/message-receipt/", 1)?.remove(0);
    let receipt: Value = db.load_actor_state(&receipt_key)?.ok_or("receipt")?;
    assert_eq!(receipt["acknowledged"], false);
    receiver.target_delivery_id = "sibling".into();
    let mut failed = super::super::fixture::RecordingGateway::new(Arc::default());
    failed.fail_ack = true;
    let mut engine = GatewaySessionEngine::with_test_transport(receiver.clone(), Box::new(failed));
    assert!(
        sibling
            .client
            .ack_gateway_entry(&mut engine, &incoming, now_unix_timestamp())
            .await
            .is_err()
    );
    assert_eq!(
        db.load_actor_state::<Value>(&receipt_key)?.ok_or("receipt")?["acknowledged"],
        false
    );
    let mut gateway = super::super::fixture::RecordingGateway::new(Arc::default());
    gateway.ack_target = "sibling".into();
    let mut engine = GatewaySessionEngine::with_test_transport(receiver.clone(), Box::new(gateway));
    sibling
        .client
        .ack_gateway_entry(&mut engine, &incoming, now_unix_timestamp())
        .await
        .map_err(|error| format!("ack receipt: {error:?}"))?;
    assert_eq!(db.load_actor_state::<Value>(&receipt_key)?.ok_or("receipt")?["acknowledged"], true);
    db.retain_delivery_actor_states("own-device/message-receipt/", now_unix_timestamp(), 0)?;
    assert!(!db.actor_state_exists(&receipt_key)?);
    assert_eq!(db.actor_state_usage("own-device/committed-packet/")?.0, 1);
    assert!(
        sibling
            .client
            .receive_own_device_message(&receiver, &entry(envelope.clone(), 2))
            .await
            .map_err(|error| format!("receive after receipt eviction: {error:?}"))?
    );
    assert_eq!(sibling.client.surface_get("surface", 0, None)?, before);
    let forged = conflicting_own_packet(&source.client, envelope)?;
    assert!(matches!(
        sibling.client.receive_own_device_message(&receiver, &entry(forged, 3)).await,
        Err(SdkError::InboundRejected(reason)) if reason == "own-device message id conflict"
    ));
    assert_eq!(sibling.client.surface_get("surface", 0, None)?, before);
    assert!(db.latest_journal_event("message.undeliverable")?.is_none());
    assert_durable_acknowledged_proof(db)?;
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn a_full_live_replay_window_defers_new_copies_without_consuming_the_ratchet() -> TestResult {
    let root = runtime_tests::root("own-copy-replay-capacity");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory) = sibling_fixture(&root, &mut source).await?;
    let gateway = super::super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    source
        .install_test_session(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    let create = super::super::dm_tests::create_carrier(&source.client)?;
    assert_eq!(send(&mut source, &create).await?["own_device_copy_state"], "submitted");
    let envelope = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0].clone();
    let db = sibling.client.account_db()?;
    let limit = crate::client::own_device_copy::MAX_DELIVERY_ROWS;
    assert_eq!(limit, 18_000);
    let now = now_unix_timestamp();
    db.write_transaction(|| {
        for i in 0..limit {
            db.persist_actor_state(
                &format!("own-device/committed-packet/budget-{i:05}"),
                &json!({"valid_until":now + 600,"expires_at":now + 900,"acknowledged":true}),
            )?;
        }
        Ok::<_, SdkError>(())
    })?;
    assert!(matches!(
        sibling.client.receive_own_device_message(&receiver, &entry(envelope.clone(), 1)).await,
        Err(SdkError::InboundPending(_)
            | SdkError::SenderManifestRequired { .. }
            | SdkError::FreshHeadRequired { .. })
    ));
    assert!(sibling.client.surface_get("surface", 0, None)?.is_null());
    assert_eq!(db.actor_state_usage("own-device/committed-packet/")?.0, u64::from(limit));
    assert_eq!(db.actor_state_usage("own-device/message-receipt/")?.0, 0);
    db.remove_actor_state("own-device/committed-packet/budget-00000")?;
    assert!(sibling.client.receive_own_device_message(&receiver, &entry(envelope, 2)).await?);
    assert_eq!(sibling.client.surface_get("surface", 0, None)?["version"], 1);
    assert_eq!(db.actor_state_usage("own-device/committed-packet/")?.0, u64::from(limit));
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn a_slow_failure_parks_the_target_from_completion_instead_of_attempt_start() -> TestResult {
    let root = runtime_tests::root("own-copy-slow-failure");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, _, directory) = sibling_fixture(&root, &mut source).await?;
    let mut gateway = super::super::fixture::RecordingGateway::new(Arc::default());
    gateway.fail_own_ack = true;
    gateway.own_delay = Duration::from_secs(3);
    let completed = Arc::clone(&gateway.own_completed_at);
    source
        .install_test_session(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    let create = super::super::dm_tests::create_carrier(&source.client)?;
    assert_eq!(send(&mut source, &create).await?["own_device_copy_state"], "pending");
    let completed_at = completed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .ok_or("RPC completion")?;
    let db = source.client.account_db()?;
    let key = db.actor_state_key_page("own-device/send/", 1)?.remove(0);
    let work: Value = db.load_actor_state(&key)?.ok_or("pending copy")?;
    for target in work["targets"].as_array().ok_or("targets")? {
        assert_eq!(target["attempts"], 1);
        let next = target["next_at"].as_i64().ok_or("next_at")?;
        assert!(
            next >= completed_at + 2,
            "backoff elapsed during I/O: next={next}, completed={completed_at}"
        );
    }
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_durable_acknowledged_proof(db: &ramflux_storage::AccountDb) -> TestResult {
    let reader = db.open_reader()?;
    let marker = reader.actor_state_key_page("own-device/committed-packet/", 1)?.remove(0);
    assert_eq!(
        marker.strip_prefix("own-device/committed-packet/").ok_or("marker prefix")?.len(),
        43
    );
    let proof: Value = reader.load_actor_state(&marker)?.ok_or("durable replay proof")?;
    assert_eq!(proof["acknowledged"], true);
    assert_eq!(proof.as_object().ok_or("proof object")?.len(), 4);
    assert_eq!(proof["fingerprint"].as_str().ok_or("private fingerprint")?.len(), 43);
    drop(reader);
    Ok(())
}

fn conflicting_own_packet(source: &RamfluxClient, mut forged: ramflux_protocol::Envelope) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let bytes = ramflux_protocol::decode_base64url(&forged.encrypted_payload)?;
    let raw = bytes.strip_prefix(crate::client::own_device_copy::PREFIX).ok_or("packet prefix")?;
    let mut packet: Value = serde_json::from_slice(raw)?;
    assert!(packet.get("context_delivery").is_none());
    let mut unsigned_local = packet.clone();
    unsigned_local["context_delivery"] = json!({"included":true});
    assert!(
        serde_json::from_value::<crate::client::own_device_copy::OwnDeviceMessage>(unsigned_local)
            .is_err()
    );
    let mut ciphertext = packet["ciphertext"].as_str().ok_or("ciphertext")?.as_bytes().to_vec();
    let first = ciphertext.first_mut().ok_or("ciphertext bytes")?;
    *first = if *first == b'A' { b'B' } else { b'A' };
    packet["ciphertext"] = json!(String::from_utf8(ciphertext)?);
    let branch = source.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    packet.as_object_mut().ok_or_else(|| SdkError::LocalBus("packet object".into()))?.remove("signature");
    let signature = ramflux_crypto::sign_with_device_branch(branch, &json!({"domain":crate::client::own_device_copy::DOMAIN,"body":packet}))?;
    packet["signature"] = json!(signature);
    let mut signed = crate::client::own_device_copy::PREFIX.to_vec();
    signed.extend(serde_json::to_vec(&packet)?);
    forged.encrypted_payload = ramflux_protocol::encode_base64url(signed);
    forged.payload_hash = ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::ENVELOPE, forged.encrypted_payload.as_bytes());
    forged.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(branch, &forged)?;
    Ok(forged)
}
