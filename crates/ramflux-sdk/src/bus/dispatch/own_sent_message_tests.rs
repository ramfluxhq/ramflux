// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated live outgoing copies preserve source identity without explicit history sync.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, atomic::AtomicBool};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn sent_dm_arrives_on_an_active_sibling_as_one_outgoing_row_despite_retries() -> TestResult {
    let root = runtime_tests::root("own-sent-dm");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory) =
        super::own_tests::sibling_fixture(&root, &mut source).await?;
    let captured = Arc::default();
    let mut gateway = super::fixture::RecordingGateway::new(Arc::clone(&captured));
    gateway.fail_own_ack = false;
    let own = Arc::clone(&gateway.own);
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(gateway));
    let message = GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: "sent-message".into(),
        envelope_id: "sent-envelope".into(),
        source_principal_id: "sender".into(),
        sender_id: "device-sender".into(),
        recipient_device_id: Some("device-peer-one".into()),
        recipient_principal_commitment: Some(
            super::fixture::manifest(&source.client)?.principal_commitment,
        ),
        target_delivery_id: "device-peer-one".into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 300,
    };
    let mut message = message;
    message.recipient_principal_commitment = source
        .client
        .account_db()?
        .client_record("identity", "peer")?
        .and_then(|v| v["contact_identity_commitment"].as_str().map(str::to_owned));
    source
        .client
        .send_plaintext_direct_message_via_gateway(&mut engine, message, b"sent to peer")
        .await?;
    source.put_engine(engine);
    crate::bus::own_device_copy::flush(&mut source).await?;
    let envelope = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    assert!(!envelope.encrypted_payload.contains("sent to peer"));
    let entry = GatewayInboxEntry { inbox_seq: 1, target_delivery_id: "sibling".into(), envelope };
    assert!(sibling.client.receive_own_device_message(&receiver, &entry).await?);
    assert!(sibling.client.receive_own_device_message(&receiver, &entry).await?);
    let rows = sibling.client.direct_messages("thread")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        sibling.client.account_db()?.message_content(&rows[0].message_id)?.as_deref(),
        Some(b"sent to peer".as_slice())
    );
    let origin = sibling.client.message_origin("thread", &rows[0].message_id)?.ok_or("origin")?;
    assert_eq!(origin["direction"], "outgoing");
    assert_eq!(origin["original_message_id"], "sent-message");
    assert_eq!(origin["envelope_id"], "sent-envelope");
    assert_eq!(origin["sender_device_id"], "device-sender");
    assert_eq!(origin["sender_root_commitment"], source.principal_commitment);
    assert_eq!(
        sibling.client.account_db()?.actor_state_usage(crate::client::delivery_receipts::PREFIX)?.0,
        0
    );
    directory.abort();
    drop((source, sibling));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn sent_group_message_creates_an_outgoing_sibling_row_without_history_import() -> TestResult {
    let root = runtime_tests::root("own-sent-group");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory) =
        super::own_tests::sibling_fixture(&root, &mut source).await?;
    source.client.create_group("own-group", "device-sender")?;
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    let request = LocalBusFrame::request(
        "group",
        Some("sender".into()),
        "group",
        "group.send",
        json!({"group_id":"own-group","conversation_id":"own-group-thread","message_id":"group-message",
            "sender_id":"device-sender","encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"sent to group")}),
    );
    let sender = source.client.owned_device_identity()?;
    let canonical = ramflux_protocol::group_message_id(
        "own-group",
        sender.root_commitment(),
        sender.device_id(),
        "group-message",
    )?;
    let result = super::super::group::dispatch_group_send_request(&request, &mut source).await?;
    assert_eq!(result.response_body["message_id"], canonical);
    assert_eq!(result.response_body["client_message_id"], "group-message");
    crate::bus::own_device_copy::flush(&mut source).await?;
    let envelope = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    let entry = GatewayInboxEntry { inbox_seq: 1, target_delivery_id: "sibling".into(), envelope };
    assert!(sibling.client.receive_own_device_message(&receiver, &entry).await?);
    assert!(sibling.client.receive_own_device_message(&receiver, &entry).await?);
    let snapshot = crate::bus::readers::read(
        &sibling.client,
        &LocalBusFrame::request(
            "rows",
            Some("sender".into()),
            "message",
            "message.list",
            json!({"conversation_id":"own-group-thread"}),
        ),
    )?;
    let rows = snapshot["messages"].as_array().ok_or("rows")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["direction"], "outgoing");
    assert_eq!(rows[0]["body_utf8"], "sent to group");
    assert_eq!(rows[0]["original_message_id"], canonical);
    assert_eq!(
        sibling
            .client
            .account_db()?
            .client_record("conversation", "own-group-thread")?
            .ok_or("thread")?["group_id"],
        "own-group"
    );
    directory.abort();
    drop((source, sibling));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn an_original_self_dm_and_its_pair_encrypted_copy_produce_one_outgoing_row() -> TestResult {
    let root = runtime_tests::root("own-original-pair");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (mut sibling, config, receiver, directory) =
        super::own_tests::sibling_fixture(&root, &mut source).await?;
    let captured = Arc::default();
    let gateway = super::fixture::RecordingGateway::new(Arc::clone(&captured));
    let own = Arc::clone(&gateway.own);
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(gateway));
    source
        .client
        .send_plaintext_direct_message_via_gateway(
            &mut engine,
            GatewayDirectMessage {
                conversation_id: "self-thread".into(),
                message_id: "self-message".into(),
                envelope_id: "self-envelope".into(),
                source_principal_id: "sender".into(),
                sender_id: "device-sender".into(),
                recipient_device_id: Some("device-sibling".into()),
                recipient_principal_commitment: Some(source.principal_commitment.clone()),
                target_delivery_id: "sibling".into(),
                encrypted_body: Vec::new(),
                created_at: now_unix_timestamp(),
                ttl: 300,
            },
            b"self pair text",
        )
        .await?;
    source.put_engine(engine);
    crate::bus::own_device_copy::flush(&mut source).await?;
    let copy = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    let copy =
        GatewayInboxEntry { inbox_seq: 2, target_delivery_id: "sibling".into(), envelope: copy };
    assert!(sibling.client.receive_own_device_message(&receiver, &copy).await?);
    assert_eq!(sibling.client.direct_messages("self-thread")?.len(), 0);
    let original = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    let original = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: "sibling".into(),
        envelope: original,
    };
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let mut engine = GatewaySessionEngine::with_test_transport(
        receiver,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    sibling.client.apply_routed_entry(&mut engine, &pool, &original, false).await?;
    assert!(sibling.client.receive_own_device_message(&engine.config, &copy).await?);
    let rows = sibling.client.direct_messages("self-thread")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        sibling.client.account_db()?.message_content(&rows[0].message_id)?.as_deref(),
        Some(b"self pair text".as_slice())
    );
    assert_eq!(
        sibling.client.message_origin("self-thread", &rows[0].message_id)?.ok_or("origin")?["direction"],
        "outgoing"
    );
    assert_eq!(
        sibling.client.account_db()?.actor_state_usage(crate::client::delivery_receipts::PREFIX)?.0,
        0
    );
    directory.abort();
    drop((source, sibling));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
