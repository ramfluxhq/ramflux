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
    let (mut sibling, config, receiver, directory) =
        super::own_tests::sibling_fixture(&root, &mut source).await?;
    let captured = Arc::default();
    let mut gateway = super::fixture::RecordingGateway::new(Arc::clone(&captured));
    gateway.fail_own_ack = false;
    let own = Arc::clone(&gateway.own);
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(gateway));
    let message = GatewayDirectMessage {
        conversation_id: super::dm_tests::conversation(&source.client)?,
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
    let root = message.recipient_principal_commitment.as_deref().ok_or("peer root")?;
    message.target_delivery_id =
        source.client.device_identity_for_root(root, "device-peer-one")?.storage_key().into();
    let conversation = message.conversation_id.clone();
    source
        .client
        .send_plaintext_direct_message_via_gateway(&mut engine, message, b"sent to peer")
        .await?;
    source.install_test_session(engine);
    assert!(crate::bus::couriers::authored_history::drive_once(&mut source).await?);
    let envelope = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    assert!(!envelope.encrypted_payload.contains("sent to peer"));
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    assert!(
        crate::client::native_test_support::bus::receive_copy(
            &mut sibling.client,
            &receiver,
            &entry
        )
        .await?
    );
    assert!(
        crate::client::native_test_support::bus::receive_copy(
            &mut sibling.client,
            &receiver,
            &entry
        )
        .await?
    );
    let message_id = assert_outgoing_copy(&sibling, &source, &conversation, &entry)?;
    assert_private_replay_after_delete(
        &mut sibling,
        &receiver,
        &entry,
        &source.client.owned_device_identity()?,
        &message_id,
    )
    .await?;
    directory.abort();
    drop((source, sibling));
    Ok(())
}

#[tokio::test]
async fn same_root_ordinary_dm_refuses_before_submission_or_projection() -> TestResult {
    let root = runtime_tests::root("own-original-pair");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, _receiver, directory) =
        super::own_tests::sibling_fixture(&root, &mut source).await?;
    let captured = Arc::default();
    let gateway = super::fixture::RecordingGateway::new(Arc::clone(&captured));
    let own = Arc::clone(&gateway.own);
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(gateway));
    let result = source
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
                target_delivery_id: sibling.client.owned_device_identity()?.storage_key().into(),
                encrypted_body: Vec::new(),
                created_at: now_unix_timestamp(),
                ttl: 300,
            },
            b"self pair text",
        )
        .await;
    let error = result.err().ok_or("ordinary same-root DM must refuse")?;
    assert!(
        error.to_string().contains("invalid ordinary DM root pair"),
        "same-root traffic requires OwnMessageCopy: {error}"
    );
    assert!(captured.lock().map_err(|_| "captured")?.is_empty());
    assert!(own.lock().map_err(|_| "own packets")?.is_empty());
    assert_eq!(source.client.direct_messages("self-thread")?.len(), 0);
    assert_eq!(sibling.client.direct_messages("self-thread")?.len(), 0);
    directory.abort();
    Ok(())
}

async fn assert_private_replay_after_delete(
    sibling: &mut LocalBusAccountState,
    receiver: &GatewaySessionConfig,
    entry: &GatewayInboxEntry,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    id: &str,
) -> TestResult {
    let conversation =
        sibling.client.direct_message_by_id(id)?.ok_or("copied message")?.conversation_id;
    assert_eq!(sibling.client.account_db()?.actor_state_usage("own-device/message-receipt/")?.0, 1);
    sibling.client.account_db()?.delete_direct_message(
        &conversation,
        id,
        "local",
        &ramflux_protocol::encode_base64url([67; 32]),
    )?;
    assert_eq!(
        sibling.client.account_db()?.actor_state_usage("own-device/message-receipt/")?.0,
        0,
        "ACK must preserve receipt erasure binding"
    );
    assert_eq!(
        sibling.client.account_db()?.own_copy_actor_usage("own-device/committed-packet/")?.0,
        1
    );
    assert!(
        !crate::client::native_test_support::bus::receive_copy(
            &mut sibling.client,
            receiver,
            entry
        )
        .await?,
        "committed erased replay is accepted without rebuilding a routing projection"
    );
    assert_eq!(
        sibling.client.account_db()?.actor_state_usage("own-device/message-receipt/")?.0,
        0,
        "committed replay must short-circuit before projection and ratchet use"
    );
    let mut forged = entry.clone();
    forged.envelope.source_device_id = "forged-copy-source".into();
    assert!(
        crate::client::native_test_support::bus::receive_copy(
            &mut sibling.client,
            receiver,
            &forged
        )
        .await
        .is_err()
    );
    let rows = sibling.client.direct_messages(&conversation)?;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].deleted);
    assert!(rows[0].is_own);
    assert!(sibling.client.message_origin(&conversation, id)?.is_none());
    assert!(sibling.client.account_db()?.message_content(id)?.is_none());
    let retained = serde_json::to_string(
        &sibling.client.account_db()?.list_actor_states::<serde_json::Value>("own-device/")?,
    )?;
    for forbidden in [
        source.device_id(),
        source.storage_key(),
        source.root_commitment(),
        "sent-envelope",
        "sent to peer",
    ] {
        assert!(!retained.contains(forbidden), "deleted copy retained {forbidden}");
    }
    Ok(())
}

fn assert_outgoing_copy(
    sibling: &LocalBusAccountState,
    source: &LocalBusAccountState,
    conversation: &str,
    entry: &GatewayInboxEntry,
) -> Result<String, Box<dyn std::error::Error>> {
    let rows = sibling.client.direct_messages(conversation)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        sibling
            .client
            .generated_message_detail(conversation, &rows[0].message_id)?
            .message
            .text
            .as_deref(),
        Some("sent to peer")
    );
    let origin =
        sibling.client.message_origin(conversation, &rows[0].message_id)?.ok_or("origin")?;
    assert_eq!(origin["direction"], "outgoing");
    assert_eq!(origin["original_message_id"], rows[0].message_id);
    assert_eq!(origin["envelope_id"], "sent-envelope");
    assert_eq!(origin["sender_device_id"], "device-sender");
    assert_eq!(origin["sender_root_commitment"], source.principal_commitment);
    assert_eq!(
        sibling.client.account_db()?.actor_state_usage(crate::client::delivery_receipts::PREFIX)?.0,
        0
    );
    sibling.client.record_own_copy_ack(entry)?;
    assert_eq!(
        sibling.client.account_db()?.own_copy_actor_usage("own-device/committed-packet/")?.0,
        1
    );
    Ok(rows.first().ok_or("outgoing row")?.message_id.clone())
}
