// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generation-one group entry points refuse retired codecs and preserve receive fences.
use super::*;
use crate::client::native_test_support::Fixture;
use ramflux_protocol::message as g;
use serde_json::json;

fn fixture_error(error: &dyn std::error::Error) -> SdkError {
    SdkError::LocalBus(format!("test: native group fixture: {error}"))
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_native_group_entry_does_not_block_the_next_generated_message()
-> crate::client::native_test_support::TestResult {
    crate::client::native_test_support::watchdog::within(native_group_isolation()).await?
}

async fn native_group_isolation() -> crate::client::native_test_support::TestResult {
    use crate::client::native_test_support::{activation_send::tests::publish_layer_four, bus};
    let mut sender = Fixture::with_principal("group-source", "device-alice", "alice").await?;
    let mut recipient = Fixture::with_principal("group-recipient", "device-bob", "bob").await?;
    publish_layer_four(&mut sender).await?;
    publish_layer_four(&mut recipient).await?;
    sender.accept_peer(&recipient)?;
    recipient.accept_peer(&sender)?;
    let sender = sender.into_bus();
    let mut recipient = recipient.into_bus();
    bus::seed_pair(&sender.client, &recipient.client)?;
    sender.client.fixture_group_create("g", "thread", None, "device-alice")?;
    let state = sender.client.fixture_group_change(
        "g",
        "device-alice",
        ramflux_protocol::GroupStateChange::Add {
            member: recipient.client.fixture_group_actor("device-bob")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    recipient.client.fixture_accept_group_state(&state, "device-bob")?;
    let distribution = sender.client.export_group_sender_key_distribution("g", "device-alice")?;
    let _ = recipient.client.import_group_sender_key_distribution(&distribution)?;
    let target = recipient.client.owned_device_identity()?;
    let config = &sender.gateway_config;
    let mut message = GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: "valid".into(),
        envelope_id: "valid-envelope".into(),
        source_principal_id: config.principal_id.clone(),
        sender_id: config.device_id.clone(),
        recipient_device_id: Some(target.device_id().into()),
        recipient_principal_commitment: Some(target.root_commitment().into()),
        target_delivery_id: target.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 600,
    };
    let content = g::Content {
        value: Some(g::content::Value::Message(g::Message {
            text: "valid after rejected".into(),
            ..Default::default()
        })),
    };
    let prepared = sender.client.prepare_authored_content(&mut message, Some("g"), &content)?;
    let logical = message.message_id.clone();
    let sealed = sender.client.seal_generated_routed_prepared(
        &sender.sealing_config()?,
        &message,
        &prepared.wire,
        crate::client::routed::Route::from_inner(&prepared.wire)?,
        crate::client::routed::SendMaterial { manifest: None, bundle: None },
    )?;
    let envelope = crate::dm::gateway_generated_envelope_from_sealed(
        &sender.sealing_config()?,
        &mut message,
        sealed,
    )?;
    let envelopes = vec![envelope];
    let config = recipient.gateway_config.clone();
    for (sequence, envelope) in envelopes.into_iter().enumerate() {
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: u64::try_from(sequence)? + 1,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        };
        let mut bad = entry.clone();
        bad.envelope.signed.signature = ramflux_protocol::encode_base64url([0; 64]);
        assert!(
            bus::receive_copy(&mut recipient.client, &config, &bad).await.is_err(),
            "unauthenticated input cannot block the next authentic group carrier"
        );
        bus::receive_copy(&mut recipient.client, &config, &entry).await?;
    }
    assert_eq!(
        recipient.client.generated_message_detail("thread", &logical)?.message.text.as_deref(),
        Some("valid after rejected")
    );
    assert_eq!(
        recipient.client.direct_chat_messages("thread")?.len(),
        1,
        "only the authenticated generated Message is projected"
    );
    Ok(())
}

/// A committed receive ledger forbids the old unrouted replay executor before decoding rows.
pub(super) async fn activated_group_unrouted_replay_refused() -> Result<(), SdkError> {
    let native = Fixture::with_principal("activated-group-guard", "device-bob", "bob")
        .await
        .map_err(|error| fixture_error(error.as_ref()))?;
    let mut receiver = native.into_bus();
    receiver.client.fixture_group_create("g", "thread", None, "device-bob")?;
    let target = receiver.target_delivery_id.clone();
    let _ =
        receiver.client.account_db()?.activate_receive_ledger(ramflux_storage::ReceiveMigrate {
            target: &target,
            incarnation: "e",
        })?;
    let message = GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: "retained".into(),
        envelope_id: "guarded-group-entry".into(),
        source_principal_id: "bob".into(),
        sender_id: "device-bob".into(),
        recipient_device_id: Some("device-bob".into()),
        recipient_principal_commitment: Some(receiver.principal_commitment.clone()),
        target_delivery_id: target.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 600,
    };
    let envelope =
        crate::bus::delivery_receipts::background::retained_receipt_fixture(&receiver, &message)?;
    let entry =
        GatewayInboxEntry { forwarded: false, inbox_seq: 2, target_delivery_id: target, envelope };
    receiver.client.account_db()?.hold_unrouted(
        "entry-guard-fixture",
        entry.inbox_seq,
        &serde_json::to_vec(&entry)?,
        now_unix_timestamp(),
    )?;
    let request = LocalBusFrame::request(
        "group.read",
        Some("bob".into()),
        "group",
        "group.read",
        json!({"group_id":"g","conversation_id":"thread","limit":32}),
    );
    let refused = Box::pin(crate::bus::account_runtime::head_refresh::with_receive_prepared(
        crate::bus::dispatch::group::dispatch_group_receive_request(&request, &mut receiver),
    ))
    .await;
    assert!(
        matches!(
            receiver.client.account_db()?.refuse_legacy_receive(),
            Err(StorageError::Integrity(ramflux_storage::LEGACY_RECEIVE_ACTIVATED))
        ),
        "activated legacy replay executor must refuse at entry"
    );
    let read = refused?;
    assert_eq!(
        read.response_body["durable_reader"], "message.read",
        "active group.read only selects the generated durable reader"
    );
    assert!(
        receiver.client.direct_messages("thread")?.is_empty(),
        "no routed effect before the entry refusal"
    );
    assert_eq!(
        receiver.client.account_db()?.unrouted_count()?,
        1,
        "entry refusal must preserve the retained row"
    );
    Ok(())
}
