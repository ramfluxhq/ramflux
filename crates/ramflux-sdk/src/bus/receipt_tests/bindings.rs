// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deferred group projection and invalid receipt targets preserve delivery integrity.
use super::{
    fixture::{self, Shared, Spec, TestResult},
    *,
};
use serde_json::json;
#[tokio::test]
async fn a_group_message_gets_its_receipt_only_after_the_missing_sender_key_arrives() -> TestResult
{
    let root = runtime_tests::root("receipt-deferred-group");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &b)?;
    let source = a.client(None)?;
    let mut receiver = b.account(None, mail.clone())?;
    for (spec, client) in [(&a, &source), (&b, &receiver.client)] {
        spec.trust(client, &a)?;
        spec.trust(client, &b)?;
        client.create_group("group", a.identity()?.storage_key())?;
        client.add_group_member_with_root(
            "group",
            &b.device,
            "member",
            b.identity()?.root_commitment(),
        )?;
        client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"group","group_id":"group"}),
        )?;
    }
    let distribution = source.export_group_sender_key_distribution("group", &a.device)?;
    let raw = source.encrypt_group_message("group", &a.device, b"held group body")?;
    let mut account = a.account(None, mail)?;
    let mut engine = account.take_live_engine().await?;
    let mut message = a.message(&b, "held");
    message.envelope_id = "held:device-bob".into();
    let sealed = source
        .seal_routed_as(
            &mut engine,
            &message,
            &raw,
            crate::client::routed::Route::group_message("group"),
        )
        .await?;
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    let entry = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: b.device.clone(),
        envelope: gateway_direct_message_envelope(&engine.config, &message, None)?,
    };
    drop(engine);
    drop(account);
    let pool = receiver.relay_quic_pool()?;
    let mut engine = receiver.take_live_engine().await?;
    receiver.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
    assert!(receiver.client.direct_message_by_id("held")?.is_none());
    assert!(receiver.client.direct_message_by_id("held:device-bob")?.is_none());
    assert_eq!(
        receiver
            .client
            .account_db()?
            .actor_state_usage(crate::client::delivery_receipts::PREFIX)?
            .0,
        0
    );
    receiver.client.import_group_sender_key_distribution(&distribution)?;
    assert_eq!(
        receiver.client.account_db()?.message_content("held")?,
        Some(b"held group body".to_vec())
    );
    let keys = receiver
        .client
        .account_db()?
        .actor_state_key_page(crate::client::delivery_receipts::PREFIX, 256)?;
    assert_eq!(keys.len(), 1);
    let work = receiver
        .client
        .account_db()?
        .load_actor_state::<crate::client::delivery_receipts::Work>(&keys[0])?
        .ok_or("receipt")?;
    assert_eq!(work.sender, a.identity()?.storage_key());
    assert_eq!(work.wire_message.as_deref(), Some("held:device-bob"));
    receiver.client.import_group_sender_key_distribution(&distribution)?;
    assert_eq!(
        receiver
            .client
            .account_db()?
            .actor_state_usage(crate::client::delivery_receipts::PREFIX)?
            .0,
        1
    );
    drop(engine);
    drop(receiver);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn unknown_or_inbound_targets_cannot_poison_a_later_valid_delivery_receipt() -> TestResult {
    let root = runtime_tests::root("receipt-unknown-target");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    fixture::seed_pair(&a, &b)?;
    let source = a.client(None)?;
    source.send_direct_message("thread", "outgoing", &a.device, b"sent")?;
    source.send_direct_message("thread", "incoming", &b.device, b"received")?;
    for target in ["missing", "incoming", "outgoing"] {
        let event = SdkReceiptEventEnvelope {
            schema: "ramflux.sdk.receipt_event.v1".into(),
            version: 1,
            receipt_id: target.into(),
            event_seq: 1,
            nonce: target.into(),
            reader_device_id: b.device.clone(),
            event: SdkReceiptEventBody::Delivered {
                conversation_id: "thread".into(),
                message_id: target.into(),
                delivered_at: now_unix_timestamp(),
                receiver_device_id: b.device.clone(),
                scope: "e2ee_private".into(),
                ttl_seconds: 300,
            },
        };
        let result = source.apply_receipt_event_plaintext(
            &serde_json::to_vec(&event)?,
            &b.identity()?,
            "thread",
        );
        if target == "outgoing" {
            assert!(result?.is_some());
        } else {
            assert!(matches!(result, Err(SdkError::InboundRejected(_))));
            assert!(source.account_db()?.delivery_receipt("thread", &b.identity()?)?.is_none());
        }
    }
    let row = source.direct_message_by_id("outgoing")?.ok_or("outgoing")?;
    assert_eq!(row.receipts.len(), 1);
    assert_eq!(row.receipts[0].state, "delivered");
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn equal_device_names_and_wire_ids_under_different_roots_have_independent_receipt_bindings()
-> TestResult {
    let root = runtime_tests::root("receipt-root-collision");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mut foreign = Spec::new(&root, "mallory", 71);
    foreign.device.clone_from(&b.device);
    let source = a.client(None)?;
    a.trust(&source, &b)?;
    a.trust(&source, &foreign)?;
    for (peer, conversation, logical) in
        [(&b, "thread-b", "logical-b"), (&foreign, "thread-m", "logical-m")]
    {
        source.send_direct_message(conversation, logical, &a.device, b"ciphertext")?;
        let mut message = a.message(peer, logical);
        message.envelope_id = "shared-wire".into();
        message.conversation_id = conversation.into();
        source.bind_outgoing_delivery(
            &a.identity()?,
            &message,
            &crate::client::routed::Kind::Direct,
        )?;
        assert_eq!(
            source.resolve_delivery_receipt_message(
                &peer.identity()?,
                conversation,
                "shared-wire"
            )?,
            logical
        );
    }
    assert!(
        source
            .resolve_delivery_receipt_message(&foreign.identity()?, "thread-b", "shared-wire")
            .is_err()
    );
    assert_eq!(
        source.resolve_delivery_receipt_message(&b.identity()?, "thread-b", "shared-wire")?,
        "logical-b"
    );
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
