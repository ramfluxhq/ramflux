// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receipt follow-ups preserve message commits, explicit retry and bounded retention.
use super::*;
use serde_json::json;

#[tokio::test]
async fn native_receive_does_not_require_a_legacy_identity_root() -> TestResult {
    let root = runtime_tests::root("receipt-no-legacy-root");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &b)?;
    let mut sender = a.account(None, mail.clone())?;
    let mut engine = sender.session_client().await?;
    let entry = a
        .send_text(&sender.client, &mut engine, a.message(&b, "incoming"), b"incoming plaintext")
        .await?;
    let mut receiver = b.account(None, mail)?;
    assert!(receiver.client.identity_root.is_none(), "native receive has no legacy root");
    let pool = receiver.relay_quic_pool()?;
    let mut transport = receiver.session_client().await?;
    crate::bus::sync_driver::process(&mut receiver, &mut transport, &pool, &entry).await?;
    let view =
        receiver.client.generated_message_detail(&a.conversation(&b)?, &a.event("incoming")?)?;
    assert_eq!(view.message.text.as_deref(), Some("incoming plaintext"));
    assert_eq!(
        receiver.client.account_db()?.actor_state_usage(PREFIX)?.0,
        1,
        "native authority permits the receipt in the incoming transaction"
    );
    Ok(())
}

#[test]
fn receipt_retention_is_bounded_preserves_legacy_payloads_and_records_journal_gaps() -> TestResult {
    let root = runtime_tests::root("receipt-retention");
    let spec = Spec::new(&root, "bob", 61);
    let client = spec.client(None)?;
    let db = client.account_db()?;
    let age = 30 * 24 * 60 * 60;
    let old = json!({"state":"sent","delivered_at":100});
    for key in [
        "delivery-receipt/status/old",
        "delivery-receipt/status/old-two",
        "delivery-receipt/outbound/old",
    ] {
        db.persist_receipt_state(key, &old, 100)?;
    }
    let legacy = json!({"sender_device_id":"legacy","extra":"unchanged"});
    db.persist_actor_state("message/origin/legacy", &legacy)?;
    db.persist_actor_state("message/origin/recent", &legacy)?;
    db.persist_actor_state("unrelated/record", &legacy)?;
    for n in 0..3 {
        db.append_journal(
            &format!("failed-{n}"),
            "message.delivery_receipt.failed",
            &json!({}),
            100,
            None,
        )?;
    }
    db.append_journal("safety", "safety.changed", &json!({}), 100, None)?;
    db.retain_delivery_receipts(100 + age - 1, 2)?;
    assert_eq!(db.actor_state_usage("delivery-receipt/status/")?.0, 2);
    db.retain_delivery_receipts(100 + age, 2)?;
    let remaining = [
        "delivery-receipt/status/old",
        "delivery-receipt/status/old-two",
        "delivery-receipt/outbound/old",
    ]
    .into_iter()
    .filter(|key| db.actor_state_exists(key).unwrap_or(false))
    .count();
    assert_eq!(remaining, 1, "one pass deletes at most two metadata rows");
    assert_eq!(
        db.journal_after(0, 100)?
            .iter()
            .filter(|event| event.topic == "message.delivery_receipt.failed")
            .count(),
        1
    );
    assert!(db.journal_bounds()?.pruned_through > 0);
    db.retain_delivery_receipts(100 + age, 2)?;
    assert_eq!(
        db.load_actor_state::<serde_json::Value>("message/origin/legacy")?,
        Some(legacy.clone())
    );
    assert_eq!(
        db.load_actor_state::<serde_json::Value>("message/origin/recent")?,
        Some(legacy.clone())
    );
    assert_eq!(db.load_actor_state::<serde_json::Value>("unrelated/record")?, Some(legacy));
    assert_eq!(
        db.journal_after(0, 100)?.iter().filter(|event| event.topic == "safety.changed").count(),
        1
    );
    drop(client);
    Ok(())
}

#[test]
fn legacy_receipt_enrollment_advances_bounded_pages_and_preserves_the_original_grace_period()
-> TestResult {
    let root = runtime_tests::root("receipt-legacy-pages");
    let client = Spec::new(&root, "bob", 61).client(None)?;
    let db = client.account_db()?;
    for n in 0..5 {
        db.persist_actor_state(&format!("delivery-receipt/status/{n:02}"), &json!({"legacy":n}))?;
    }
    for (now, last) in [(100, "01"), (101, "03"), (102, "04")] {
        db.retain_delivery_receipts(now, 2)?;
        let cursor = db
            .load_actor_state::<std::collections::BTreeMap<String, String>>(
                "delivery-receipt/retention-cursor",
            )?
            .ok_or("cursor")?;
        assert_eq!(
            cursor.get("delivery-receipt/status/"),
            Some(&format!("delivery-receipt/status/{last}"))
        );
        assert_eq!(db.actor_state_usage("delivery-receipt/status/")?.0, 5);
    }
    let age = 30 * 24 * 60 * 60;
    for (now, remaining) in [(100 + age, 3), (101 + age, 1), (102 + age, 0)] {
        db.retain_delivery_receipts(now, 2)?;
        assert_eq!(
            db.actor_state_usage("delivery-receipt/status/")?.0,
            remaining,
            "wrap must not renew an existing retention timestamp"
        );
    }
    drop(client);
    Ok(())
}

#[tokio::test]
async fn message_attribution_survives_receipt_expiry_and_is_removed_only_with_its_message()
-> TestResult {
    let root = runtime_tests::root("durable-message-origin");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &b)?;
    let mut sender = a.account(None, mail.clone())?;
    let mut transport = sender.session_client().await?;
    let entry = a
        .send_text(&sender.client, &mut transport, a.message(&b, "origin"), b"attributed body")
        .await?;
    let mut receiver = b.account(None, mail)?;
    let pool = receiver.relay_quic_pool()?;
    let mut transport = receiver.session_client().await?;
    crate::bus::sync_driver::process(&mut receiver, &mut transport, &pool, &entry).await?;
    let conversation = a.conversation(&b)?;
    let id = a.event("origin")?;
    let client = &receiver.client;
    let db = client.account_db()?;
    let original = client.message_origin(&conversation, &id)?.ok_or("origin")?;
    let before = client.generated_message_detail(&conversation, &id)?.message;
    assert_eq!(before.author.as_ref().ok_or("author")?.device_id, a.device);
    for _ in 0..3 {
        db.retain_delivery_receipts(now_unix_timestamp() + 90 * 24 * 60 * 60, 128)?;
    }
    assert_eq!(client.message_origin(&conversation, &id)?, Some(original.clone()));
    assert_eq!(client.generated_message_detail(&conversation, &id)?.message.author, before.author);
    client.delete_direct_message(
        &conversation,
        &id,
        "local",
        &ramflux_protocol::encode_base64url([67; 32]),
    )?;
    assert!(client.message_origin(&conversation, &id)?.is_none());
    let stale_key = format!(
        "message/origin/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.delivery-receipt.v1",
            &ramflux_protocol::canonical_json_bytes(&(&conversation, &id, ""))?
        )
    );
    db.persist_actor_state(&stale_key, &original)?;
    let deleted = client.generated_message_detail(&conversation, &id)?.message;
    assert_eq!(deleted.state, "tombstone");
    assert_eq!(
        deleted.author, before.author,
        "immutable author comes from the event identity, never the stale auxiliary origin row"
    );
    assert!(deleted.content.is_none());
    assert!(deleted.text.is_none());
    Ok(())
}
