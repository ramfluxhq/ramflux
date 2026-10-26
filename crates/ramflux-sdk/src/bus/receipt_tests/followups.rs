// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receipt follow-ups preserve message commits, explicit retry and bounded retention.
use super::*;
use serde_json::json;

#[test]
fn missing_local_root_does_not_roll_back_an_incoming_message_transaction() -> TestResult {
    let root = runtime_tests::root("receipt-no-root");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    fixture::seed_pair(&a, &b)?;
    let sender = a.client(None)?;
    let config = a.config(&sender)?;
    let entry = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: b.device.clone(),
        envelope: gateway_direct_message_envelope(&config, &a.message(&b, "incoming"), None)?,
    };
    let mut receiver = b.client(None)?;
    receiver.identity_root = None;
    let db = receiver.account_db()?;
    db.write_transaction(|| -> Result<(), SdkError> {
        receiver.send_direct_message("thread", "incoming", &a.device, b"ciphertext")?;
        db.store_message_content("thread", "incoming", b"incoming plaintext")?;
        receiver.stage_delivery_receipt("thread", "incoming", &entry)
    })?;
    assert!(receiver.direct_message_by_id("incoming")?.is_some());
    assert_eq!(db.message_content("incoming")?, Some(b"incoming plaintext".to_vec()));
    assert_eq!(db.actor_state_usage(PREFIX)?.0, 0);
    drop(receiver);
    drop(sender);
    std::fs::remove_dir_all(root)?;
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
    std::fs::remove_dir_all(root)?;
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
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn message_attribution_survives_receipt_expiry_and_is_removed_only_with_its_message() -> TestResult
{
    let root = runtime_tests::root("durable-message-origin");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    fixture::seed_pair(&a, &b)?;
    let sender = a.client(None)?;
    let receiver = b.client(None)?;
    let entry = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: b.device.clone(),
        envelope: gateway_direct_message_envelope(
            &a.config(&sender)?,
            &a.message(&b, "origin"),
            None,
        )?,
    };
    let db = receiver.account_db()?;
    db.write_transaction(|| -> Result<(), SdkError> {
        receiver.send_direct_message("thread", "origin", &a.device, b"ciphertext")?;
        receiver.stage_delivery_receipt("thread", "origin", &entry)
    })?;
    let original = receiver.message_origin("thread", "origin")?.ok_or("origin")?;
    let request = LocalBusFrame::request(
        "origin-read",
        Some("bob".into()),
        "test",
        "message.read",
        json!({"conversation_id":"thread"}),
    );
    let before = crate::bus::readers::read(&receiver, &request)?;
    assert_eq!(original["sender_device_id"], a.device);
    for _ in 0..3 {
        db.retain_delivery_receipts(now_unix_timestamp() + 90 * 24 * 60 * 60, 128)?;
    }
    assert_eq!(receiver.message_origin("thread", "origin")?, Some(original));
    let after = crate::bus::readers::read(&receiver, &request)?;
    for field in ["sender_device_id", "sender_root_commitment", "sender_device_display"] {
        assert_eq!(after["messages"][0][field], before["messages"][0][field]);
        assert!(!after["messages"][0][field].is_null());
    }
    receiver.delete_direct_message("thread", "origin", "local", "deleted-origin")?;
    assert!(receiver.message_origin("thread", "origin")?.is_none());
    drop(receiver);
    drop(sender);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
