// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receipt admission, display and migration retain authenticated root separation.
use super::*;
fn actor(seed: u8) -> Result<ramflux_crypto::RootQualifiedDeviceRef, StorageError> {
    Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
        &ramflux_crypto::create_identity_root("actor", [seed; 32]),
        "bob",
    )?)
}
#[test]
fn receipt_ids_and_display_are_independent_for_same_name_devices_under_different_roots()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receipt-root-scope")?;
    db.send_direct_message("thread", "message", "sender", b"ciphertext")?;
    let bob = actor(1)?;
    let mallory = actor(2)?;
    for source in [&mallory, &bob] {
        assert!(db.record_receipt_event_once(ReceiptEventWrite {
            receipt_id: "same-receipt",
            conversation_id: "thread",
            message_id: "message",
            receipt_type: "delivered",
            actor: source,
            created_at: 100
        })?);
        db.mark_delivered("thread", source, "message", 100, 300)?;
    }
    assert!(!db.record_receipt_event_once(ReceiptEventWrite {
        receipt_id: "same-receipt",
        conversation_id: "thread",
        message_id: "message",
        receipt_type: "delivered",
        actor: &bob,
        created_at: 100
    })?);
    let messages = db.direct_messages("thread")?;
    assert_eq!(messages[0].receipts.len(), 2);
    assert!(messages[0].receipts.iter().all(|row| row.device_id == "bob"));
    let roots = messages[0]
        .receipts
        .iter()
        .filter_map(|row| row.principal_commitment.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        roots,
        std::collections::BTreeSet::from([bob.root_commitment(), mallory.root_commitment()])
    );
    db.mark_read("thread", &bob, "message")?;
    assert_eq!(
        db.conversation_projection("thread", Some(&bob))?.read_through_message_id.as_deref(),
        Some("message")
    );
    assert_eq!(db.conversation_projection("thread", Some(&mallory))?.read_through_message_id, None);
    let receipt =
        db.delivery_receipt("thread", &bob)?.ok_or(StorageError::AuthorizationRejected)?;
    assert_eq!(receipt.receiver_device_id, "bob");
    assert_eq!(receipt.receiver_principal_commitment, bob.root_commitment());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn unproven_old_actor_strings_never_satisfy_a_qualified_receipt_lookup() -> Result<(), StorageError>
{
    let (root, db) = crate::tests::test_db("receipt-legacy-prefix")?;
    db.send_direct_message("thread", "message", "sender", b"ciphertext")?;
    let bob = actor(1)?;
    db.connection.execute(
        "INSERT INTO conversation_delivery_state VALUES('thread',?1,'message',100,300)",
        params![bob.storage_key()],
    )?;
    db.connection.execute(
        "INSERT INTO conversation_read_state VALUES('thread',?1,'message',100)",
        params![bob.storage_key()],
    )?;
    db.connection.execute("DELETE FROM receipt_identity_upgrade", [])?;
    drop(db);
    let index = AccountIndex::open(&root)?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    assert_eq!(db.delivery_receipt("thread", &bob)?, None);
    assert_eq!(db.conversation_projection("thread", Some(&bob))?.read_through_message_id, None);
    assert_eq!(
        db.connection.query_row(
            "SELECT count(*) FROM legacy_conversation_delivery_state",
            [],
            |row| row.get::<_, u32>(0)
        )?,
        1
    );
    assert_eq!(db.direct_messages("thread")?[0].encrypted_body, b"ciphertext");
    db.mark_delivered("thread", &bob, "message", 101, 300)?;
    assert_eq!(
        db.delivery_receipt("thread", &bob)?
            .ok_or(StorageError::AuthorizationRejected)?
            .receiver_device_id,
        "bob"
    );
    assert_eq!(db.expire_delivery_receipts(401)?, 2);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn durable_ack_positions_ignore_old_raw_ids_and_separate_receiver_roots() -> Result<(), StorageError>
{
    let (root, db) = crate::tests::test_db("ack-root-scope")?;
    let bob = actor(1)?;
    let mallory = actor(2)?;
    db.connection.execute("INSERT INTO runtime_ack(envelope_id) VALUES('same-id')", [])?;
    db.remember_gateway_ack(&mallory, "same-mailbox", 1)?;
    assert!(!db.has_gateway_ack(&bob, "same-mailbox", 1)?);
    db.remember_gateway_ack(&bob, "same-mailbox", 1)?;
    drop(db);
    let index = AccountIndex::open(&root)?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    assert!(db.has_gateway_ack(&bob, "same-mailbox", 1)?);
    assert!(!db.has_gateway_ack(&bob, "same-mailbox", 2)?);
    assert!(!db.has_gateway_ack(&bob, "another-mailbox", 1)?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
