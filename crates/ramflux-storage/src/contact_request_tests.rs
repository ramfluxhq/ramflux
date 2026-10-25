// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable consent capacity, root-scoped message caps and independent rate windows.
use super::tests::test_db;
use crate::{ContactMessageRequestWrite, ContactRequestRecord, StorageError};
fn record(root: &str, id: &str, expires_at: i64) -> ContactRequestRecord {
    ContactRequestRecord {
        contact_identity_commitment: root.into(),
        direction: "inbound".into(),
        request_id: id.into(),
        principal_id: format!("peer-{id}"),
        link_id: format!("link-{id}"),
        state: "pending".into(),
        request_json: b"{}".to_vec(),
        expires_at,
        updated_at: 1000,
    }
}
fn device(seed: u8) -> Result<ramflux_crypto::RootQualifiedDeviceRef, StorageError> {
    Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
        &ramflux_crypto::create_identity_root("peer", [seed; 32]),
        &ramflux_crypto::create_device_branch("peer", "phone", 1, [seed + 1; 32]),
    )?)
}
#[test]
fn contact02_storage_caps_requests_and_messages_without_conflating_same_name_roots()
-> Result<(), StorageError> {
    let (path, db) = test_db("contact-request-caps")?;
    for id in 0..128 {
        assert!(db.persist_contact_request(&record(
            &format!("root-{id}"),
            &id.to_string(),
            2000
        ))?);
    }
    assert!(matches!(
        db.persist_contact_request(&record("extra", "extra", 2000)),
        Err(StorageError::AuthorizationRejected)
    ));
    assert!(
        !db.persist_contact_request(&record("root-0", "0", 2000))?,
        "a replay consumes no extra pending slot"
    );
    assert_eq!(db.pending_contact_requests()?.len(), 128);
    db.expire_contact_requests(2001)?;
    assert!(db.pending_contact_requests()?.is_empty());
    let a = device(11)?;
    let b = device(21)?;
    for actor in [&a, &b] {
        assert!(db.persist_contact_request(&record(
            actor.root_commitment(),
            actor.root_commitment(),
            4000
        ))?);
    }
    for index in 0..20 {
        assert!(db.hold_contact_message(ContactMessageRequestWrite {
            sender: &a,
            message_id: &format!("message-{index}"),
            conversation_id: "thread",
            message_json: b"private",
            expires_at: 3000,
            created_at: 2001
        })?);
    }
    assert!(!db.hold_contact_message(ContactMessageRequestWrite {
        sender: &a,
        message_id: "overflow",
        conversation_id: "thread",
        message_json: b"private",
        expires_at: 3000,
        created_at: 2001
    })?);
    assert!(db.hold_contact_message(ContactMessageRequestWrite {
        sender: &b,
        message_id: "message-0",
        conversation_id: "thread",
        message_json: b"other-root",
        expires_at: 3000,
        created_at: 2001
    })?);
    assert_eq!(db.held_contact_messages(a.root_commitment())?.len(), 20);
    assert_eq!(db.held_contact_messages(b.root_commitment())?.len(), 1);
    db.discard_contact_messages(a.root_commitment())?;
    assert_eq!(db.held_contact_messages(b.root_commitment())?.len(), 1);
    assert!(!db.hold_contact_message(ContactMessageRequestWrite {
        sender: &b,
        message_id: "oversized",
        conversation_id: "thread",
        message_json: &vec![1; 1_048_577],
        expires_at: 3000,
        created_at: 2001
    })?);
    db.expire_contact_requests(3001)?;
    assert_eq!(db.held_contact_messages(b.root_commitment())?.len(), 0);
    drop(db);
    std::fs::remove_dir_all(path)?;
    Ok(())
}
#[test]
fn contact02_short_rate_windows_cannot_reset_a_requesters_hourly_budget() -> Result<(), StorageError>
{
    let (path, db) = test_db("contact-request-rates")?;
    assert!(db.charge_contact_request("hourly", 2, 3600, 1000)?);
    assert!(db.charge_contact_request("hourly", 2, 3600, 1001)?);
    assert!(db.charge_contact_request("short", 2, 60, 1100)?);
    assert!(!db.charge_contact_request("hourly", 2, 3600, 1101)?);
    assert!(db.charge_contact_request("hourly", 2, 3600, 4601)?);
    drop(db);
    std::fs::remove_dir_all(path)?;
    Ok(())
}
