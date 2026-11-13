// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Tombstones are recorded before deletion drops the bindings and copies they come from.
#![allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]
use super::erased_capture_tests::{bindings, count, current, full, lifetime, tombstone};
use super::privacy_tests::bind;
use super::stage_tests::{bytes, input, run};
use crate::{AccountDb, StorageError};
use rusqlite::params;
use serde_json::{Value, json};

fn work(sequence: u64, payload: &str, principal: &str, device: &str, now: i64) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(&bytes(sequence)).expect("entry fixture");
    v["envelope"]["payload_hash"] = json!(payload);
    v["envelope"]["source_principal_id"] = json!(principal);
    v["envelope"]["source_device_id"] = json!(device);
    v["envelope"]["created_at"] = json!(now);
    v["envelope"]["ttl"] = json!(3600);
    serde_json::to_vec(&v).expect("entry encoding")
}

fn setup(name: &str) -> Result<(ramflux_test_support::TestPath, AccountDb), StorageError> {
    let (root, db) = super::stage_tests::setup(name)?;
    db.connection.disable_background_checkpoints_for_test();
    Ok((root, db))
}

fn tombstones(db: &AccountDb) -> Result<i64, StorageError> {
    count(db, "SELECT count(*) FROM receive_erased_input")
}

#[test]
fn erased_input_recorded_before_bindings_drop() -> Result<(), StorageError> {
    let now = crate::unix_now();
    let expiry = lifetime(now, 3600, now);
    // (a) Work bound to M gets one binding (i) per bound envelope; deleting M leaves exactly
    // one tombstone per envelope and the bindings are gone afterwards.
    let (root, db) = setup("erased-producers-a")?;
    db.send_direct_message("thread", "A", "peer", b"x")?;
    for (seq, payload) in [(1, "pa1"), (2, "pa2")] {
        let wire = work(seq, payload, "pa-p", "pa-d", now);
        assert_eq!(run(&db, input(&wire, seq))?, super::stage::ReceiveStageResult::Staged);
        assert_eq!(bind(&db, seq, "A")?, super::privacy::ReceiveBind::Bound);
    }
    assert_eq!(bindings(&db, "A")?.len(), 2);
    assert_eq!(tombstones(&db)?, 0);
    db.delete_direct_message("thread", "A", "local", "delete-a")?;
    assert!(bindings(&db, "A")?.is_empty(), "the bindings are dropped by the deletion");
    for payload in ["pa1", "pa2"] {
        let (_, selector) = current(&db, "pa-p", "pa-d", payload)?;
        assert_eq!(tombstone(&db, &selector)?, Some(expiry), "{payload}");
    }
    assert_eq!(tombstones(&db)?, 2);
    // (b) A routed-committed copy (source ii) yields a tombstone.
    db.send_direct_message("thread", "B", "peer", b"x")?;
    db.persist_actor_state(
        "routed/committed/b",
        &json!({"routing":{"message_id":"B"},"entry":{"envelope":full("pb-p","pb-d","pb",now,3600)}}),
    )?;
    db.delete_direct_message("thread", "B", "local", "delete-b")?;
    let (_, sel_b) = current(&db, "pb-p", "pb-d", "pb")?;
    assert_eq!(tombstone(&db, &sel_b)?, Some(expiry));
    // (c) Live staged work owned through its payload (source iii), with no binding (i).
    db.send_direct_message("thread", "C", "peer", b"x")?;
    let wire = work(3, "pc", "pc-p", "pc-d", now);
    assert_eq!(run(&db, input(&wire, 3))?, super::stage::ReceiveStageResult::Staged);
    db.connection.execute("INSERT INTO message_copy_binding VALUES('payload:pc','C')", [])?;
    assert_eq!(bindings(&db, "C")?, Vec::<String>::new());
    db.delete_direct_message("thread", "C", "local", "delete-c")?;
    let (_, sel_c) = current(&db, "pc-p", "pc-d", "pc")?;
    assert_eq!(tombstone(&db, &sel_c)?, Some(expiry));
    assert_eq!(tombstones(&db)?, 4);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn erased_input_remote_group_delete_converts_only_its_message() -> Result<(), StorageError> {
    // (d) A remote group delete converts only M's envelopes; an unrelated message has no row.
    let now = crate::unix_now();
    let (root, db) = crate::tests::test_db("erased-producers-d")?;
    let identity = ramflux_crypto::create_identity_root("owner", [0x72; 32]);
    let actor = ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
        &identity,
        "owner-device",
    )?;
    db.create_group("group", actor.device_id())?;
    db.persist_group_member_device_key("group", &actor, "owner-key")?;
    for (id, payload) in [("group-message", "pd1"), ("other-message", "pd2")] {
        db.send_direct_message("group", id, actor.device_id(), b"secret")?;
        db.persist_actor_state(
            &format!("routed/committed/{id}"),
            &json!({"routing":{"message_id":id},"entry":{"envelope":full("pd-p","pd-d",payload,now,3600)}}),
        )?;
    }
    db.apply_group_message_delete(
        &crate::GroupMessageDeleteWrite {
            group_id: "group".into(),
            event_id: "delete-event".into(),
            actor_device_id: actor.device_id().into(),
            target_message_id: "group-message".into(),
            group_epoch: 1,
            delete_scope: "all_devices".into(),
            tombstone_id: "group-tombstone".into(),
            reason: "user".into(),
        },
        &actor,
    )?;
    let (_, deleted) = current(&db, "pd-p", "pd-d", "pd1")?;
    let (_, unrelated) = current(&db, "pd-p", "pd-d", "pd2")?;
    assert_eq!(tombstone(&db, &deleted)?, Some(lifetime(now, 3600, now)));
    assert_eq!(tombstone(&db, &unrelated)?, None);
    assert_eq!(tombstones(&db)?, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn erased_input_conversation_delete_converts_the_sum_of_envelopes() -> Result<(), StorageError> {
    // (e) A conversation-wide expiry over k messages records exactly the sum; none is evicted.
    let now = crate::unix_now();
    let (root, db) = crate::tests::test_db("erased-producers-e")?;
    for n in 0..3 {
        let id = format!("expiring-{n}");
        db.send_direct_message_at_with_metadata(crate::DirectMessageWrite {
            conversation_id: "thread",
            message_id: &id,
            sender_id: "peer",
            encrypted_body: b"x",
            metadata: &crate::MessageMetadata::default(),
            created_at: 1,
        })?;
        db.persist_actor_state(
            &format!("routed/committed/{id}"),
            &json!({"routing":{"message_id":id},"entry":{"envelope":full("pe-p","pe-d",&format!("pe{n}"),now,3600)}}),
        )?;
    }
    db.set_disappearing_policy("thread", 5, "on_send", "all_devices", 1)?;
    assert_eq!(db.expire_disappearing_messages("thread", 6)?.len(), 3);
    assert_eq!(tombstones(&db)?, 3);
    for n in 0..3 {
        let (_, selector) = current(&db, "pe-p", "pe-d", &format!("pe{n}"))?;
        assert!(tombstone(&db, &selector)?.is_some());
    }
    let _ = params![0];
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn erased_input_live_capture_sweeps_expired_rows_up_to_the_bound() -> Result<(), StorageError> {
    let now = crate::unix_now();
    let expiry = lifetime(now, 3600, now);
    let (root, db) = setup("erased-producers-sweep")?;
    db.send_direct_message("thread", "S", "peer", b"x")?;
    let wire = work(1, "ps", "ps-p", "ps-d", now);
    assert_eq!(run(&db, input(&wire, 1))?, super::stage::ReceiveStageResult::Staged);
    assert_eq!(bind(&db, 1, "S")?, super::privacy::ReceiveBind::Bound);
    for n in 0..100 {
        db.connection.execute(
            "INSERT INTO receive_erased_input VALUES(?1,'old-bundle',1)",
            params![format!("expired-{n:03}")],
        )?;
    }
    db.connection.execute(
        "INSERT INTO receive_erased_input VALUES('live-existing','live-bundle',?1)",
        params![now + 5_000],
    )?;
    db.delete_direct_message("thread", "S", "local", "delete-s")?;
    let (_, selector) = current(&db, "ps-p", "ps-d", "ps")?;
    assert_eq!(tombstone(&db, &selector)?, Some(expiry), "the captured tuple is recorded");
    assert_eq!(
        count(&db, "SELECT count(*) FROM receive_erased_input WHERE expires_at<=1")?,
        36,
        "one write reclaims at most 64 expired rows"
    );
    assert_eq!(tombstone(&db, "live-existing")?, Some(now + 5_000));
    assert_eq!(tombstones(&db)?, 38);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
