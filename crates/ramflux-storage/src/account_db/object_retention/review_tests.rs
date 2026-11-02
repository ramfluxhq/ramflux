// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Upgrade provenance, indexed deletion, generation accounting and committed-write outcomes.
use super::tests::{install, payload};
use super::*;
use serde_json::json;

type TestResult = Result<(), StorageError>;

// Mutation: remove legacy-to-imported promotion after discovery installs a live owner.
#[test]
fn discovered_legacy_attachment_is_erased_after_last_owner_delete_and_reopen() -> TestResult {
    let (root, db) = crate::tests::test_db("legacy-owned-erasure")?;
    db.send_direct_message("thread", "legacy-owner", "peer", b"body")?;
    payload(&db)?;
    db.persist_actor_state(
        "directory/object/wire",
        &json!({
            "message_id":"legacy-owner", "manifest_hash":"manifest"
        }),
    )?;
    db.persist_actor_state(
        "attachment/reference/wire",
        &json!({
            "reference":{"object_id":"wire","manifest_hash":"manifest","slot":"private-canary"}
        }),
    )?;
    db.connection
        .execute("UPDATE object_retention_upgrade SET phase=0,cursor=0 WHERE singleton=1", [])?;
    drop(db);
    let db = reopen(&root)?;
    let class: String = db.connection.query_row(
        "SELECT retention_class FROM object_retention_payload WHERE wire_id='wire'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(class, "imported", "a live discovered owner proves import provenance");
    db.delete_direct_message("thread", "legacy-owner", "local", "delete")?;
    drop(db);
    let db = reopen(&root)?;
    assert!(matches!(db.load_object::<Value>("wire"), Err(StorageError::ObjectErased)));
    let rows: i64 = db.connection.query_row("SELECT count(*) FROM object_index WHERE object_id='wire' AND (ciphertext IS NOT NULL OR object_content_key IS NOT NULL OR object_body IS NOT NULL)", [], |row| row.get(0))?;
    assert_eq!(rows, 0);
    super::tests::assert_erasure_canary_absent(&db)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn reopen(root: &std::path::Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &crate::AccountIndex::open(root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

// Mutation: remove the indexed wire-id predicate from payload cleanup DELETE statements.
#[test]
fn attachment_cleanup_plans_probe_object_indexes_and_skip_messages_without_edges() -> TestResult {
    let (root, db) = crate::tests::test_db("object-cleanup-plans")?;
    db.connection.call(|sql| {
        let trigger: String = sql.query_row("SELECT sql FROM sqlite_master WHERE name='object_erase_message'", [], |row| row.get(0))?;
        assert!(trigger.contains("AND EXISTS(SELECT 1 FROM object_message_reference WHERE message_id=NEW.message_id)"));
        let mut guard = sql.prepare("EXPLAIN QUERY PLAN SELECT EXISTS(SELECT 1 FROM object_message_reference WHERE message_id=?1)")?;
        let plan = guard.query_map(["without-attachment"], |row| row.get::<_, String>(3))?.collect::<rusqlite::Result<Vec<_>>>()?;
        eprintln!("guard: {plan:?}");
        assert!(plan.iter().any(|line| line.contains("SEARCH object_message_reference")));
        for statement in schema::payload_cleanup(sql)?.split(';').filter(|s| !s.trim().is_empty()) {
            let mut query = sql.prepare(&format!("EXPLAIN QUERY PLAN {statement}"))?;
            let plan = query.query_map([], |row| row.get::<_, String>(3))?.collect::<rusqlite::Result<Vec<_>>>()?;
            eprintln!("{statement}: {plan:?}");
            for table in ["object_index", "object_chunk", "object_transfer_state", "object_key_slot", "object_manifest", "object_operation", "object_share_grant_projection", "object_tombstone"] {
                assert!(!plan.iter().any(|line| line.contains(&format!("SCAN {table}"))), "unbounded {table}: {plan:?}");
            }
        }
        Ok(())
    })?;
    db.send_direct_message("thread", "without-attachment", "peer", b"body")?;
    db.delete_direct_message("thread", "without-attachment", "local", "delete")?;
    assert_eq!(db.privacy_erasure_generation()?, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: bump the privacy generation unconditionally or again in PAYLOAD_ERASE.
#[test]
fn attachment_privacy_generation_changes_once_for_real_removal_and_not_refires() -> TestResult {
    let (root, db) = crate::tests::test_db("object-generation-accounting")?;
    db.send_direct_message("thread", "plain", "peer", b"body")?;
    let generation = db.privacy_erasure_generation()?;
    db.delete_direct_message("thread", "plain", "local", "delete-plain")?;
    assert_eq!(db.privacy_erasure_generation()?, generation);
    let registration =
        db.register_privacy_resource("plain-publication", generation, Arc::new(|| Ok(())))?;
    drop(registration);
    install(&db, "attached", "reference")?;
    payload(&db)?;
    db.delete_direct_message("thread", "attached", "local", "delete-attached")?;
    assert_eq!(db.privacy_erasure_generation()?, generation + 1);
    db.connection.execute(
        "UPDATE direct_message_projection SET deleted=1 WHERE message_id='attached'",
        [],
    )?;
    assert_eq!(db.privacy_erasure_generation()?, generation + 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: propagate notify_object_retirement() with `?` after the transaction commits.
#[test]
fn attachment_notification_failure_keeps_committed_delete_success_and_clears_cache() -> TestResult {
    let (root, db) = crate::tests::test_db("object-notification-failure")?;
    install(&db, "message", "reference")?;
    payload(&db)?;
    let cleared = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::clone(&cleared);
    db.observe_object_retirement(Arc::new(move |identities| {
        if identities.is_none() {
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }))?;
    let _resource = db.register_privacy_resource(
        "failed-notification",
        db.privacy_erasure_generation()?,
        Arc::new(|| Err(StorageError::AuthorizationRejected)),
    )?;
    let deletion = db.delete_direct_message("thread", "message", "local", "delete");
    assert!(deletion.is_ok(), "committed deletion reported failure: {deletion:?}");
    assert!(db.message_is_deleted("message")?);
    assert!(cleared.load(std::sync::atomic::Ordering::SeqCst));
    assert!(matches!(db.load_object::<Value>("wire"), Err(StorageError::ObjectErased)));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
