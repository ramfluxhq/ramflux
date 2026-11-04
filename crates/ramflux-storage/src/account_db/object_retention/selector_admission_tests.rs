// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::{AccountDbKey, AccountIndex};
use serde_json::json;

fn register(db: &AccountDb, context: ObjectReferenceAdmission) -> Result<(), StorageError> {
    db.register_object_reference(
        context,
        &ObjectReferenceOwner {
            reference_hash: "reference",
            wire_id: "wire",
            manifest_hash: "manifest",
            selector: "alias",
            message_id: "message",
            reference: &json!({"key":"secret"}),
            metadata: &json!({"message_id":"message"}),
        },
    )
}

fn closed(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.execute(
        "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
        params![
            object_erasure_lookup(db.object_erasure_root(), "alias"),
            object_erasure_commitment(db.object_erasure_root(), "wire", "manifest"),
        ],
    )?;
    Ok(())
}

fn reopen(root: &std::path::Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &AccountIndex::open(root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn assert_empty(db: &AccountDb) -> Result<(), StorageError> {
    for table in [
        "object_retention_payload",
        "object_retention_reference",
        "object_message_reference",
        "message_copy_binding",
    ] {
        let count: i64 =
            db.connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))?;
        assert_eq!(count, 0, "unexpected write to {table}");
    }
    Ok(())
}

#[test]
fn e16a_fresh_context_admits_new_owner_on_closed_selector() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-fresh")?;
    closed(&db)?;
    register(&db, ObjectReferenceAdmission::FreshMessage)?;
    drop(db);
    let db = reopen(&root)?;
    db.check_object_access("alias")?;
    let count: i64 = db.connection.query_row(
        "SELECT COUNT(*) FROM object_message_reference WHERE message_id='message'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn e16a_historical_context_refuses_identical_candidate() -> Result<(), StorageError> {
    for context in [
        ObjectReferenceAdmission::Restore,
        ObjectReferenceAdmission::ArchiveDiscovery,
        ObjectReferenceAdmission::OwnCopy,
    ] {
        let (root, db) = crate::tests::test_db("selector-historical")?;
        closed(&db)?;
        assert!(matches!(register(&db, context), Err(StorageError::ObjectErased)));
        drop(db);
        let db = reopen(&root)?;
        assert_empty(&db)?;
        assert!(matches!(db.check_object_access("alias"), Err(StorageError::ObjectErased)));
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn e16a_deleted_owner_refused_under_both_contexts() -> Result<(), StorageError> {
    for context in [
        ObjectReferenceAdmission::FreshMessage,
        ObjectReferenceAdmission::Restore,
        ObjectReferenceAdmission::ArchiveDiscovery,
        ObjectReferenceAdmission::OwnCopy,
    ] {
        let (root, db) = crate::tests::test_db("selector-deleted")?;
        db.send_direct_message("thread", "message", "peer", b"body")?;
        db.delete_direct_message("thread", "message", "local", "delete")?;
        assert!(matches!(register(&db, context), Err(StorageError::ObjectErased)));
        drop(db);
        let db = reopen(&root)?;
        assert_empty(&db)?;
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn e16a_payload_fenced_refused_under_both_contexts() -> Result<(), StorageError> {
    for context in [
        ObjectReferenceAdmission::FreshMessage,
        ObjectReferenceAdmission::Restore,
        ObjectReferenceAdmission::ArchiveDiscovery,
        ObjectReferenceAdmission::OwnCopy,
    ] {
        let (root, db) = crate::tests::test_db("selector-fenced")?;
        db.connection.execute(
            "INSERT INTO object_erasure_fence VALUES(?1)",
            params![object_erasure_commitment(db.object_erasure_root(), "wire", "manifest")],
        )?;
        assert!(matches!(register(&db, context), Err(StorageError::ObjectErased)));
        drop(db);
        let db = reopen(&root)?;
        assert_empty(&db)?;
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn e1_closed_lookup_with_injected_ownerless_reference_is_erased() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-orphan")?;
    register(&db, ObjectReferenceAdmission::FreshMessage)?;
    // Inject historical corruption without running the ordinary message erasure trigger.
    db.connection.execute("DELETE FROM object_message_reference", [])?;
    closed(&db)?;
    drop(db);
    let db = reopen(&root)?;
    assert!(matches!(db.check_object_access("alias"), Err(StorageError::ObjectErased)));
    assert!(matches!(
        db.persist_actor_state("attachment/reference-by-slot/stale", &json!("alias")),
        Err(StorageError::ObjectErased)
    ));
    for key in ["attachment/reference/alias", "directory/object/alias", "sync/attachment/alias"] {
        assert!(matches!(
            db.persist_actor_state(
                key,
                &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}})
            ),
            Err(StorageError::ObjectErased)
        ));
        assert!(!db.actor_state_exists(key)?);
    }
    let bindings: i64 =
        db.connection
            .query_row("SELECT COUNT(*) FROM object_payload_actor", [], |row| row.get(0))?;
    assert_eq!(bindings, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn e2_historical_partial_lookup_keeps_survivor() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-survivor")?;
    register(&db, ObjectReferenceAdmission::FreshMessage)?;
    closed(&db)?;
    register(&db, ObjectReferenceAdmission::OwnCopy)?;
    drop(db);
    let db = reopen(&root)?;
    db.check_object_access("alias")?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
