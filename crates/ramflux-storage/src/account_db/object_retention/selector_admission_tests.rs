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

fn discovery_candidate(
    db: &AccountDb,
    archived: bool,
    live_owner: bool,
) -> Result<(), StorageError> {
    if live_owner {
        db.send_direct_message("thread", "message", "peer", b"body")?;
    }
    db.connection.execute_batch("CREATE TABLE IF NOT EXISTS backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind));")?;
    for (kind, value) in [
        ("directory/object/alias", json!({"message_id":"message","manifest_hash":"manifest"})),
        (
            "attachment/reference/alias",
            json!({"reference":{"object_id":"wire","manifest_hash":"manifest","slot":"private-canary"}}),
        ),
    ] {
        // Seed historical actor bytes directly: current actor admission is not
        // the mechanism this discovery regression exercises.
        if archived {
            db.connection.execute(
                "INSERT INTO backup_archived_actor_state VALUES('archive',?1,?2)",
                params![kind, serde_json::to_vec(&value)?],
            )?;
        } else {
            db.connection.execute(
                "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
                params![kind, serde_json::to_vec(&value)?],
            )?;
        }
    }
    db.connection.execute("UPDATE object_retention_upgrade SET phase=1,cursor=0,unsafe_references=0 WHERE singleton=1", [])?;
    Ok(())
}

#[test]
fn e18_archived_alias_behind_closed_lookup_inserts_nothing() -> Result<(), StorageError> {
    for archived in [false, true] {
        let (root, db) = crate::tests::test_db("discovery-closed")?;
        discovery_candidate(&db, archived, true)?;
        closed(&db)?;
        db.maintain_object_retention()?;
        assert_empty(&db)?;
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
fn e18_no_lookup_no_admissible_owner_counts_unsafe_only() -> Result<(), StorageError> {
    for archived in [false, true] {
        let (root, db) = crate::tests::test_db("discovery-ownerless")?;
        discovery_candidate(&db, archived, false)?;
        db.maintain_object_retention()?;
        assert_empty(&db)?;
        let unsafe_count: i64 = db.connection.query_row(
            "SELECT unsafe_references FROM object_retention_upgrade WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(unsafe_count, 1);
        // No live-store decision/classification value is manufactured.
        let contexts: i64 = db.connection.query_row(
            "SELECT COUNT(*) FROM object_legacy_reference_context",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(contexts, 0);
        drop(db);
        let db = reopen(&root)?;
        assert_empty(&db)?;
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn e18_valid_owner_registers_normally() -> Result<(), StorageError> {
    for archived in [false, true] {
        let (root, db) = crate::tests::test_db("discovery-live")?;
        discovery_candidate(&db, archived, true)?;
        db.maintain_object_retention()?;
        drop(db);
        let db = reopen(&root)?;
        db.check_object_access("alias")?;
        let graph: (i64,i64,String) = db.connection.query_row("SELECT (SELECT COUNT(*) FROM object_retention_reference),(SELECT COUNT(*) FROM object_message_reference),retention_class FROM object_retention_payload", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
        assert_eq!(graph, (1, 1, "imported".to_owned()));
        let bindings: i64 = db.connection.query_row("SELECT COUNT(*) FROM message_copy_binding WHERE message_id='message' AND copy_id IN ('object:alias','object:wire')", [], |row| row.get(0))?;
        assert_eq!(bindings, 2);
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn e18_discovery_page_cut_before_commit() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("discovery-rollback")?;
    discovery_candidate(&db, true, true)?;
    let before: (i64,i64,i64) = db.connection.query_row("SELECT rows_scanned,decoded_bytes,unsafe_references FROM object_retention_upgrade WHERE singleton=1", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
    // Test-only fault at the page's final cursor/budget write, after graph
    // registration but inside the same account writer transaction.
    db.connection.execute_batch("CREATE TRIGGER discovery_cut BEFORE UPDATE ON object_retention_upgrade WHEN NEW.phase=5 AND EXISTS(SELECT 1 FROM object_message_reference) BEGIN SELECT RAISE(ABORT,'discovery cut before commit'); END;")?;
    assert!(db.maintain_object_retention().is_err());
    let path = db.path.clone();
    drop(db);
    let backup = rusqlite::Connection::open(&path)?;
    backup.execute_batch(&format!(
        "PRAGMA key=\"x'{}'\";",
        AccountDbKey::derive("acct", b"storage-test-secret").sqlcipher_hex()
    ))?;
    let cursor: (i64, i64, i64) = backup.query_row(
        "SELECT phase,cursor,rows_scanned FROM object_retention_upgrade WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!((cursor.0, cursor.1), (1, 0));
    let after: (i64,i64,i64) = backup.query_row("SELECT rows_scanned,decoded_bytes,unsafe_references FROM object_retention_upgrade WHERE singleton=1", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
    assert_eq!(after, before);
    for table in [
        "object_retention_payload",
        "object_retention_reference",
        "object_message_reference",
        "message_copy_binding",
    ] {
        let count: i64 =
            backup.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))?;
        assert_eq!(count, 0, "rollback left {table}");
    }
    backup.execute_batch("DROP TRIGGER discovery_cut;")?;
    drop(backup);
    let db = reopen(&root)?;
    db.check_object_access("alias")?;
    let owners: i64 =
        db.connection
            .query_row("SELECT COUNT(*) FROM object_message_reference", [], |row| row.get(0))?;
    assert_eq!(owners, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn revocation_fixture(db: &AccountDb) -> Result<(), StorageError> {
    register(db, ObjectReferenceAdmission::FreshMessage)
}

fn assert_revocation_refused(db: &AccountDb) -> Result<(), StorageError> {
    assert!(matches!(
        db.set_object_tombstoned_with_revocation("alias", Some("peer"), Some("revoke"), 1),
        Err(StorageError::AuthorizationRejected)
    ));
    let count: i64 =
        db.connection.query_row("SELECT COUNT(*) FROM object_index", [], |row| row.get(0))?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn e10_retained_live_reference_is_the_only_manifest_source() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("revoke-retention-only")?;
    revocation_fixture(&db)?;
    assert!(!db.actor_state_exists("attachment/reference/alias")?);
    assert!(db.client_record("object", "alias")?.is_none());
    db.set_object_tombstoned("alias")?;
    drop(db);
    let db = reopen(&root)?;
    let manifest: String = db.connection.query_row(
        "SELECT CAST(manifest_hash AS TEXT) FROM object_index WHERE object_id='alias'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(manifest, "manifest");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn e10_revocation_creation_stores_resolved_nonzero_manifest() -> Result<(), StorageError> {
    for managed in [false, true] {
        let (root, db) = crate::tests::test_db("revoke-nonzero")?;
        if managed {
            revocation_fixture(&db)?;
        }
        db.persist_actor_state(
            "attachment/reference/alias",
            &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
        )?;
        db.persist_client_record(
            "object",
            "alias",
            &json!({"owner":"peer","message_id":"message","manifest_hash":"manifest"}),
        )?;
        db.set_object_tombstoned_with_revocation(
            "alias",
            Some("peer"),
            Some("revoke-envelope"),
            1,
        )?;
        drop(db);
        let db = reopen(&root)?;
        let (manifest, chunk): (Vec<u8>, Vec<u8>) = db.connection.query_row(
            "SELECT manifest_hash,chunk_manifest_hash FROM object_index WHERE object_id='alias'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(manifest, b"manifest");
        assert_eq!(chunk, manifest);
        let count: i64 = db.connection.query_row(
            "SELECT COUNT(*) FROM object_message_reference",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            count,
            i64::from(managed),
            "legacy creation must not fabricate retention ownership"
        );
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn e10_no_source_is_refused_without_row() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("revoke-no-source")?;
    assert_revocation_refused(&db)?;
    drop(db);
    let db = reopen(&root)?;
    assert!(!db.object_is_tombstoned("alias")?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn e10_conflicting_retention_manifests_refused() -> Result<(), StorageError> {
    for actor_conflict in [false, true] {
        let (root, db) = crate::tests::test_db("revoke-conflict")?;
        revocation_fixture(&db)?;
        if actor_conflict {
            db.persist_actor_state(
                "attachment/reference/alias",
                &json!({"reference":{"object_id":"wire","manifest_hash":"other-manifest"}}),
            )?;
        } else {
            db.register_object_reference(
                ObjectReferenceAdmission::FreshMessage,
                &ObjectReferenceOwner {
                    reference_hash: "other-reference",
                    wire_id: "wire",
                    manifest_hash: "other-manifest",
                    selector: "alias",
                    message_id: "other-message",
                    reference: &json!({}),
                    metadata: &json!({}),
                },
            )?;
        }
        assert_revocation_refused(&db)?;
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn e10_stale_display_metadata_cannot_override_mapping() -> Result<(), StorageError> {
    for actor in [false, true] {
        let (root, db) = crate::tests::test_db("revoke-display-conflict")?;
        revocation_fixture(&db)?;
        if actor {
            db.persist_actor_state(
                "attachment/reference/alias",
                &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
            )?;
        }
        db.persist_client_record(
            "object",
            "alias",
            &json!({"owner":"peer","manifest_hash":"stale"}),
        )?;
        assert_revocation_refused(&db)?;
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn e10_display_only_owner_metadata_refused() -> Result<(), StorageError> {
    for manifest in [None, Some("display-manifest")] {
        let (root, db) = crate::tests::test_db("revoke-display-only")?;
        db.persist_client_record(
            "object",
            "alias",
            &json!({"owner":"peer","message_id":"message","manifest_hash":manifest}),
        )?;
        assert_revocation_refused(&db)?;
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
