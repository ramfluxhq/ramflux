// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Managed selector death and transport dependency capture.
use super::*;
use serde_json::json;

fn register(db: &AccountDb, selector: &str, message: &str, hash: &str) -> Result<(), StorageError> {
    db.send_direct_message("thread", message, "peer", b"body")?;
    db.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: hash,
            wire_id: "wire",
            manifest_hash: "manifest",
            selector,
            message_id: message,
            reference: &json!({"object_id":"wire","slot":hash}),
            metadata: &json!({"object_id":selector,"message_id":message}),
        },
    )?;
    Ok(())
}

fn placeholder(db: &AccountDb, selector: &str) -> Result<(), StorageError> {
    // Authenticated retained mapping exists; G2 fallback tightening is a later slice.
    db.persist_actor_state(
        &format!("attachment/reference/{selector}"),
        &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
    )?;
    db.set_object_tombstoned(selector)?;
    let key = format!("attachment/reference-by-slot/{selector}");
    db.persist_actor_state(&key, &json!(selector))?;
    let hashes: Vec<String> = db
        .connection
        .prepare("SELECT reference_hash FROM object_retention_reference WHERE selector=?1")?
        .query_map(params![selector], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for hash in hashes {
        db.register_object_reference_actor(&hash, &key)?;
    }
    Ok(())
}

fn assert_retired(db: &AccountDb, selector: &str) -> Result<(), StorageError> {
    assert!(matches!(db.check_object_access(selector), Err(StorageError::ObjectErased)));
    let count: i64 = db.connection.query_row(
        "SELECT count(*) FROM object_index WHERE object_id=?1",
        params![selector],
        |r| r.get(0),
    )?;
    assert_eq!(count, 0, "placeholder survived selector retirement");
    for key in [
        format!("attachment/reference/{selector}"),
        format!("directory/object/{selector}"),
        format!("attachment/reference-by-slot/{selector}"),
    ] {
        assert!(!db.actor_state_exists(&key)?, "actor survived: {key}");
        let count: i64 = db.connection.query_row(
            "SELECT count(*) FROM object_payload_actor WHERE state_kind=?1",
            params![key],
            |r| r.get(0),
        )?;
        assert_eq!(count, 0, "payload actor binding survived");
    }
    let bindings: i64 = db.connection.query_row(
        "SELECT count(*) FROM message_copy_binding WHERE copy_id=?1",
        params![format!("object:{selector}")],
        |r| r.get(0),
    )?;
    assert_eq!(bindings, 0);
    for table in
        ["object_erasure_work", "object_reference_erasure_work", "object_projection_erasure_work"]
    {
        let count: i64 =
            db.connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
        assert_eq!(count, 0, "work survived: {table}");
    }
    Ok(())
}

fn reopen(root: &std::path::Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &crate::AccountIndex::open(root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn verify_snapshot(db: &AccountDb, root: &std::path::Path) -> Result<(), StorageError> {
    db.checkpoint_retired_secrets()?;
    super::tests::assert_erasure_canary_absent(db)?;
    let path = root.join("retired-snapshot.db");
    let snapshot = db.write_backup_snapshot(&path)?;
    let sql = rusqlite::Connection::open(&path)?;
    sql.execute_batch(&format!("PRAGMA key=\"x'{}'\";", snapshot.key.sqlcipher_hex()))?;
    super::tests::assert_erasure_canary_absent_sql(&sql)?;
    Ok(())
}

fn alias_deletion(first: &str, second: &str) -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-death")?;
    register(&db, "private-canary", "m1", "r1")?;
    register(&db, "private-canary", "m2", "r2")?;
    register(&db, "survivor", "m3", "r3")?;
    placeholder(&db, "private-canary")?;
    db.delete_direct_message("thread", first, "local", "delete-first")?;
    assert!(db.object_is_tombstoned("private-canary")?);
    db.check_object_access("private-canary")?;
    let lookup: i64 = db.connection.query_row(
        "SELECT count(*) FROM object_erasure_lookup WHERE lookup=?1",
        params![object_erasure_lookup(db.object_erasure_root(), "private-canary")],
        |r| r.get(0),
    )?;
    assert_eq!(lookup, 0, "a surviving selector must not acquire a new lookup");
    db.delete_direct_message("thread", second, "local", "delete-second")?;
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    db.check_object_access("survivor")?;
    assert_eq!(db.object_erasure_generation()?, 0, "another selector keeps C alive");
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn alias_order(first: &str, second: &str) -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("alias-order")?;
    register(&db, "wire", "m1", "wire-reference")?;
    register(&db, "private-canary", "m2", "alias-reference")?;
    super::tests::payload(&db)?;
    placeholder(&db, "private-canary")?;
    db.delete_direct_message("thread", first, "local", "delete-first")?;
    if first == "m2" {
        assert_retired(&db, "private-canary")?;
        db.check_object_access("wire")?;
        assert!(db.load_object::<Value>("wire")?.is_some());
        assert_eq!(db.object_erasure_generation()?, 0);
    } else {
        assert!(db.object_is_tombstoned("private-canary")?);
        db.check_object_access("private-canary")?;
    }
    db.delete_direct_message("thread", second, "local", "delete-second")?;
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn e1_alias_dies_with_last_reference_m2_then_m1() -> Result<(), StorageError> {
    alias_order("m2", "m1")
}
#[test]
fn e1_alias_dies_with_last_reference_m1_then_m2() -> Result<(), StorageError> {
    alias_order("m1", "m2")
}

#[test]
fn e2_same_selector_distinct_hashes_survive_first_delete() -> Result<(), StorageError> {
    alias_deletion("m1", "m2")
}

#[test]
fn e2_shared_hash_two_owners() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-shared-hash")?;
    register(&db, "private-canary", "m1", "shared")?;
    register(&db, "private-canary", "m2", "shared")?;
    placeholder(&db, "private-canary")?;
    db.delete_direct_message("thread", "m1", "local", "delete-one")?;
    assert!(db.object_is_tombstoned("private-canary")?);
    db.check_object_access("private-canary")?;
    db.delete_direct_message("thread", "m2", "local", "delete-two")?;
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn transport(hold_child: bool, two_hops: bool, message_seeded: bool) -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-transport")?;
    register(&db, "private-canary", "m1", "parent-ref")?;
    db.retain_object("wire", "manifest", ObjectRetention::OwnDeviceTransport)?;
    placeholder(&db, "private-canary")?;
    let child =
        if hold_child { Some(db.pre_send_object_hold("child", "child-manifest")?) } else { None };
    if hold_child || two_hops || message_seeded {
        if child.is_none() {
            db.retain_object("child", "child-manifest", ObjectRetention::Imported)?;
        }
        if two_hops {
            db.retain_object("middle", "middle-manifest", ObjectRetention::OwnDeviceTransport)?;
            db.retain_transport_dependency("wire", "manifest", "middle", "middle-manifest")?;
            db.retain_transport_dependency("middle", "middle-manifest", "child", "child-manifest")?;
        } else {
            db.retain_transport_dependency("wire", "manifest", "child", "child-manifest")?;
        }
    }
    if let Some(child) = child {
        let (class,owners):(String,i64)=db.connection.query_row("SELECT retention_class,owner_count FROM object_retention_payload WHERE wire_id='child'",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        assert_eq!((class.as_str(), owners), ("pre_send", 0));
        child.release()?;
    } else if message_seeded {
        db.send_direct_message("thread", "child-message", "peer", b"body")?;
        db.register_object_reference(
            ObjectReferenceAdmission::FreshMessage,
            &ObjectReferenceOwner {
                reference_hash: "child-ref",
                wire_id: "child",
                manifest_hash: "child-manifest",
                selector: "child-alias",
                message_id: "child-message",
                reference: &json!({}),
                metadata: &json!({}),
            },
        )?;
        db.delete_direct_message("thread", "child-message", "local", "child-delete")?;
    } else if two_hops {
        // The public transport retirement API seeds only transports.
        db.retain_object("child", "child-manifest", ObjectRetention::OwnDeviceTransport)?;
        db.retire_transport_object("child", "child-manifest")?;
    } else {
        db.retire_transport_object("wire", "manifest")?;
    }
    drop(db);
    let db = reopen(&root)?;
    assert_retired(&db, "private-canary")?;
    verify_snapshot(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn e3_direct_transport_retirement() -> Result<(), StorageError> {
    transport(false, false, false)
}
#[test]
fn e3_hold_child_retires_referenced_transport_parent() -> Result<(), StorageError> {
    transport(true, false, false)
}
#[test]
fn e3_two_hop_ancestor_chain() -> Result<(), StorageError> {
    transport(false, true, false)
}
#[test]
fn e3_message_seeded_chain() -> Result<(), StorageError> {
    transport(false, false, true)
}
