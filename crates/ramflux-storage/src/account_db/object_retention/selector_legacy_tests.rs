// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy footprint retirement independent of retention discovery and work rows.
use super::*;
use serde_json::json;

fn locator(db: &AccountDb) -> String {
    json!({
        "selector":"private-canary","wire":"wire","manifest":"manifest",
        "commitment":object_erasure_commitment(db.object_erasure_root(),"wire","manifest"),
        "selector_lookup":object_erasure_lookup(db.object_erasure_root(),"private-canary"),
    })
    .to_string()
}

fn enroll_fixture(db: &AccountDb, message: &str) -> Result<(), StorageError> {
    // Inject the future G2 enrollment output, not a retention owner. Production
    // enrollment is a separate admission change; this fixture isolates the driver.
    db.connection.execute("INSERT INTO message_copy_binding VALUES('object:private-canary',?1) ON CONFLICT DO NOTHING",params![message])?;
    db.connection.execute(
        "INSERT INTO message_footprint VALUES(?1,'revocation_selector',?2)",
        params![message, locator(db)],
    )?;
    for key in [
        "attachment/reference/private-canary",
        "directory/object/private-canary",
        "attachment/reference-by-slot/private-canary",
    ] {
        db.connection.execute(
            "INSERT INTO message_footprint VALUES(?1,'actor',?2) ON CONFLICT DO NOTHING",
            params![message, key],
        )?;
    }
    Ok(())
}

pub(super) fn fixture(db: &AccountDb) -> Result<(), StorageError> {
    db.send_direct_message("thread", "message", "peer", b"body")?;
    db.persist_actor_state(
        "attachment/reference/private-canary",
        &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
    )?;
    db.persist_client_record(
        "object",
        "private-canary",
        &json!({"owner":"peer","message_id":"message","manifest_hash":"manifest"}),
    )?;
    db.persist_actor_state(
        "attachment/reference-by-slot/private-canary",
        &json!("private-canary"),
    )?;
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    enroll_fixture(db, "message")?;
    db.connection.execute_batch("CREATE TEMP TABLE legacy_work_count(n INTEGER); INSERT INTO legacy_work_count VALUES(0); CREATE TEMP TRIGGER legacy_count AFTER INSERT ON main.object_erasure_work BEGIN UPDATE legacy_work_count SET n=n+1; END;")?;
    Ok(())
}

fn no_payload_work(db: &AccountDb) -> Result<(), StorageError> {
    for table in [
        "object_retention_payload",
        "object_message_reference",
        "object_erasure_work",
        "object_reference_erasure_work",
        "object_projection_erasure_work",
    ] {
        let count: i64 =
            db.connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))?;
        assert_eq!(count, 0, "unexpected {table}");
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

fn erased(db: &AccountDb, root: &std::path::Path) -> Result<(), StorageError> {
    no_payload_work(db)?;
    assert!(matches!(db.check_object_access("private-canary"), Err(StorageError::ObjectErased)));
    assert!(!db.object_is_tombstoned("private-canary")?);
    let lookup: i64 = db.connection.query_row(
        "SELECT COUNT(*) FROM object_erasure_lookup WHERE lookup=?1 AND commitment=?2",
        params![
            object_erasure_lookup(db.object_erasure_root(), "private-canary"),
            object_erasure_commitment(db.object_erasure_root(), "wire", "manifest")
        ],
        |row| row.get(0),
    )?;
    assert_eq!(lookup, 1);
    db.checkpoint_retired_secrets()?;
    super::tests::assert_erasure_canary_absent(db)?;
    let path = root.join("legacy-snapshot.db");
    let snapshot = db.write_backup_snapshot(&path)?;
    let sql = rusqlite::Connection::open(path)?;
    sql.execute_batch(&format!("PRAGMA key=\"x'{}'\";", snapshot.key.sqlcipher_hex()))?;
    super::tests::assert_erasure_canary_absent_sql(&sql)?;
    Ok(())
}

#[test]
fn legacy_footprint_driver_deletes_without_retention_work() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("legacy-driver")?;
    fixture(&db)?;
    no_payload_work(&db)?;
    let generation = db.privacy_erasure_generation()?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    assert_eq!(db.privacy_erasure_generation()?, generation + 1);
    let work: i64 =
        db.connection.query_row("SELECT n FROM legacy_work_count", [], |row| row.get(0))?;
    assert_eq!(work, 0, "payload work must not mask the legacy-only generation bump");
    // Re-firing a deletion cannot advance generation once its locator is drained.
    db.connection
        .execute("UPDATE direct_message_projection SET deleted=1 WHERE message_id='message'", [])?;
    assert_eq!(db.privacy_erasure_generation()?, generation + 1);
    drop(db);
    let db = reopen(&root)?;
    erased(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn legacy_footprint_driver_preserves_independent_witness() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("legacy-survivor")?;
    fixture(&db)?;
    db.send_direct_message("thread", "other", "peer", b"body")?;
    enroll_fixture(&db, "other")?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    assert!(db.object_is_tombstoned("private-canary")?);
    assert_eq!(db.privacy_erasure_generation()?, 0);
    assert!(db.actor_state_exists("attachment/reference/private-canary")?);
    drop(db);
    let db = reopen(&root)?;
    db.check_object_access("private-canary")?;
    db.delete_direct_message("thread", "other", "local", "delete-other")?;
    assert_eq!(db.privacy_erasure_generation()?, 1);
    drop(db);
    let db = reopen(&root)?;
    erased(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn legacy_footprint_driver_before_commit_failure_rolls_back() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("legacy-driver-rollback")?;
    fixture(&db)?;
    db.connection.execute_batch("CREATE TRIGGER legacy_delete_cut BEFORE DELETE ON message_footprint WHEN OLD.kind='revocation_selector' BEGIN SELECT RAISE(ABORT,'legacy delete before commit'); END;")?;
    assert!(db.delete_direct_message("thread", "message", "local", "delete").is_err());
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(db.privacy_erasure_generation()?, 0);
    assert!(db.object_is_tombstoned("private-canary")?);
    assert!(db.actor_state_exists("attachment/reference/private-canary")?);
    let count: i64 = db.connection.query_row(
        "SELECT COUNT(*) FROM message_footprint WHERE kind='revocation_selector' AND locator=?1",
        params![locator(&db)],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    let lookups: i64 =
        db.connection
            .query_row("SELECT COUNT(*) FROM object_erasure_lookup", [], |row| row.get(0))?;
    assert_eq!(lookups, 0);
    no_payload_work(&db)?;
    db.connection.execute_batch("DROP TRIGGER legacy_delete_cut;")?;
    db.delete_direct_message("thread", "message", "local", "retry")?;
    drop(db);
    let db = reopen(&root)?;
    erased(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn legacy_footprint_driver_child_abort_rolls_back() -> Result<(), StorageError> {
    const CHILD_ROOT: &str = "RAMFLUX_TEST_LEGACY_FOOTPRINT_ABORT_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let root = std::path::PathBuf::from(root);
        let db = reopen(&root)?;
        let marker = root.join("legacy-cut-reached");
        db.connection.call(move |raw| {
            raw.update_hook(Some(move |action, _database: &str, table: &str, _row| {
                if action == rusqlite::hooks::Action::SQLITE_DELETE
                    && table == "message_copy_binding"
                {
                    assert!(std::fs::write(&marker, b"legacy cleanup reached").is_ok());
                    std::process::abort();
                }
            }));
            Ok(())
        })?;
        db.delete_direct_message("thread", "message", "local", "delete")?;
        return Err(StorageError::AuthorizationRejected);
    }
    let (root, db) = crate::tests::test_db("legacy-driver-abort")?;
    fixture(&db)?;
    drop(db);
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact","account_db::object_retention::selector_legacy_tests::legacy_footprint_driver_child_abort_rolls_back","--nocapture"])
        .env(CHILD_ROOT,&root).status()?;
    assert!(!status.success());
    assert_eq!(std::fs::read(root.join("legacy-cut-reached"))?, b"legacy cleanup reached");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(status.signal(), Some(6));
    }
    let db = reopen(&root)?;
    assert_eq!(db.privacy_erasure_generation()?, 0);
    assert!(db.object_is_tombstoned("private-canary")?);
    assert!(db.actor_state_exists("attachment/reference/private-canary")?);
    let footprints:i64=db.connection.query_row("SELECT COUNT(*) FROM message_footprint WHERE message_id='message' AND kind='revocation_selector'",[],|row|row.get(0))?;
    assert_eq!(footprints, 1);
    let lookups: i64 =
        db.connection
            .query_row("SELECT COUNT(*) FROM object_erasure_lookup", [], |row| row.get(0))?;
    assert_eq!(lookups, 0);
    no_payload_work(&db)?;
    db.delete_direct_message("thread", "message", "local", "retry")?;
    drop(db);
    let db = reopen(&root)?;
    erased(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn legacy_footprint_driver_preserves_managed_survivor() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("legacy-managed-survivor")?;
    fixture(&db)?;
    db.send_direct_message("thread", "other", "peer", b"body")?;
    db.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: "managed-reference",
            wire_id: "wire",
            manifest_hash: "manifest",
            selector: "private-canary",
            message_id: "other",
            reference: &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
            metadata: &json!({"message_id":"other"}),
        },
    )?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    assert!(db.object_is_tombstoned("private-canary")?);
    db.check_object_access("private-canary")?;
    assert_eq!(db.privacy_erasure_generation()?, 0);
    drop(db);
    let db = reopen(&root)?;
    assert!(db.object_is_tombstoned("private-canary")?);
    db.delete_direct_message("thread", "other", "local", "delete-other")?;
    drop(db);
    let db = reopen(&root)?;
    erased(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
