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
    // Inject historical enrollment for an independent witness that cannot be
    // created by revoking an already existing placeholder.
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

fn legacy_source(db: &AccountDb) -> Result<(), StorageError> {
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
    Ok(())
}

pub(super) fn fixture(db: &AccountDb) -> Result<(), StorageError> {
    legacy_source(db)?;
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    count_payload_work(db)
}

fn count_payload_work(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.execute_batch("CREATE TEMP TABLE legacy_work_count(n INTEGER); INSERT INTO legacy_work_count VALUES(0); CREATE TEMP TRIGGER legacy_count AFTER INSERT ON main.object_erasure_work BEGIN UPDATE legacy_work_count SET n=n+1; END;")?;
    Ok(())
}

fn no_payload_work(db: &AccountDb) -> Result<(), StorageError> {
    for table in [
        "object_retention_payload",
        "object_retention_reference",
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
fn e19_message_deleted_before_discovery() -> Result<(), StorageError> {
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
fn e19_message_deleted_after_discovery_without_managed_owner() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("legacy-after-discovery")?;
    legacy_source(&db)?;
    // Historical attachment metadata may arrive before its DM projection.
    // Remove only that projection, without invoking message-death cleanup.
    db.connection
        .execute("DELETE FROM direct_message_projection WHERE message_id='message'", [])?;
    db.connection
        .execute("UPDATE object_retention_upgrade SET phase=1,cursor=0 WHERE singleton=1", [])?;
    db.maintain_object_retention()?;
    let discovery: (i64, i64) = db.connection.query_row(
        "SELECT phase,unsafe_references FROM object_retention_upgrade WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(discovery, (5, 1), "discovery must finish and skip the ownerless candidate");
    no_payload_work(&db)?;
    db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("revoke"), 1)?;
    assert!(db.object_is_tombstoned("private-canary")?);
    count_payload_work(&db)?;
    no_payload_work(&db)?;
    let generation = db.privacy_erasure_generation()?;
    db.import_deleted_message_projection("thread", "message", false, 1)?;
    assert_eq!(db.privacy_erasure_generation()?, generation + 1);
    let work: i64 =
        db.connection.query_row("SELECT n FROM legacy_work_count", [], |row| row.get(0))?;
    assert_eq!(work, 0, "payload work must not mask the legacy-only generation bump");
    no_payload_work(&db)?;
    db.import_deleted_message_projection("thread", "message", false, 1)?;
    assert_eq!(db.privacy_erasure_generation()?, generation + 1);
    drop(db);
    let db = reopen(&root)?;
    erased(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn e19_later_discovery_page_cannot_resurrect() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("legacy-later-discovery")?;
    fixture(&db)?;
    let reference = db
        .load_actor_state::<serde_json::Value>("attachment/reference/private-canary")?
        .ok_or(StorageError::AuthorizationRejected)?;
    let directory =
        db.client_record("object", "private-canary")?.ok_or(StorageError::AuthorizationRejected)?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    drop(db);
    let db = reopen(&root)?;
    erased(&db, &root)?;
    // A later archive page still contains the old bytes. Discovery must leave
    // the retired selector closed and create no payload, reference or owner.
    db.connection.execute_batch("CREATE TABLE IF NOT EXISTS backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind));")?;
    for (key, value) in [
        ("directory/object/private-canary", directory),
        ("attachment/reference/private-canary", reference),
    ] {
        db.connection.execute(
            "INSERT INTO backup_archived_actor_state VALUES('late',?1,?2)",
            params![key, serde_json::to_vec(&value)?],
        )?;
    }
    db.connection
        .execute("UPDATE object_retention_upgrade SET phase=1,cursor=0 WHERE singleton=1", [])?;
    db.maintain_object_retention()?;
    let phase: i64 = db.connection.query_row(
        "SELECT phase FROM object_retention_upgrade WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(phase, 5);
    no_payload_work(&db)?;
    assert!(!db.object_is_tombstoned("private-canary")?);
    assert!(matches!(db.check_object_access("private-canary"), Err(StorageError::ObjectErased)));
    let bindings: i64 = db.connection.query_row(
        "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:private-canary'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(bindings, 0);
    drop(db);
    let db = reopen(&root)?;
    no_payload_work(&db)?;
    assert!(matches!(db.check_object_access("private-canary"), Err(StorageError::ObjectErased)));
    assert!(!db.object_is_tombstoned("private-canary")?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn e19_independent_same_selector_witness_survives_until_its_own_deletion()
-> Result<(), StorageError> {
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
fn e19_legacy_delete_cut_before_commit() -> Result<(), StorageError> {
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
            }))?;
            Ok(())
        })?;
        db.delete_direct_message("thread", "message", "local", "delete")?;
        return Err(StorageError::AuthorizationRejected);
    }
    let (root, db) = crate::tests::test_db("legacy-driver-abort")?;
    fixture(&db)?;
    drop(db);
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact","account_db::object_retention::selector_legacy_tests::e19_legacy_delete_cut_before_commit","--nocapture"])
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
    let bindings: i64 = db.connection.query_row(
        "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:private-canary' AND message_id='message'",
        [], |row| row.get(0),
    )?;
    assert_eq!(bindings, 1, "pre-COMMIT abort must preserve the binding");
    let lookups: i64 =
        db.connection
            .query_row("SELECT COUNT(*) FROM object_erasure_lookup", [], |row| row.get(0))?;
    assert_eq!(lookups, 0);
    no_payload_work(&db)?;
    db.delete_direct_message("thread", "message", "local", "retry")?;
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(db.privacy_erasure_generation()?, 1);
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

fn managed_deletion_with_legacy_survivor(
    retire_payload: bool,
    zero_manifest: bool,
    reverse_triggers: bool,
) -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("managed-legacy-survivor")?;
    fixture(&db)?;
    db.send_direct_message("thread", "managed", "peer", b"body")?;
    db.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: "managed-reference",
            wire_id: "wire",
            manifest_hash: "manifest",
            selector: "private-canary",
            message_id: "managed",
            reference: &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
            metadata: &json!({"message_id":"managed"}),
        },
    )?;
    for key in
        ["attachment/reference/private-canary", "attachment/reference-by-slot/private-canary"]
    {
        db.register_object_reference_actor("managed-reference", key)?;
    }
    if !retire_payload {
        super::tests::install(&db, "wire-owner", "wire-reference")?;
    }
    if zero_manifest {
        // Inject the touched v12 row shape; upgrade itself has separate witnesses.
        db.connection.execute("UPDATE object_index SET manifest_hash=zeroblob(32),chunk_manifest_hash=zeroblob(32) WHERE object_id='private-canary'", [])?;
    }
    if reverse_triggers {
        // Recreate the footprint trigger last to exercise the opposite SQLite
        // AFTER-trigger order without changing either production trigger body.
        db.connection.call(|raw| {
            let sql: String = raw.query_row(
                "SELECT sql FROM sqlite_master WHERE name='footprint_erase_message'",
                [],
                |r| r.get(0),
            )?;
            raw.execute_batch("DROP TRIGGER footprint_erase_message;")?;
            raw.execute_batch(&sql)
        })?;
    }
    db.delete_direct_message("thread", "managed", "local", "delete-managed")?;
    if retire_payload {
        // The fence dominates even the still-live legacy message. Its private
        // enrollment must disappear together with the fenced selector graph.
        drop(db);
        let db = reopen(&root)?;
        erased(&db, &root)?;
        db.delete_direct_message("thread", "message", "local", "delete-legacy")?;
        drop(db);
        std::fs::remove_dir_all(root)?;
        return Ok(());
    }
    assert!(db.object_is_tombstoned("private-canary")?);
    let manifest: Vec<u8> = db.connection.query_row(
        "SELECT manifest_hash FROM object_index WHERE object_id='private-canary'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(manifest, b"manifest");
    for key in [
        "attachment/reference/private-canary",
        "directory/object/private-canary",
        "attachment/reference-by-slot/private-canary",
    ] {
        assert!(db.actor_state_exists(key)?, "legacy actor lost: {key}");
    }
    let bindings: i64 = db.connection.query_row("SELECT count(*) FROM message_copy_binding WHERE copy_id='object:private-canary' AND message_id='message'", [], |r| r.get(0))?;
    assert_eq!(bindings, 1);
    let lookups: i64 = db.connection.query_row(
        "SELECT count(*) FROM object_erasure_lookup WHERE lookup=?1",
        params![object_erasure_lookup(db.object_erasure_root(), "private-canary")],
        |r| r.get(0),
    )?;
    assert_eq!(lookups, 0, "live legacy selector must not acquire a lookup");
    drop(db);
    let db = reopen(&root)?;
    db.check_object_access("private-canary")?;
    assert!(db.object_is_tombstoned("private-canary")?);
    db.delete_direct_message("thread", "message", "local", "delete-legacy")?;
    if !retire_payload {
        db.delete_direct_message("thread", "wire-owner", "local", "delete-wire")?;
    }
    drop(db);
    let db = reopen(&root)?;
    erased(&db, &root)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn managed_retirement_preserves_enrolled_legacy_survivor() -> Result<(), StorageError> {
    managed_deletion_with_legacy_survivor(false, false, false)
}

#[test]
fn payload_fence_retires_enrolled_legacy_witness() -> Result<(), StorageError> {
    managed_deletion_with_legacy_survivor(true, false, false)
}

#[test]
fn managed_retirement_normalizes_zero_manifest_from_legacy_survivor() -> Result<(), StorageError> {
    managed_deletion_with_legacy_survivor(false, true, false)
}

#[test]
fn managed_retirement_legacy_survivor_is_trigger_order_independent() -> Result<(), StorageError> {
    managed_deletion_with_legacy_survivor(false, false, true)
}

#[test]
fn e19_live_legacy_revoke_enrolls_binding_and_footprint() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("legacy-enrollment")?;
    fixture(&db)?;
    drop(db);
    let db = reopen(&root)?;
    let footprints: Vec<String> = db.connection.prepare(
        "SELECT locator FROM message_footprint WHERE message_id='message' AND kind='revocation_selector'",
    )?.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
    assert_eq!(
        footprints,
        vec![locator(&db)],
        "canonical footprint must use actor identity, not revoke envelope"
    );
    let binding: i64 = db.connection.query_row(
        "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:private-canary' AND message_id='message'", [], |row| row.get(0),
    )?;
    assert_eq!(binding, 1);
    for key in [
        "attachment/reference/private-canary",
        "directory/object/private-canary",
        "attachment/reference-by-slot/private-canary",
    ] {
        let count: i64 = db.connection.query_row(
            "SELECT count(*) FROM message_footprint WHERE message_id='message' AND kind='actor' AND locator=?1", params![key], |row| row.get(0),
        )?;
        assert_eq!(count, 1, "missing actor enrollment: {key}");
    }
    no_payload_work(&db)?;
    assert!(db.object_is_tombstoned("private-canary")?);
    db.upsert_object(&crate::ObjectWrite {
        object_id: "private-canary",
        manifest_hash: "manifest",
        nonce: "nonce",
        ciphertext: b"late",
        plaintext_hash: "hash",
        tombstoned: false,
        backup_excluded: false,
        content_key: None,
        object: &json!({}),
        updated_at: 2,
    })?;
    assert!(db.object_is_tombstoned("private-canary")?);
    let ciphertext: Vec<u8> = db.connection.query_row(
        "SELECT ciphertext FROM object_index WHERE object_id='private-canary'",
        [],
        |row| row.get(0),
    )?;
    assert!(ciphertext.is_empty(), "late import must not replace the placeholder");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn e19_enrollment_failure_rolls_back_creation() -> Result<(), StorageError> {
    for placeholder_first in [false, true] {
        let (root, db) = crate::tests::test_db("legacy-enrollment-rollback")?;
        legacy_source(&db)?;
        // Remove the pre-existing trigger enrollment so every row under test is
        // newly written in the creation transaction and must roll back.
        db.connection
            .execute_batch("DELETE FROM message_copy_binding; DELETE FROM message_footprint;")?;
        if placeholder_first {
            db.connection.execute_batch("CREATE TEMP TRIGGER enrollment_cut BEFORE INSERT ON main.message_footprint WHEN NEW.kind='revocation_selector' AND EXISTS(SELECT 1 FROM object_index) BEGIN SELECT RAISE(ABORT,'placeholder then enrollment cut'); END;")?;
            // Exercise the inverse statement order with the same production
            // resolver/enrollment and placeholder schema in one writer transaction.
            let result: Result<(), StorageError> = db.write_transaction(|| {
                db.connection.execute("INSERT INTO object_index(object_id,chunk_manifest_hash,object_state,total_cipher_size,chunk_count,created_at,updated_at,manifest_hash,nonce,ciphertext,tombstoned,backup_excluded,object_body) VALUES('private-canary',x'01','tombstoned',0,0,1,1,x'01',zeroblob(12),x'',1,0,x'7b7d')", [])?;
                let record = db.client_record("object", "private-canary")?;
                db.resolve_revocation_manifest("private-canary", Some("peer"), record.as_ref())?;
                Ok(())
            });
            assert!(
                matches!(result, Err(error) if error.to_string().contains("placeholder then enrollment cut"))
            );
        } else {
            db.connection.execute_batch("CREATE TEMP TRIGGER enrollment_cut BEFORE INSERT ON main.object_index WHEN EXISTS(SELECT 1 FROM message_footprint WHERE kind='revocation_selector') BEGIN SELECT RAISE(ABORT,'enrollment then placeholder cut'); END;")?;
            let result = db.set_object_tombstoned_with_revocation(
                "private-canary",
                Some("peer"),
                Some("revoke"),
                1,
            );
            assert!(
                matches!(result, Err(error) if error.to_string().contains("enrollment then placeholder cut"))
            );
        }
        drop(db);
        let db = reopen(&root)?;
        for table in
            ["object_index", "message_copy_binding", "message_footprint", "object_erasure_lookup"]
        {
            let count: i64 =
                db.connection
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))?;
            assert_eq!(
                count, 0,
                "rollback retained {table}, placeholder_first={placeholder_first}"
            );
        }
        assert!(!db.object_is_tombstoned("private-canary")?);
        db.check_object_access("private-canary")?;
        // A healthy retry commits the entire creation after the TEMP cut vanishes.
        db.set_object_tombstoned_with_revocation("private-canary", Some("peer"), Some("retry"), 2)?;
        assert!(db.object_is_tombstoned("private-canary")?);
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn e19_missing_message_id_or_conflicting_manifest_refused() -> Result<(), StorageError> {
    for record in [
        json!({"owner":"peer","manifest_hash":"manifest"}),
        json!({"owner":"peer","message_id":123,"manifest_hash":"manifest"}),
        json!({"owner":"peer","message_id":"message","manifest_hash":"conflict"}),
        json!({"owner":"other","message_id":"message","manifest_hash":"manifest"}),
    ] {
        let (root, db) = crate::tests::test_db("legacy-enrollment-refused")?;
        legacy_source(&db)?;
        db.persist_client_record("object", "private-canary", &record)?;
        assert!(matches!(
            db.set_object_tombstoned_with_revocation(
                "private-canary",
                Some("peer"),
                Some("revoke"),
                1
            ),
            Err(StorageError::AuthorizationRejected)
        ));
        drop(db);
        let db = reopen(&root)?;
        assert!(!db.object_is_tombstoned("private-canary")?);
        let count: i64 = db.connection.query_row(
            "SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0);
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn e19_known_deleted_owner_or_fence_refuses() -> Result<(), StorageError> {
    for fenced in [false, true] {
        let (root, db) = crate::tests::test_db("legacy-enrollment-dead")?;
        if !fenced {
            db.send_direct_message("thread", "message", "peer", b"body")?;
            db.delete_direct_message("thread", "message", "local", "delete")?;
        }
        // Historical actor bytes bypass admission: the creation guard itself
        // must refuse a known deleted owner or consume an existing payload fence.
        for (key, value) in [
            (
                "attachment/reference/private-canary",
                json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
            ),
            (
                "directory/object/private-canary",
                json!({"owner":"peer","message_id":"message","manifest_hash":"manifest"}),
            ),
        ] {
            db.connection.execute(
                "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
                params![key, serde_json::to_vec(&value)?],
            )?;
        }
        assert!(db.actor_state_exists("attachment/reference/private-canary")?);
        assert!(db.client_record("object", "private-canary")?.is_some());
        assert_eq!(db.message_is_deleted("message")?, !fenced);
        if fenced {
            db.connection.execute(
                "INSERT INTO object_erasure_fence VALUES(?1)",
                params![object_erasure_commitment(db.object_erasure_root(), "wire", "manifest")],
            )?;
        }
        let result = db.set_object_tombstoned_with_revocation(
            "private-canary",
            Some("peer"),
            Some("revoke"),
            1,
        );
        if fenced {
            // This legacy actor has no admitted retention identity, so G2
            // resolves the fence and refuses before enrollment or insertion.
            assert!(matches!(result, Err(StorageError::ObjectErased)));
        } else {
            assert!(matches!(result, Err(StorageError::AuthorizationRejected)));
        }
        drop(db);
        let db = reopen(&root)?;
        assert!(!db.object_is_tombstoned("private-canary")?);
        let count: i64 = db.connection.query_row(
            "SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0);
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
