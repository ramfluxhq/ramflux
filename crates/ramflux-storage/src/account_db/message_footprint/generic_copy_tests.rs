// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T11 generic absence across active/archive/restore and history-container any-owner invalidation.
use super::*;
use crate::{
    AccountDbKey, AccountIndex, BackupDatabase, ObjectReferenceAdmission, ObjectReferenceOwner,
    ObjectWrite,
};
use rusqlite::params;
use serde_json::json;

const SECRETS: [&str; 6] = [
    "actor-secret-body",
    "nested-raw-secret",
    "journal-event-secret",
    "operation-preview-secret",
    "prepared-envelope-secret",
    "history-page-secret",
];

fn secrets() -> Vec<String> {
    SECRETS.iter().map(|secret| (*secret).to_owned()).collect()
}

fn seed_registered_copies(db: &AccountDb) -> Result<(), StorageError> {
    db.send_direct_message("thread", "projection-id", "peer", b"private-content")?;
    db.persist_message_actor_state(
        "projection-id",
        "own-copy/nested-raw/n1",
        &json!({"message_id":"projection-id","nested_raw":"nested-raw-secret"}),
    )?;
    db.persist_message_actor_state(
        "projection-id",
        "own-copy/actor/seed",
        &json!({"message_id":"projection-id","body":"actor-secret-body"}),
    )?;
    db.append_journal(
        "journal-projection",
        "message.event",
        &json!({"message_id":"projection-id","body":"journal-event-secret"}),
        1,
        None,
    )?;
    db.reserve_operation("op-projection", "fp")?;
    db.complete_operation(
        "op-projection",
        &json!({"message_id":"projection-id","preview":"operation-preview-secret"}),
    )?;
    db.write_transaction(|| {
        db.put_prepared_message_copy(
            "projection-id",
            "copy-1",
            &json!({"message_id":"projection-id","payload":"prepared-envelope-secret"}),
        )?;
        db.put_history_container(
            "xfer-1",
            0,
            &["projection-id"],
            &json!({"body":"history-page-secret"}),
        )?;
        Ok::<(), StorageError>(())
    })?;
    archive_live_copies(db)
}

fn archive_live_copies(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.call(|raw| {
        super::ensure_archive_actor_table(raw)?;
        raw.execute_batch(
            "INSERT OR IGNORE INTO backup_archived_actor_state
             SELECT 'archive',state_kind,state_json FROM runtime_actor_state
             WHERE state_kind GLOB 'own-copy/*' OR state_kind GLOB 'own-device/history-container/*';",
        )?;
        Ok(())
    })?;
    Ok(())
}

fn assert_generic_absence(
    db: &AccountDb,
    message: &str,
    forbidden: &[String],
) -> Result<(), StorageError> {
    db.checkpoint_retired_secrets()?;
    let forbidden = forbidden.to_vec();
    let message = message.to_owned();
    db.connection.call(move |raw| scan_tables(raw, &message, &forbidden))?;
    Ok(())
}

fn scan_tables(
    raw: &rusqlite::Connection,
    message: &str,
    forbidden: &[String],
) -> rusqlite::Result<()> {
    let mut query = raw.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let tables = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(query);
    for table in tables {
        scan_table(raw, &table, forbidden)?;
    }
    let leftover: i64 = raw.query_row(
        "SELECT count(*) FROM message_footprint WHERE message_id=?1",
        params![message],
        |row| row.get(0),
    )?;
    assert_eq!(leftover, 0, "footprint rows survived for {message}");
    Ok(())
}

fn scan_table(
    raw: &rusqlite::Connection,
    table: &str,
    forbidden: &[String],
) -> rusqlite::Result<()> {
    let quoted = table.replace('"', "\"\"");
    let mut rows = raw.prepare(&format!("SELECT * FROM \"{quoted}\""))?;
    let names = rows.column_names().iter().map(ToString::to_string).collect::<Vec<_>>();
    let values = rows
        .query_map([], |row| {
            (0..names.len())
                .map(|i| match row.get_ref(i)? {
                    rusqlite::types::ValueRef::Text(bytes)
                    | rusqlite::types::ValueRef::Blob(bytes) => {
                        Ok(String::from_utf8_lossy(bytes).into_owned())
                    }
                    _ => Ok(String::new()),
                })
                .collect::<rusqlite::Result<Vec<_>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for row in values {
        for (name, value) in names.iter().zip(&row) {
            for secret in forbidden {
                assert!(
                    !value.contains(secret),
                    "residual in {table}.{name}: {secret}; row={row:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn raw_inner_generic_absence_across_active_archive_and_restore() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("p11-generic-absence")?;
    seed_registered_copies(&db)?;
    let content = root.join("content.db");
    let content_snap = db.write_backup_snapshot(&content)?;
    db.retire_outbound_for_recovery("p11-head")?;
    db.delete_direct_message("thread", "projection-id", "local", "delete")?;
    let forbidden = secrets();
    assert_generic_absence(&db, "projection-id", &forbidden)?;
    drop(db);
    let db = AccountDb::open(
        &AccountIndex::open(&root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    assert_generic_absence(&db, "projection-id", &forbidden)?;
    let erased = root.join("erased.db");
    let erased_snap = db.write_backup_snapshot(&erased)?;
    let mut merged = BackupDatabase::open(&erased, &erased_snap.key)?;
    merged.merge_backup(&content, &content_snap.key, || Ok(()))?;
    merged.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    scan_tables(&merged.db, "projection-id", &forbidden)?;
    drop(merged);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn omitting_prepared_copy_registration_is_detected_as_an_erasure_residual()
-> Result<(), StorageError> {
    const MUTATION: &str = "RAMFLUX_TEST_DROP_PREPARED_COPY_REGISTRATION";
    if std::env::var_os(MUTATION).is_none() {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "account_db::message_footprint::generic_copy_tests::omitting_prepared_copy_registration_is_detected_as_an_erasure_residual",
                "--nocapture",
            ])
            .env(MUTATION, "1")
            .status()?;
        assert!(!status.success(), "the erasure audit accepted a missing prepared registration");
        return Ok(());
    }
    let (root, db) = crate::tests::test_db("p11-prepared-registration-mutation")?;
    db.send_direct_message("thread", "projection-id", "peer", b"private-content")?;
    db.write_transaction(|| {
        db.put_prepared_message_copy(
            "projection-id",
            "copy-1",
            &json!({"message_id":"projection-id","payload":"prepared-envelope-secret"}),
        )
    })?;
    db.delete_direct_message("thread", "projection-id", "local", "delete")?;
    let audit = assert_generic_absence(&db, "projection-id", &["prepared-envelope-secret".into()]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    audit?;
    Ok(())
}

fn register_shared_object(db: &AccountDb, message: &str) -> Result<(), StorageError> {
    let reference =
        json!({"object_id":"shared-wire","manifest_hash":"manifest","slot":"shared-alias"});
    db.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: message,
            wire_id: "shared-wire",
            manifest_hash: "manifest",
            selector: "shared-alias",
            message_id: message,
            reference: &reference,
            metadata: &json!({"message_id":message}),
        },
    )?;
    Ok(())
}

#[test]
fn history_container_any_owner_invalidates_without_erasing_shared_object()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("p11-history-any-owner")?;
    db.create_group("group", "peer")?;
    for message in ["m1", "m2"] {
        db.send_direct_message("thread", message, "peer", b"private-content")?;
        register_shared_object(&db, message)?;
    }
    db.upsert_object(&ObjectWrite {
        object_id: "shared-wire",
        manifest_hash: "manifest",
        nonce: "n",
        ciphertext: b"shared-object-payload",
        plaintext_hash: "plain",
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&[7; 32]),
        object: &json!({}),
        updated_at: 1,
    })?;
    db.write_transaction(|| {
        db.put_history_container(
            "xfer-shared",
            0,
            &["m1", "m2"],
            &json!({"body":"history-page-secret"}),
        )
    })?;
    db.delete_direct_message("thread", "m1", "local", "delete-m1")?;
    assert!(db.load_history_container::<Value>("xfer-shared", 0)?.is_none());
    assert!(!db.message_is_deleted("m2")?);
    let payload: i64 = db.connection.query_row(
        "SELECT length(ciphertext) FROM object_index WHERE object_id='shared-wire'",
        [],
        |row| row.get(0),
    )?;
    assert!(payload > 0, "shared object last-owner payload was erased");
    let owners: i64 = db.connection.query_row(
        "SELECT count(*) FROM object_message_reference WHERE reference_hash IN ('m1','m2')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(owners, 1);
    let groups: i64 = db.connection.query_row(
        "SELECT count(*) FROM group_projection WHERE group_id='group'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(groups, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
