// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T11 generic absence across active/archive/restore and history-container any-owner invalidation.
use super::generic_copy::collect_message_ids;
use super::*;
use crate::{
    AccountDbKey, AccountIndex, BackupDatabase, BackupIndexInstall, ObjectReferenceAdmission,
    ObjectReferenceOwner, ObjectWrite, WrappedAccountDbKey,
};
use rusqlite::params;
use serde_json::json;
use std::collections::BTreeSet;
use std::path::Path;

const SECRETS: [&str; 9] = [
    "actor-secret-body",
    "nested-raw-secret",
    "journal-event-secret",
    "operation-preview-secret",
    "prepared-envelope-secret",
    "history-page-secret",
    "raw-inner-copy-secret",
    "raw-evidence-secret",
    "raw-opening-secret",
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
    db.reserve_operation("op-projection", "fp", "")?;
    db.complete_operation(
        "op-projection",
        &json!({"message_id":"projection-id","preview":"operation-preview-secret"}),
    )?;
    db.write_transaction(|| {
        db.put_prepared_message_copy(
            "projection-id",
            "copy-1",
            &json!({"payload":"prepared-envelope-secret"}),
        )?;
        db.put_history_container(
            "xfer-1",
            0,
            &["projection-id"],
            &json!({"body":"history-page-secret"}),
        )?;
        db.put_unsupported_raw_copy(super::super::raw_inner::RawInnerCopyWrite {
            owner_id: "projection-id",
            verified_source_anchor: "verified-root",
            copy_id: "raw-copy-1",
            kind: super::super::raw_inner::RawInnerCopyKind::NestedGroup,
            bytes: b"raw-inner-copy-secret",
            bounded_metadata: b"{}",
        })?;
        db.put_known_content_evidence(
            "projection-id",
            "thread",
            b"private-content",
            b"raw-evidence-secret",
            b"raw-opening-secret",
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
    census_raw_inner(raw, message)?;
    Ok(())
}

fn census_raw_inner(raw: &rusqlite::Connection, message: &str) -> rusqlite::Result<()> {
    let copies: i64 = raw.query_row(
        "SELECT count(*) FROM raw_inner_copy WHERE owner_id=?1",
        params![message],
        |row| row.get(0),
    )?;
    assert_eq!(copies, 0, "raw_inner_copy still holds {message}");
    let owners: i64 = raw.query_row(
        "SELECT count(*) FROM raw_inner_owner WHERE owner_id=?1",
        params![message],
        |row| row.get(0),
    )?;
    assert_eq!(owners, 0, "raw_inner_owner still holds {message}");
    let evidence: i64 = raw.query_row(
        "SELECT count(*) FROM raw_inner_evidence WHERE message_id=?1",
        params![message],
        |row| row.get(0),
    )?;
    assert_eq!(evidence, 0, "raw_inner_evidence still holds {message}");
    let bindings: i64 = raw.query_row(
        "SELECT count(*) FROM message_copy_binding WHERE message_id=?1 AND copy_id GLOB 'raw:*'",
        params![message],
        |row| row.get(0),
    )?;
    assert_eq!(bindings, 0, "raw_inner marker binding still holds {message}");
    let footprints: i64 = raw.query_row(
        "SELECT count(*) FROM message_footprint
         WHERE message_id=?1 AND kind IN ('raw_inner','raw_inner_evidence')",
        params![message],
        |row| row.get(0),
    )?;
    assert_eq!(footprints, 0, "raw_inner footprint still holds {message}");
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
#[allow(clippy::too_many_lines)]
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
    let archived = BackupDatabase::open(&erased, &erased_snap.key)?;
    census_raw_inner(&archived.db, "projection-id")?;
    drop(archived);
    let mut merged = BackupDatabase::open(&erased, &erased_snap.key)?;
    merged.merge_backup(&content, &content_snap.key, || Ok(()))?;
    merged.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    scan_tables(&merged.db, "projection-id", &forbidden)?;
    drop(merged);
    drop(db);
    let source = BackupDatabase::open(&content, &content_snap.key)?;
    let restored = install_pre_erase_snapshot(&root.join("fresh"), &source)?;
    drop(source);
    restored.delete_direct_message("thread", "projection-id", "local", "delete")?;
    assert_generic_absence(&restored, "projection-id", &forbidden)?;
    drop(restored);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn install_pre_erase_snapshot(
    root: &Path,
    source: &BackupDatabase,
) -> Result<AccountDb, StorageError> {
    let index = AccountIndex::open(root)?;
    let path = "accounts/acct/generation-restored/account.db";
    std::fs::create_dir_all(root.join("accounts/acct/generation-restored"))?;
    let key = AccountDbKey::generate()?;
    source.copy_to(&root.join(path), &key)?;
    let (nonce, wrapped_key) = crate::wrap_with_vault_secret(&[9; 32], key.bytes())?;
    index.install_backup_generation(&BackupIndexInstall {
        account_id: "acct",
        principal_commitment: "principal",
        db_relative_path: path,
        object_relative_path: "accounts/acct/generation-restored",
        manifest_json: b"{}",
        wrapped_key: &WrappedAccountDbKey {
            key_wrapping_provider: "local-vault".into(),
            key_wrapping_ref: "test".into(),
            nonce,
            wrapped_key,
        },
    })?;
    drop(index);
    AccountDb::open(&AccountIndex::open(root)?, "acct", &key)
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
            &json!({"payload":"prepared-envelope-secret"}),
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
    db.delete_direct_message("thread", "m2", "local", "delete-m2")?;
    let leftover: i64 = db.connection.query_row(
        "SELECT count(*) FROM object_index WHERE object_id='shared-wire' AND length(ciphertext)>0",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(leftover, 0, "shared object last-owner payload survived");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn json_copy_trigger_and_collect_message_ids_share_one_key_set() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("p11-shared-message-id-keys")?;
    let sql: String = db.connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='footprint_runtime_operation_INSERT'",
        [],
        |row| row.get(0),
    )?;
    let keys = super::schema::json_message_id_keys_sql();
    assert!(sql.contains(&format!("t.key IN ({keys})")), "{sql}");
    let mut ids = BTreeSet::new();
    collect_message_ids(
        &json!({
            "message_id": "a",
            "own_copy_message_id": "b",
            "target_message_id": "c",
            "message": {"id": "d"},
            "unrelated": "e"
        }),
        &mut ids,
    );
    assert_eq!(
        ids,
        BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned(), "d".to_owned()])
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn envelope_with_secret(secret: &str) -> serde_json::Value {
    json!({
        "source_principal_id": "p",
        "source_device_id": "d",
        "signing_key_id": "k",
        "payload_hash": "h",
        "created_at": 1,
        "ttl": 1,
        "pair": secret
    })
}

fn archive_kinds(db: &AccountDb, source: &str, glob: &str) -> Result<(), StorageError> {
    let source = source.to_owned();
    let glob = glob.to_owned();
    db.connection.call(move |raw| {
        super::ensure_archive_actor_table(raw)?;
        raw.execute(
            "INSERT OR IGNORE INTO backup_archived_actor_state
             SELECT ?1,state_kind,state_json FROM runtime_actor_state WHERE state_kind GLOB ?2",
            params![source, glob],
        )?;
        Ok(())
    })?;
    Ok(())
}

fn secret_rows(db: &AccountDb, table: &str, secret: &str) -> Result<i64, StorageError> {
    let sql = format!("SELECT count(*) FROM {table} WHERE instr(CAST(state_json AS TEXT), ?1)>0");
    Ok(db.connection.query_row(&sql, params![secret], |row| row.get(0))?)
}

#[test]
fn operation_receipt_does_not_claim_actor_rows_that_share_its_key() -> Result<(), StorageError> {
    let kind = "dm-pair/session/peer";
    let (root, db) = crate::tests::test_db("p11-operation-actor-collision")?;
    db.send_direct_message("thread", "m", "peer", b"private-content")?;
    db.persist_actor_state(kind, &envelope_with_secret("pair-session-secret"))?;
    db.reserve_operation(kind, "fp", "")?;
    db.complete_operation(kind, &json!({"message_id":"m","preview":"op-preview-secret"}))?;
    db.persist_actor_state(kind, &envelope_with_secret("pair-session-secret"))?;
    archive_kinds(&db, "archive", kind)?;
    let actor_binds: i64 = db.connection.query_row(
        "SELECT count(*) FROM message_copy_binding WHERE copy_id=?1",
        params![format!("actor:{kind}")],
        |row| row.get(0),
    )?;
    assert_eq!(actor_binds, 0, "operation receipts must not bind actor rows");
    db.delete_direct_message("thread", "m", "local", "delete")?;
    assert_eq!(secret_rows(&db, "runtime_actor_state", "pair-session-secret")?, 1);
    assert_eq!(secret_rows(&db, "backup_archived_actor_state", "pair-session-secret")?, 1);
    let receipt: String = db.connection.query_row(
        "SELECT response_json FROM runtime_operation WHERE operation_id=?1",
        params![kind],
        |row| row.get(0),
    )?;
    assert!(!receipt.contains("op-preview-secret"), "{receipt}");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn history_page_rewrite_drops_former_owner_archive_claim() -> Result<(), StorageError> {
    let locator = "own-device/history-container/xfer-rw/0";
    let (root, db) = crate::tests::test_db("p11-history-rewrite-owner")?;
    for message in ["m1", "m2"] {
        db.send_direct_message("thread", message, "peer", b"private-content")?;
    }
    db.write_transaction(|| {
        db.put_history_container("xfer-rw", 0, &["m1"], &json!({"body":"history-page-v1"}))
    })?;
    archive_kinds(&db, "first", "own-device/history-container/*")?;
    db.write_transaction(|| {
        db.put_history_container("xfer-rw", 0, &["m2"], &json!({"body":"history-page-secret"}))
    })?;
    archive_kinds(&db, "second", "own-device/history-container/*")?;
    db.delete_direct_message("thread", "m1", "local", "delete-m1")?;
    let rewritten: Vec<u8> = db.connection.query_row(
        "SELECT state_json FROM backup_archived_actor_state WHERE source='second' AND state_kind=?1",
        params![locator],
        |row| row.get(0),
    )?;
    assert!(
        String::from_utf8_lossy(&rewritten).contains("history-page-secret"),
        "former owner deleted the rewritten page"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn merge_does_not_claim_other_sources_nested_archive_rows() -> Result<(), StorageError> {
    let locator = "own-copy/prepared/copy-1";
    let nested = serde_json::to_vec(&json!({"payload":"other-source-secret"}))?;
    let (root, db) = crate::tests::test_db("p11-nested-archive-claim")?;
    db.connection.call(move |raw| {
        super::ensure_archive_actor_table(raw)?;
        raw.execute(
            "INSERT INTO backup_archived_actor_state VALUES('other',?1,?2)",
            params![locator, nested],
        )?;
        Ok(())
    })?;
    db.send_direct_message("thread", "m", "peer", b"private-content")?;
    db.write_transaction(|| {
        db.put_prepared_message_copy("m", "copy-1", &json!({"payload":"prepared-envelope-secret"}))
    })?;
    let incoming = root.join("incoming.db");
    let incoming_snap = db.write_backup_snapshot(&incoming)?;
    drop(db);
    let local_root = root.join("local");
    let local_index = AccountIndex::open(&local_root)?;
    local_index.create_account("acct", "principal")?;
    let local = AccountDb::open(&local_index, "acct", &AccountDbKey::generate()?)?;
    local.send_direct_message("thread", "unrelated", "peer", b"local-body")?;
    let target = root.join("target.db");
    let local_snap = local.write_backup_snapshot(&target)?;
    let mut merged = BackupDatabase::open(&target, &local_snap.key)?;
    merged.merge_backup(&incoming, &incoming_snap.key, || Ok(()))?;
    let changed = merged.db.execute(
        "UPDATE direct_message_projection SET deleted=1 WHERE message_id='m' AND deleted=0",
        [],
    )?;
    assert_eq!(changed, 1);
    let nested_left: i64 = merged.db.query_row(
        "SELECT count(*) FROM backup_archived_actor_state
         WHERE instr(CAST(state_json AS TEXT),'other-source-secret')>0",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(nested_left, 1, "nested archive from another source was claimed");
    let prepared_left: i64 = merged.db.query_row(
        "SELECT count(*) FROM backup_archived_actor_state
         WHERE instr(CAST(state_json AS TEXT),'prepared-envelope-secret')>0",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(prepared_left, 0, "incoming live prepared copy survived delete");
    drop(merged);
    drop(local);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
