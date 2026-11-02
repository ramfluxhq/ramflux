// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::{AccountDbKey, AccountIndex, ObjectWrite};
use serde_json::json;

fn reopen(root: &std::path::Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &AccountIndex::open(root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

// Frozen migration-1 reader from the pre-erasure schema; it does not know migration 12.
fn read_existing_ledger_as_pre_erasure_writer(
    connection: &crate::database::Connection,
) -> Result<(), StorageError> {
    let existing: Option<String> = connection
        .query_row(
            "SELECT checksum FROM schema_migration WHERE schema_version = ?1",
            params![1],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(checksum) = existing {
        if checksum == "2026-06-14-account-core-v1" {
            return Ok(());
        }
        return Err(StorageError::MigrationChecksumMismatch {
            schema_version: 1,
            expected: "2026-06-14-account-core-v1".into(),
            actual: checksum,
        });
    }
    Ok(())
}

// Mutation: remove the version-one checksum sentinel while keeping the version-twelve migration.
#[test]
fn erasure_writer_floor_refuses_old_checksum_rules_and_future_or_torn_schema_versions()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-writer-floor")?;
    let reader = db.open_reader()?;
    assert!(reader.is_query_only()?);
    let before: Vec<(i64, String)> = reader
        .connection
        .prepare("SELECT schema_version,checksum FROM schema_migration ORDER BY schema_version")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let legacy = read_existing_ledger_as_pre_erasure_writer(&reader.connection);
    let error = legacy.err().ok_or(StorageError::AuthorizationRejected)?;
    assert!(
        matches!(&error, StorageError::MigrationChecksumMismatch { schema_version: 1, expected, actual }
        if expected == "2026-06-14-account-core-v1" && actual == crate::schema_object_erasure::SENTINEL)
    );
    assert_eq!(
        error.to_string(),
        "migration checksum mismatch for version 1: expected 2026-06-14-account-core-v1, got 2026-06-14-account-core-v1;writer-floor=12;object-erasure-v1"
    );
    let after: Vec<(i64, String)> = reader
        .connection
        .prepare("SELECT schema_version,checksum FROM schema_migration ORDER BY schema_version")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    assert_eq!(before, after);
    drop(reader);
    db.connection
        .execute("INSERT INTO schema_migration VALUES(13,0,'future','future','future')", [])?;
    assert!(matches!(
        reopen(&root),
        Err(StorageError::AccountSchemaTooNew { schema_version: 13, supported: 12 })
    ));
    db.connection.execute("DELETE FROM schema_migration WHERE schema_version=13", [])?;
    db.connection.execute(
        "UPDATE schema_migration SET checksum='2026-06-14-account-core-v1' WHERE schema_version=1",
        [],
    )?;
    read_existing_ledger_as_pre_erasure_writer(&db.connection)?;
    assert!(matches!(
        reopen(&root),
        Err(StorageError::MigrationChecksumMismatch { schema_version: 1, .. })
    ));
    db.connection.execute(
        "UPDATE schema_migration SET checksum=?1 WHERE schema_version=1",
        params![crate::schema_object_erasure::SENTINEL],
    )?;
    drop(db);
    drop(reopen(&root)?);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: scan unbounded metadata on open or infer imported ownership from absent references.
#[test]
fn legacy_discovery_resumes_with_a_256_row_budget_and_preserves_ambiguous_orphans()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-discovery-budget")?;
    db.write_transaction(|| {
        for n in 0..600 {
            let id=format!("legacy-{n:04}");
            db.upsert_object(&ObjectWrite {object_id:&id,manifest_hash:"legacy-manifest",nonce:"nonce",ciphertext:b"legacy-body",plaintext_hash:"legacy-hash",tombstoned:false,backup_excluded:false,content_key:Some(&[7;32]),object:&json!({"legacy":true}),updated_at:1})?;
        }
        db.connection.execute("UPDATE object_retention_upgrade SET phase=0,cursor=0,rows_scanned=0,decoded_bytes=0 WHERE singleton=1",[])?;
        Ok::<(),StorageError>(())
    })?;
    drop(db);
    let mut previous = 0_i64;
    let mut previous_bytes = 0_i64;
    for _ in 0..4 {
        let db = reopen(&root)?;
        let (phase,rows,bytes):(i64,i64,i64)=db.connection.query_row("SELECT phase,rows_scanned,decoded_bytes FROM object_retention_upgrade WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        assert!(rows - previous <= 256);
        assert!(bytes - previous_bytes <= 1024 * 1024);
        previous_bytes = bytes;
        previous = rows;
        assert!(db.load_object::<Value>("legacy-0000")?.is_some());
        assert_eq!(db.object_erasure_generation()?, 0);
        if phase == 5 {
            break;
        }
    }
    let db = reopen(&root)?;
    assert_eq!(
        db.connection.query_row(
            "SELECT phase FROM object_retention_upgrade WHERE singleton=1",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        5
    );
    assert_eq!(db.load_objects::<Value>()?.0.len(), 600);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: decode a second large metadata row after consuming the per-open byte budget.
#[test]
fn legacy_discovery_stops_at_one_mebibyte_and_keeps_a_durable_cursor() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-discovery-bytes")?;
    for id in ["one", "two"] {
        db.persist_actor_state(&format!("directory/object/{id}"),&json!({"message_id":"legacy-message","manifest_hash":"legacy-manifest","name":"x".repeat(600_000)}))?;
    }
    db.connection.execute("UPDATE object_retention_upgrade SET phase=1,cursor=0,rows_scanned=0,decoded_bytes=0 WHERE singleton=1",[])?;
    drop(db);
    let db = reopen(&root)?;
    let (phase, cursor, bytes): (i64, i64, i64) = db.connection.query_row(
        "SELECT phase,cursor,decoded_bytes FROM object_retention_upgrade WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    assert_eq!(phase, 1);
    assert!(cursor > 0);
    assert!((600_000..=1_048_576).contains(&bytes));
    drop(db);
    let db = reopen(&root)?;
    let after: i64 = db.connection.query_row(
        "SELECT decoded_bytes FROM object_retention_upgrade WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    assert!((600_000..=1_048_576).contains(&(after - bytes)));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: reclaim more than one eligible payload or reclaim an oversized legacy BLOB.
#[test]
fn maintenance_reclaims_one_proven_orphan_and_leaves_oversized_payloads_for_explicit_policy()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-reclaim-budget")?;
    for id in ["one", "two", "oversized"] {
        db.retain_object(id, "manifest", ObjectRetention::Imported)?;
        db.upsert_object(&ObjectWrite {
            object_id: id,
            manifest_hash: "manifest",
            nonce: "nonce",
            ciphertext: b"cipher",
            plaintext_hash: "hash",
            tombstoned: false,
            backup_excluded: false,
            content_key: Some(&[7; 32]),
            object: &json!({}),
            updated_at: 1,
        })?;
    }
    db.connection.execute(
        "UPDATE object_index SET ciphertext=zeroblob(16777233) WHERE object_id='oversized'",
        [],
    )?;
    db.maintain_object_retention()?;
    assert_eq!(db.object_erasure_generation()?, 1);
    db.maintain_object_retention()?;
    assert_eq!(db.object_erasure_generation()?, 2);
    db.maintain_object_retention()?;
    assert_eq!(db.object_erasure_generation()?, 2);
    assert_eq!(
        db.connection.query_row(
            "SELECT length(ciphertext) FROM object_index WHERE object_id='oversized'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        16_777_233
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: consult only the pinned reader snapshot when checking an object's erasure fence.
#[test]
fn pinned_backup_reader_cannot_read_erased_payload_and_keeps_wal_retirement_pending()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-pinned-reader")?;
    super::tests::install(&db, "one", "reference")?;
    super::tests::payload(&db)?;
    let reader = db.open_backup_reader()?;
    assert!(reader.load_object::<Value>("wire")?.is_some());
    db.delete_direct_message("thread", "one", "local", "delete")?;
    assert!(matches!(reader.load_object::<Value>("wire"), Err(StorageError::ObjectErased)));
    assert!(db.connection.query_row(
        "SELECT erasure_pending FROM runtime_privacy_maintenance WHERE singleton=1",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    drop(reader);
    db.checkpoint_retired_secrets()?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
