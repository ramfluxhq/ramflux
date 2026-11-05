// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Version-twelve ledger fixtures and atomic live/private writer-floor upgrade.
use super::*;
use crate::{AccountDbKey, AccountIndex, BackupDatabase};
use std::path::Path;

pub(super) fn v12_fixture(db: &AccountDb) -> Result<(), StorageError> {
    // v13 introduces no table/column changes. Reconstruct the v12 ledger and
    // remove the new candidate index; leave existing user data untouched.
    db.connection.execute_batch("DROP TABLE IF EXISTS account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14; DELETE FROM schema_migration WHERE schema_version=13; DROP INDEX IF EXISTS runtime_outbox_object_selector;")?;
    db.connection.execute(
        "UPDATE schema_migration SET checksum=?1 WHERE schema_version=1",
        params![crate::schema_object_erasure::V12_SENTINEL],
    )?;
    db.connection.call(|raw| Ok(crate::schema_object_erasure::validate(raw)))??;
    Ok(())
}
fn reopen(root: &Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &AccountIndex::open(root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}
fn assert_v13(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.call(|raw| Ok(crate::schema_object_erasure::validate(raw)))??;
    let version: i64 =
        db.connection
            .query_row("SELECT MAX(schema_version) FROM schema_migration", [], |r| r.get(0))?;
    assert_eq!(version, 14);
    let checksum: String = db.connection.query_row(
        "SELECT checksum FROM schema_migration WHERE schema_version=12",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(checksum, crate::schema_object_erasure::V12_CHECKSUM);
    Ok(())
}
#[test]
fn e10_live_store_v12_to_v13_upgrade() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-v13-live")?;
    db.send_direct_message("thread", "retained", "peer", b"user data")?;
    v12_fixture(&db)?;
    db.connection.execute_batch("DROP TRIGGER object_erase_message; CREATE TRIGGER object_erase_message AFTER UPDATE OF deleted ON direct_message_projection BEGIN SELECT 1; END;")?;
    drop(db);
    let db = reopen(&root)?;
    assert_v13(&db)?;
    let trigger: String = db.connection.query_row(
        "SELECT sql FROM sqlite_master WHERE name='object_erase_message'",
        [],
        |r| r.get(0),
    )?;
    assert!(trigger.contains("object_reference_erasure_work"));
    let retained: bool = db.connection.query_row("SELECT EXISTS(SELECT 1 FROM direct_message_projection WHERE message_id='retained' AND deleted=0)", [], |r| r.get(0))?;
    assert!(retained);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn e10_old_writer_refuses_v13() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-v13-old-writer")?;
    db.connection.execute_batch(
        "DROP TABLE account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14;",
    )?;
    // Frozen v12 validation performs this maximum-version check before writes.
    let newest: i64 = db.connection.query_row(
        "SELECT COALESCE(MAX(schema_version),0) FROM schema_migration",
        [],
        |r| r.get(0),
    )?;
    let result: Result<(), StorageError> = if newest > 12 {
        Err(StorageError::AccountSchemaTooNew { schema_version: newest, supported: 12 })
    } else {
        Ok(())
    };
    assert!(matches!(
        result,
        Err(StorageError::AccountSchemaTooNew { schema_version: 13, supported: 12 })
    ));
    // Older readers ignoring future rows still refuse the changed migration-1 checksum.
    let sentinel: String = db.connection.query_row(
        "SELECT checksum FROM schema_migration WHERE schema_version=1",
        [],
        |r| r.get(0),
    )?;
    assert_ne!(sentinel, crate::schema_object_erasure::V12_SENTINEL);
    assert_eq!(sentinel, crate::schema_object_erasure::SENTINEL);
    db.connection.execute("DELETE FROM schema_migration WHERE schema_version=13", [])?;
    let torn = db.connection.call(|raw| Ok(crate::schema_object_erasure::validate(raw)))?;
    assert!(matches!(torn, Err(StorageError::MigrationChecksumMismatch { .. })));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn e10_v13_migration_rollback() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-v13-rollback")?;
    v12_fixture(&db)?;
    db.connection.execute_batch("DROP TRIGGER object_erase_message; CREATE TRIGGER object_erase_message AFTER UPDATE OF deleted ON direct_message_projection BEGIN SELECT 1; END; CREATE TRIGGER fail_v13 BEFORE INSERT ON schema_migration WHEN NEW.schema_version=13 BEGIN SELECT RAISE(ABORT,'v13 cut'); END;")?;
    assert!(crate::schema_object_erasure::upgrade_private(&db.connection).is_err());
    let path = db.path.clone();
    drop(db);
    let sql = rusqlite::Connection::open(path)?;
    sql.execute_batch(&format!(
        "PRAGMA key=\"x'{}'\";",
        AccountDbKey::derive("acct", b"storage-test-secret").sqlcipher_hex()
    ))?;
    crate::schema_object_erasure::validate(&sql)?;
    let version: i64 =
        sql.query_row("SELECT MAX(schema_version) FROM schema_migration", [], |r| r.get(0))?;
    assert_eq!(version, 12);
    let trigger: String = sql.query_row(
        "SELECT sql FROM sqlite_master WHERE name='object_erase_message'",
        [],
        |r| r.get(0),
    )?;
    assert!(!trigger.contains("object_reference_erasure_work"));
    let index: bool = sql.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='runtime_outbox_object_selector')",
        [],
        |r| r.get(0),
    )?;
    assert!(!index);
    sql.execute_batch("DROP TRIGGER fail_v13;")?;
    drop(sql);
    let db = reopen(&root)?;
    assert_v13(&db)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn c2_v12_archive_restores_into_v13_store_with_base_semantics() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("selector-v12-restore")?;
    let target_path = root.join("target.db");
    let target = db.write_backup_snapshot(&target_path)?;
    db.send_direct_message("thread", "restored", "peer", b"archived content")?;
    v12_fixture(&db)?;
    let source_path = root.join("source.db");
    let source = db.write_backup_snapshot(&source_path)?;
    let before = std::fs::read(&source_path)?;
    for native in [false, true] {
        let path = root.join(format!("merge-{native}.db"));
        let key = AccountDbKey::generate()?;
        BackupDatabase::open(&target_path, &target.key)?.copy_to(&path, &key)?;
        let mut merged = BackupDatabase::open(&path, &key)?;
        // Restore consumes a private input copy, preserving the published archive.
        let input = root.join(format!("input-{native}.db"));
        std::fs::copy(&source_path, &input)?;
        if native {
            merged.merge_native_backup(&input, &source.key, || Ok(()))?;
        } else {
            merged.merge_backup(&input, &source.key, || Ok(()))?;
        }
        let present: bool = merged.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM direct_message_projection WHERE message_id='restored')",
            [],
            |r| r.get(0),
        )?;
        assert!(present);
        crate::schema_object_erasure::validate(&merged.db)?;
    }
    assert!(before == std::fs::read(&source_path)?, "source archive bytes changed");
    // Opening a private staged v12 copy uses the same upgrade as the live store.
    let staged_path = root.join("staged.db");
    std::fs::copy(&source_path, &staged_path)?;
    let staged = BackupDatabase::open(&staged_path, &source.key)?;
    crate::schema_object_erasure::validate(&staged.db)?;
    let version: i64 =
        staged
            .db
            .query_row("SELECT MAX(schema_version) FROM schema_migration", [], |r| r.get(0))?;
    assert_eq!(version, 14);
    drop(staged);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
