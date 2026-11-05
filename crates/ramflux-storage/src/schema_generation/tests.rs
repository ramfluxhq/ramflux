// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase, BackupOpenMode, StorageError};
use ramflux_protocol::schema_profile::MESSAGE_SCHEMA_V1_GENERATION;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn refused<T>(result: &Result<T, StorageError>) {
    assert!(matches!(
        result,
        Err(StorageError::SchemaResetRequired {
            generation: MESSAGE_SCHEMA_V1_GENERATION,
            supported: 0
        })
    ));
}

#[test]
fn schema_generation_refuses_mismatched_database_and_archive() -> TestResult {
    let (root, db) = crate::tests::test_db("schema-generation")?;
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let index = AccountIndex::open(&root)?;
    let path = db.path.clone();
    // Existing unmarked stores, all live reader modes and both archive boundaries work.
    drop(db.open_reader()?);
    drop(db.open_backup_reader()?);
    let archive_path = root.join("archive.db");
    let snapshot = db.write_backup_snapshot(&archive_path)?;
    let archive = BackupDatabase::open(&archive_path, &snapshot.key)?;
    drop(BackupDatabase::open_restore_input(
        &archive_path,
        &snapshot.key,
        BackupOpenMode::PreNormalization,
    )?);
    let copied_path = root.join("copy.db");
    archive.copy_to(&copied_path, &snapshot.key)?;
    drop(archive.reopen_restore_input(&copied_path, &snapshot.key, BackupOpenMode::Normalized)?);
    archive.db.pragma_update(None, "user_version", MESSAGE_SCHEMA_V1_GENERATION)?;
    // Malformed application data/schema must not mask the profile refusal.
    archive.db.execute_batch("DROP TABLE schema_migration; DROP TABLE account_key_check;")?;
    drop(archive);
    let original = std::fs::read(&archive_path)?;
    refused(&BackupDatabase::open(&archive_path, &snapshot.key));
    refused(&BackupDatabase::open_restore_input(
        &archive_path,
        &snapshot.key,
        BackupOpenMode::PreNormalization,
    ));
    assert_eq!(std::fs::read(&archive_path)?, original);
    let retained = BackupDatabase::open(&copied_path, &snapshot.key)?;
    refused(&retained.reopen_restore_input(
        &archive_path,
        &snapshot.key,
        BackupOpenMode::Normalized,
    ));
    drop(retained);

    db.connection.execute_batch("PRAGMA user_version=1;")?;
    refused(&db.open_reader());
    refused(&db.open_backup_reader());
    db.connection.execute_batch("DROP TABLE schema_migration; PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(db);
    let original = std::fs::read(&path)?;
    refused(&AccountDb::open(&index, "acct", &key));
    assert_eq!(std::fs::read(&path)?, original);
    assert!(path.exists());

    drop(index);
    let index = rusqlite::Connection::open(root.join(crate::ACCOUNT_INDEX_FILE))?;
    index.execute_batch("PRAGMA user_version=1; DROP TABLE account_index_migration; PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(index);
    let index_path = root.join(crate::ACCOUNT_INDEX_FILE);
    let original = std::fs::read(&index_path)?;
    refused(&AccountIndex::open(&root));
    assert_eq!(std::fs::read(&index_path)?, original);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn negative_and_future_generations_never_fall_back_to_existing_profile() -> TestResult {
    for generation in [-1, 1, 2, i64::from(i32::MAX)] {
        assert!(matches!(
            super::require(generation),
            Err(StorageError::SchemaResetRequired { .. })
        ));
    }
    super::require(0)?;
    Ok(())
}
