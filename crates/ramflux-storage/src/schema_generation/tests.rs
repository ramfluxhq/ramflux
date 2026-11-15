// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase, BackupOpenMode, StorageError};
use ramflux_protocol::schema_profile::ACTIVE_STORAGE_GENERATION;
use std::io::Read as _;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn bounded_bytes(path: &std::path::Path) -> TestResult<Vec<u8>> {
    const LIMIT: u64 = 32 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(LIMIT + 1).read_to_end(&mut bytes)?;
    assert!(u64::try_from(bytes.len())? <= LIMIT, "test database exceeded its byte budget");
    Ok(bytes)
}

fn refused<T>(result: &Result<T, StorageError>) {
    assert!(matches!(
        result,
        Err(StorageError::SchemaResetRequired {
            generation: 0,
            supported: ACTIVE_STORAGE_GENERATION
        })
    ));
}

#[test]
fn schema_generation_refuses_mismatched_database_and_archive() -> TestResult {
    let root_guard = tempfile::tempdir()?;
    let root = root_guard.path();
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let index = AccountIndex::open(root)?;
    index.create_account("acct", "principal")?;
    let db = AccountDb::open(&index, "acct", &key)?;
    assert_eq!(
        index.connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
        ACTIVE_STORAGE_GENERATION,
        "a fresh index must publish the active marker before application schema access"
    );
    assert_eq!(
        db.connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
        ACTIVE_STORAGE_GENERATION,
        "a fresh encrypted account must publish the active marker before application schema access"
    );
    let path = db.path.clone();
    // Fresh generation-1 stores, all live reader modes and both archive boundaries work.
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
    archive.db.pragma_update(None, "user_version", 0)?;
    // Malformed application data/schema must not mask the profile refusal.
    archive.db.execute_batch("DROP TABLE schema_migration; DROP TABLE account_key_check;")?;
    drop(archive);
    let original = bounded_bytes(&archive_path)?;
    refused(&BackupDatabase::open(&archive_path, &snapshot.key));
    refused(&BackupDatabase::open_restore_input(
        &archive_path,
        &snapshot.key,
        BackupOpenMode::PreNormalization,
    ));
    assert_eq!(bounded_bytes(&archive_path)?, original);
    let retained = BackupDatabase::open(&copied_path, &snapshot.key)?;
    refused(&retained.reopen_restore_input(
        &archive_path,
        &snapshot.key,
        BackupOpenMode::Normalized,
    ));
    drop(retained);

    db.connection.execute_batch("PRAGMA user_version=0;")?;
    refused(&db.open_reader());
    refused(&db.open_backup_reader());
    db.connection.execute_batch("DROP TABLE schema_migration; PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(db);
    let original = bounded_bytes(&path)?;
    refused(&AccountDb::open(&index, "acct", &key));
    assert_eq!(bounded_bytes(&path)?, original);
    assert!(path.exists());

    drop(index);
    let index = rusqlite::Connection::open(root.join(crate::ACCOUNT_INDEX_FILE))?;
    index.execute_batch("PRAGMA user_version=0; DROP TABLE account_index_migration; PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(index);
    let index_path = root.join(crate::ACCOUNT_INDEX_FILE);
    let original = bounded_bytes(&index_path)?;
    refused(&AccountIndex::open(root));
    assert_eq!(bounded_bytes(&index_path)?, original);
    Ok(())
}

#[test]
fn negative_and_future_generations_never_fall_back_to_existing_profile() -> TestResult {
    for generation in [-1, 0, 2, i64::from(i32::MAX)] {
        assert!(matches!(
            super::require(generation),
            Err(StorageError::SchemaResetRequired { .. })
        ));
    }
    super::require(ACTIVE_STORAGE_GENERATION)?;
    Ok(())
}
