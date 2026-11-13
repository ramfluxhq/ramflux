// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local SQL differences preserve nullable values, row identities and sequence ceilings.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn pairing_full_local_row_delta_preserves_nulls_rowids_and_no_trigger_side_effects() -> TestResult {
    let owner = tempfile::tempdir()?;
    let key = AccountDbKey::derive("test", b"local-row-delta");
    let source = owner.path().join("source.db");
    let target = owner.path().join("target.db");
    let schema = "CREATE TABLE local_rows(id INTEGER PRIMARY KEY AUTOINCREMENT,value BLOB,note TEXT); CREATE TABLE local_keys(name TEXT PRIMARY KEY,value BLOB) WITHOUT ROWID; CREATE TABLE effects(value TEXT); CREATE TRIGGER on_local_rows AFTER INSERT ON local_rows BEGIN INSERT INTO effects VALUES('unexpected'); END;";
    for path in [&source, &target] {
        super::super::super::super::stage::create_file(path)?.sync_all()?;
        let db = open(path, &key)?;
        db.execute_batch(schema)?;
    }
    let source_db = open(&source, &key)?;
    source_db.execute_batch("INSERT INTO local_rows VALUES(9,NULL,'present'); INSERT INTO local_rows VALUES(100,x'0001',NULL); DELETE FROM local_rows WHERE id=100; INSERT INTO local_keys VALUES('one',NULL); DELETE FROM effects;")?;
    let target_db = open(&target, &key)?;
    target_db.execute_batch("INSERT INTO local_rows VALUES(9,x'99','old'); INSERT INTO local_rows VALUES(10,NULL,NULL); INSERT INTO local_keys VALUES('two',x'0102'); DELETE FROM effects;")?;
    attach(&target_db, &source, &key)?;
    target_db.execute_batch("BEGIN IMMEDIATE")?;
    for name in ["local_rows", "local_keys"] {
        table(&target_db, name)?;
    }
    sequences(&target_db)?;
    target_db.execute_batch("COMMIT")?;
    assert_eq!(
        target_db.query_row(
            "SELECT count(*) FROM local_rows WHERE id=9 AND value IS NULL AND note='present'",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        1,
        "test: nullable B update was lost"
    );
    assert_eq!(
        target_db.query_row("SELECT count(*) FROM local_rows", [], |row| row.get::<_, u64>(0))?,
        1,
        "test: removed B row survived"
    );
    assert_eq!(
        target_db.query_row(
            "SELECT count(*) FROM local_keys WHERE name='one' AND value IS NULL",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        1,
        "test: WITHOUT ROWID change was lost"
    );
    assert_eq!(
        target_db.query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='local_rows'",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        100,
        "test: B sequence ceiling moved backwards"
    );
    assert_eq!(
        target_db.query_row("SELECT count(*) FROM effects", [], |row| row.get::<_, u64>(0))?,
        0,
        "test: replay generated local events"
    );
    assert_eq!(
        source_db.query_row("SELECT count(*) FROM local_rows", [], |row| row.get::<_, u64>(0))?,
        1,
        "test: delta mutated its source"
    );
    Ok(())
}

fn open(path: &Path, key: &AccountDbKey) -> Result<Connection, rusqlite::Error> {
    let db = Connection::open(path)?;
    let hex = Zeroizing::new(key.sqlcipher_hex());
    let pragma = Zeroizing::new(format!("PRAGMA key=\"x'{}'\";", hex.as_str()));
    db.execute_batch(&pragma)?;
    Ok(db)
}
