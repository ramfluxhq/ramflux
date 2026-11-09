// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::schema::TABLES;
use super::super::skip_merge;
use super::helpers::{TestResult, adoption, floor, h, head, invited, terminal};
use crate::BackupDatabase;

pub(super) fn live_rows_are_stripped_floors_survive() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-backup")?;
    db.put_pairing_floor(&floor())?;
    db.put_pairing_live(&invited()?)?;
    db.put_pairing_head(&head()?)?;
    db.put_pairing_terminal(&terminal())?;
    db.put_pairing_adoption(&adoption("secondary", None)?)?;
    let archive = root.join("archive.db");
    let snapshot = db.write_backup_snapshot(&archive)?;
    let opened = rusqlite::Connection::open(&archive)?;
    opened.execute_batch(&format!("PRAGMA key = \"x'{}'\";", snapshot.key.sqlcipher_hex()))?;
    for table in ["pairing_live", "pairing_head", "pairing_terminal", "pairing_adoption"] {
        let n: i64 =
            opened.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))?;
        assert_eq!(n, 0, "{table} restored");
    }
    let issued: i64 = opened.query_row(
        "SELECT issued_seq FROM pairing_floor WHERE account_id='acct'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(issued, 3);
    let (fresh_root, fresh) = crate::tests::test_db("pair04-backup-fresh")?;
    let mut low = floor();
    low.issued_seq = 1;
    low.next_generation = 1;
    fresh.put_pairing_floor(&low)?;
    let target_path = fresh_root.join("target.db");
    let target_snap = fresh.write_backup_snapshot(&target_path)?;
    let mut restored = BackupDatabase::open(&target_path, &target_snap.key)?;
    restored.merge_backup(&archive, &snapshot.key, || Ok(()))?;
    let live: i64 =
        restored.db.query_row("SELECT count(*) FROM pairing_live", [], |row| row.get(0))?;
    let heads: i64 =
        restored.db.query_row("SELECT count(*) FROM pairing_head", [], |row| row.get(0))?;
    let terms: i64 =
        restored.db.query_row("SELECT count(*) FROM pairing_terminal", [], |row| row.get(0))?;
    let adopts: i64 =
        restored.db.query_row("SELECT count(*) FROM pairing_adoption", [], |row| row.get(0))?;
    assert_eq!((live, heads, terms, adopts), (0, 0, 0, 0));
    let merged: (i64, i64) = restored.db.query_row(
        "SELECT issued_seq,next_generation FROM pairing_floor WHERE account_id='acct'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(merged, (3, 2));
    let old_path = fresh_root.join("old-no-tables.db");
    let old_snap = fresh.write_backup_snapshot(&old_path)?;
    {
        let old = rusqlite::Connection::open(&old_path)?;
        old.execute_batch(&format!("PRAGMA key = \"x'{}'\";", old_snap.key.sqlcipher_hex()))?;
        old.execute_batch(
            "DROP TABLE IF EXISTS pairing_live; DROP TABLE IF EXISTS pairing_head;
             DROP TABLE IF EXISTS pairing_terminal; DROP TABLE IF EXISTS pairing_adoption;
             DROP TABLE IF EXISTS pairing_floor;",
        )?;
    }
    restored.merge_backup(&old_path, &old_snap.key, || Ok(()))?;
    let after: (i64, i64) = restored.db.query_row(
        "SELECT issued_seq,next_generation FROM pairing_floor WHERE account_id='acct'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(after, (3, 2));
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(fresh_root);
    Ok(())
}

pub(super) fn skip_merge_and_floor_maxima() -> TestResult {
    for table in TABLES {
        assert!(skip_merge(table), "{table}");
    }
    assert!(!skip_merge("direct_message_projection"));
    let (root, db) = crate::tests::test_db("pair04-floor-merge")?;
    db.put_pairing_floor(&floor())?;
    db.connection.call(|sql| {
        sql.execute_batch("ATTACH ':memory:' AS incoming")?;
        super::super::schema::install(sql)?;
        sql.execute_batch(
            "CREATE TABLE incoming.pairing_floor AS SELECT * FROM pairing_floor LIMIT 0",
        )?;
        sql.execute(
            "INSERT INTO incoming.pairing_floor(account_id,account_anchor,issued_seq,next_generation)
             VALUES('acct',?1,9,8)",
            rusqlite::params![h(2)],
        )?;
        Ok(super::super::merge_floor(sql))
    })??;
    let merged = db.pairing_floor()?.ok_or("floor")?;
    assert_eq!(merged.issued_seq, 9);
    assert_eq!(merged.next_generation, 8);
    db.connection.call(|sql| {
        sql.execute(
            "UPDATE incoming.pairing_floor SET account_anchor=?1",
            rusqlite::params![h(9)],
        )?;
        let result = super::super::merge_floor(sql);
        assert!(
            matches!(result, Err(crate::StorageError::PairingField("account_anchor"))),
            "foreign anchor: {result:?}"
        );
        Ok(())
    })?;
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn floor_merge_binds_local_account() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-floor-empty-foreign")?;
    db.connection.call(|sql| {
        sql.execute_batch("ATTACH ':memory:' AS incoming")?;
        super::super::schema::install(sql)?;
        sql.execute_batch(
            "CREATE TABLE incoming.pairing_floor AS SELECT * FROM pairing_floor LIMIT 0",
        )?;
        sql.execute(
            "INSERT INTO incoming.pairing_floor(account_id,account_anchor,issued_seq,next_generation)
             VALUES('other',?1,9,8)",
            rusqlite::params![h(2)],
        )?;
        let result = super::super::privacy::merge_floor_for(sql, Some("acct"));
        assert!(
            matches!(result, Err(crate::StorageError::PairingField("account_id"))),
            "empty local foreign: {result:?}"
        );
        Ok(())
    })?;
    assert!(db.pairing_floor()?.is_none());
    db.connection.call(|sql| {
        sql.execute("UPDATE incoming.pairing_floor SET account_id='acct'", [])?;
        Ok(super::super::privacy::merge_floor_for(sql, Some("acct")))
    })??;
    let copied = db.pairing_floor()?.ok_or("copied")?;
    assert_eq!(copied.account_id, "acct");
    assert_eq!(copied.issued_seq, 9);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}
