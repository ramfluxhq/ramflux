// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::schema::TABLES;
use super::super::skip_merge;
use super::helpers::{TestResult, floor, h, invited};

pub(super) fn live_rows_are_stripped_floors_survive() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-backup")?;
    db.put_pairing_floor(&floor())?;
    db.put_pairing_live(&invited()?)?;
    db.connection.call(|sql| Ok(super::super::sanitize_backup(sql)))??;
    assert_eq!(db.pairing_live_count()?, 0);
    assert_eq!(db.pairing_terminal_count()?, 0);
    assert!(db.pairing_adoption()?.is_none());
    let kept = db.pairing_floor()?.ok_or("floor missing")?;
    assert_eq!(kept.issued_seq, 3);
    assert_eq!(kept.next_generation, 2);
    let _ = std::fs::remove_dir_all(root);
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
