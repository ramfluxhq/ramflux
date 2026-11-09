// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::schema::{HEAD_ROW_MAX, LIVE_ROW_MAX, TABLES};
use super::helpers::{TestResult, h};
use crate::schema::migrate_account_db;
use rusqlite::params;

pub(super) fn tables_and_indexes() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-tables")?;
    let names: Vec<String> = TABLES.iter().map(|t| (*t).to_owned()).collect();
    for table in &names {
        let n: i64 = db.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![table],
            |row| row.get(0),
        )?;
        assert_eq!(n, 1, "{table}");
    }
    assert_eq!(TABLES.len(), 5);
    for index in ["pairing_live_phase", "pairing_terminal_finished"] {
        let n: i64 = db.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?1",
            params![index],
            |row| row.get(0),
        )?;
        assert_eq!(n, 1, "{index}");
    }
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn old_open_creates_tables() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-migrate")?;
    db.connection.execute_batch(
        "DROP TABLE pairing_live; DROP TABLE pairing_head; DROP TABLE pairing_terminal;
         DROP TABLE pairing_adoption; DROP TABLE pairing_floor;",
    )?;
    migrate_account_db(&db.connection)?;
    for table in TABLES {
        let n: i64 = db.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![table],
            |row| row.get(0),
        )?;
        assert_eq!(n, 1, "{table}");
    }
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

pub(super) fn caps_and_sql_bounds() -> TestResult {
    let (root, db) = crate::tests::test_db("pair04-sql-cap")?;
    insert_dummy_live(&db, 0)?;
    insert_dummy_live(&db, 1)?;
    insert_dummy_live(&db, 2)?;
    let fourth = insert_dummy_live(&db, 3);
    assert!(fourth.is_err(), "live cap");
    let oversize = db.connection.execute(
        "INSERT INTO pairing_live(
          account_id,operation_id,invitation_id,issuer_seq,local_seq,generation,role,descriptor,
          phase,base_record_hash,base_epoch,expires_at)
         VALUES('acct',?1,?2,1,10,1,'initiator',?3,'invited',?4,1,1)",
        params![h(40), h(41), vec![1_u8; LIVE_ROW_MAX + 1], h(4)],
    );
    assert!(oversize.is_err(), "live row max");
    let head_over = db.connection.execute(
        "INSERT INTO pairing_head(
          account_id,operation_id,generation,kind,base_record_hash,base_epoch,publisher_ref,
          candidate,candidate_hash,state,created_at,invitation_id,recipient_ref)
         VALUES('acct',?1,1,'enroll',?2,1,x'7b7d',?3,?2,'prepared',1,?1,x'7b7d')",
        params![h(50), h(4), vec![1_u8; HEAD_ROW_MAX + 1]],
    );
    assert!(head_over.is_err(), "head candidate max");
    db.put_pairing_floor(&super::helpers::floor())?;
    let down =
        db.connection.execute("UPDATE pairing_floor SET issued_seq=0 WHERE account_id='acct'", []);
    assert!(down.is_err(), "floor monotonic");
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

fn insert_dummy_live(db: &crate::AccountDb, n: u8) -> Result<(), crate::StorageError> {
    db.connection.execute(
        "INSERT INTO pairing_live(
          account_id,operation_id,invitation_id,issuer_seq,local_seq,generation,role,descriptor,
          phase,base_record_hash,base_epoch,expires_at)
         VALUES('acct',?1,?2,1,?3,1,'initiator',x'01','invited',?4,1,1)",
        params![h(30 + n), h(60 + n), i64::from(n) + 1, h(4)],
    )?;
    Ok(())
}
