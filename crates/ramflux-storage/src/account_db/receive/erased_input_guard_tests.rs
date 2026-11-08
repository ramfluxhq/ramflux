// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `erased_input_classification_guard`: an unclassified footprint store or kind is rejected.
#![allow(clippy::expect_used, clippy::panic)]
use super::erased_capture::{ClassificationError, classification_guard};
use crate::{AccountDb, StorageError};

/// A connection or SQLite failure is a `StorageError`; only a classification refusal is the inner
/// `Err`.
fn guard(db: &AccountDb) -> Result<Result<(), ClassificationError>, StorageError> {
    Ok(db.connection.call(|raw| Ok(classification_guard(raw)))?)
}

fn refused(db: &AccountDb, expected: &str) {
    let result = guard(db).expect("connection");
    assert!(
        matches!(&result, Err(ClassificationError::Unclassified(text)) if text == expected),
        "{:?}",
        result.err()
    );
}

#[test]
fn erased_input_classification_guard() -> Result<(), StorageError> {
    // (u3) A clean database, with and without the receive ledger, is fully classified.
    let (root, db) = crate::tests::test_db("erased-guard-clean")?;
    guard(&db)?.expect("clean database is classified");
    db.install_receive_ledger_schema()?;
    guard(&db)?.expect("receive ledger is classified");
    drop(db);
    std::fs::remove_dir_all(root)?;
    // (u1) An unclassified table with a footprint trigger is named exactly.
    let (root, db) = crate::tests::test_db("erased-guard-table")?;
    db.connection.execute_batch(
        "CREATE TABLE zz_store(x TEXT);
         CREATE TRIGGER footprint_zz_store_INSERT AFTER INSERT ON zz_store BEGIN SELECT 1; END;",
    )?;
    refused(&db, "tables [zz_store]; kinds []");
    drop(db);
    std::fs::remove_dir_all(root)?;
    // (u2) An unclassified kind on a classified table is named exactly.
    let (root, db) = crate::tests::test_db("erased-guard-kind")?;
    db.connection.execute(
        "INSERT INTO message_footprint VALUES('M','actor:zz','runtime_actor_state')",
        [],
    )?;
    refused(&db, "tables []; kinds [actor:zz]");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
