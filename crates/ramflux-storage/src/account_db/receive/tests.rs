// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P01 migration, unsigned ordering, authority and actual process-death oracles.
#![allow(clippy::expect_used, clippy::panic)]
use super::*;
use crate::{AccountDbKey, AccountIndex, durability_test_hooks};
use rusqlite::params;
use std::{
    path::Path,
    process::{Child, Command},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
#[path = "previous_writer.rs"]
mod previous_writer;

fn reopen(root: &Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &AccountIndex::open(root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn wait(mut child: Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill hung child");
            child.wait().expect("reap hung child");
            panic!("receive ledger child exceeded 30-second hang guard");
        }
        std::thread::yield_now();
    }
}

fn child(root: &Path, mode: &str) -> std::process::ExitStatus {
    wait(
        Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "account_db::receive::tests::ledger_child", "--nocapture"])
            .env("RAMFLUX_RECEIVE_CHILD_ROOT", root)
            .env("RAMFLUX_RECEIVE_CHILD_MODE", mode)
            .spawn()
            .expect("spawn child"),
    )
}

#[test]
fn ledger_child() -> Result<(), StorageError> {
    let Some(root) = std::env::var_os("RAMFLUX_RECEIVE_CHILD_ROOT") else {
        return Ok(());
    };
    let mode = std::env::var("RAMFLUX_RECEIVE_CHILD_MODE").expect("child mode");
    if mode == "old-writer" {
        // Frozen c7bc48bd writer guard, executed before any migration/effect.
        let index = AccountIndex::open(&root)?;
        let path = Path::new(&root).join(index.account("acct")?.db_relative_path);
        let connection = crate::database::Connection::open(path)?;
        crate::encryption::apply_key(
            &connection,
            &AccountDbKey::derive("acct", b"storage-test-secret"),
        )?;
        let result = connection.call(|db| Ok(previous_writer::validate(db)))?;
        match result {
            Err(StorageError::AccountSchemaTooNew { schema_version: 15, supported: 14 }) => {}
            other => panic!("previous writer must refuse before writes: {other:?}"),
        }
        return Ok(());
    }
    let db = reopen(Path::new(&root))?;
    let after = mode == "after";
    let _observer = durability_test_hooks::observe(
        db.path.clone(),
        Arc::new(move |sql, completed, autocommit| {
            if sql == "COMMIT" && completed == after {
                assert_eq!(autocommit, after);
                std::process::abort();
            }
            Ok(())
        }),
    )?;
    db.install_receive_ledger_schema()?;
    panic!("real COMMIT cut did not fire");
}

#[test]
fn old_writer_refusal() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-old-writer")?;
    db.install_receive_ledger_schema()?;
    db.connection.execute(
        "INSERT INTO gateway_receive_epoch VALUES('target','epoch',1,x'',?1,?1)",
        params![0u64.to_be_bytes().as_slice()],
    )?;
    db.checkpoint_retired_secrets()?;
    let path = db.path.clone();
    drop(db);
    let before = std::fs::read(&path)?;
    assert!(child(&root, "old-writer").success(), "previous writer refusal child failed");
    assert_eq!(std::fs::read(&path)?, before, "old writer changed encrypted DB");
    let db = reopen(&root)?;
    let epoch: String =
        db.connection
            .query_row("SELECT incarnation_id FROM gateway_receive_epoch", [], |r| r.get(0))?;
    assert_eq!(epoch, "epoch");
    db.install_receive_ledger_schema()?; // Idempotent; never reverses the floor.
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn schema_allowlists_and_unsigned_indexes() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-schema")?;
    let count: i64 = db.connection.query_row("SELECT count(*) FROM sqlite_master WHERE name LIKE 'gateway_receive_%' OR name IN ('gateway_ack_intent','gateway_inbox_loss')", [], |r| r.get(0))?;
    assert_eq!(count, 0, "schema stays dormant until explicit installation");
    db.install_receive_ledger_schema()?;
    for (table, columns) in [
        (
            "gateway_receive_receipt",
            "target_delivery_id,incarnation_id,inbox_seq,disposition,retain_until,first_seen",
        ),
        (
            "gateway_receive_work",
            "target_delivery_id,incarnation_id,inbox_seq,entry_json,admission_key,byte_len",
        ),
        (
            "gateway_ack_intent",
            "target_delivery_id,incarnation_id,inbox_seq,created_at,attempts,next_attempt_at,expires_at",
        ),
        (
            "gateway_inbox_loss",
            "target_delivery_id,incarnation_id,from_seq,to_seq,count,reason,recorded_at,classification",
        ),
        (
            "gateway_receive_epoch",
            "target_delivery_id,incarnation_id,incarnation_verified,retired_incarnations,activated_cursor,legacy_uncertain_through",
        ),
    ] {
        let actual = db
            .connection
            .prepare(&format!("PRAGMA table_info({table})"))?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(actual.join(","), columns, "{table} privacy allowlist");
    }
    let seqs = [1, i64::MAX as u64, 1u64 << 63, u64::MAX];
    for seq in seqs {
        db.connection.execute(
            "INSERT INTO gateway_ack_intent VALUES('t','e',?1,0,0,0,0)",
            params![seq.to_be_bytes().as_slice()],
        )?;
    }
    let actual = db.connection.prepare("SELECT inbox_seq FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq")?.query_map([], |r| r.get::<_, Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    assert_eq!(actual, seqs.map(|s| s.to_be_bytes().to_vec()));
    let due: String = db.connection.query_row("EXPLAIN QUERY PLAN SELECT inbox_seq FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e' AND next_attempt_at<=0 ORDER BY next_attempt_at,inbox_seq LIMIT 16", [], |r| r.get(3))?;
    assert!(due.contains("gateway_ack_intent_due"), "{due}");
    let receipt: String = db.connection.query_row("EXPLAIN QUERY PLAN SELECT inbox_seq FROM gateway_receive_receipt WHERE target_delivery_id='t' AND incarnation_id='e' AND inbox_seq>=?1 AND inbox_seq<=?2 ORDER BY inbox_seq LIMIT 64", params![1u64.to_be_bytes().as_slice(), u64::MAX.to_be_bytes().as_slice()], |r| r.get(3))?;
    assert!(receipt.contains("PRIMARY KEY"), "{receipt}");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn migration_real_commit_child_cuts() -> Result<(), StorageError> {
    for mode in ["before", "after"] {
        let (root, db) = crate::tests::test_db(&format!("receive-cut-{mode}"))?;
        drop(db);
        let status = child(&root, mode);
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(6), "must hit the abort hook, not a setup/test error");
        }
        assert!(!status.success(), "child must abort at the real COMMIT");
        let db = reopen(&root)?;
        let tables: i64 = db.connection.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('gateway_receive_receipt','gateway_receive_work','gateway_ack_intent','gateway_inbox_loss','gateway_receive_epoch')", [], |r| r.get(0))?;
        let floor: bool = db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migration WHERE schema_version=15)",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(tables, if mode == "after" { 5 } else { 0 });
        assert_eq!(floor, mode == "after");
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn nested_release_is_not_durable_commit() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-release")?;
    let boundaries = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&boundaries);
    let observer = durability_test_hooks::observe(
        db.path.clone(),
        Arc::new(move |sql, completed, auto| {
            if sql.starts_with("RELEASE") || sql == "COMMIT" {
                captured.lock().expect("boundaries").push((sql.to_owned(), completed, auto));
            }
            Ok(())
        }),
    )?;
    db.write_transaction(|| db.install_receive_ledger_schema())?;
    let events = boundaries.lock().expect("boundaries");
    assert_eq!(events.len(), 4);
    assert!(events[0].0.starts_with("RELEASE"));
    assert_eq!((events[0].1, events[0].2), (false, false));
    assert_eq!((events[1].1, events[1].2), (true, false));
    assert_eq!((&*events[2].0, events[2].1, events[2].2), ("COMMIT", false, false));
    assert_eq!((&*events[3].0, events[3].1, events[3].2), ("COMMIT", true, true));
    drop(events);
    drop(observer);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn transaction_authority_fences_before_effects() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-authority")?;
    db.install_receive_ledger_schema()?;
    db.connection.execute(
        "INSERT INTO gateway_receive_epoch VALUES('t','e',1,x'',?1,?1)",
        params![0u64.to_be_bytes().as_slice()],
    )?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", &u64::MAX.to_string())?;
    let expected = ReceiveExpectation {
        target: "t",
        incarnation: "e",
        cursor: u64::MAX,
        generation: 4,
        erasure_generation: db.privacy_erasure_generation()?,
    };
    db.receive_transaction(expected, 4, |authority| {
        authority.require_writer()?;
        assert!(!db.connection.is_autocommit()?);
        Ok(())
    })?;
    for bad in [
        ReceiveExpectation { generation: 3, ..expected },
        ReceiveExpectation { incarnation: "other", ..expected },
        ReceiveExpectation { cursor: 0, ..expected },
    ] {
        let error = db
            .receive_transaction::<()>(bad, 4, |_| panic!("stale authority ran effects"))
            .expect_err("stale authority");
        assert!(matches!(error, StorageError::AuthorizationRejected), "{error:?}");
    }
    let error = db
        .receive_transaction::<()>(
            ReceiveExpectation { erasure_generation: -1, ..expected },
            4,
            |_| panic!("erased authority ran effects"),
        )
        .expect_err("erasure fence");
    assert!(matches!(error, StorageError::ObjectErased), "{error:?}");
    let error = db
        .receive_transaction(expected, 4, |_| {
            db.connection
                .execute("UPDATE account_erasure_generation SET generation=generation+1", [])?;
            Ok(())
        })
        .expect_err("late erasure must roll back the whole phase");
    assert!(matches!(error, StorageError::ObjectErased), "{error:?}");
    assert_eq!(db.privacy_erasure_generation()?, expected.erasure_generation);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn check_rejection(db: &AccountDb, sql: &str, rule: &str) {
    let error = db.connection.execute_batch(sql).expect_err("one-rule negative must fail");
    match error {
        rusqlite::Error::SqliteFailure(code, message) => {
            assert_eq!(code.extended_code, 275, "exact CHECK error");
            assert_eq!(
                message.as_deref(),
                Some(format!("CHECK constraint failed: {rule}").as_str())
            );
        }
        other => panic!("unexpected constraint error: {other:?}"),
    }
}

#[test]
fn schema_bounds_and_cross_fields() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-bounds")?;
    db.install_receive_ledger_schema()?;
    // Isolate work-key bounds; the foreign-key negative has its own fixture.
    db.connection.execute_batch("PRAGMA foreign_keys=OFF")?;
    for (table, column, insert) in [
        (
            "gateway_receive_receipt",
            "inbox_seq",
            "INSERT INTO gateway_receive_receipt VALUES('t','e',@SEQ@,'staged',0,0)",
        ),
        (
            "gateway_ack_intent",
            "inbox_seq",
            "INSERT INTO gateway_ack_intent VALUES('t','e',@SEQ@,0,0,0,0)",
        ),
        (
            "gateway_receive_work",
            "inbox_seq",
            "INSERT INTO gateway_receive_work VALUES('t','e',@SEQ@,x'','key',0)",
        ),
        (
            "gateway_inbox_loss",
            "from_seq",
            "INSERT INTO gateway_inbox_loss VALUES('t','e',@SEQ@,x'ffffffffffffffff',x'0000000000000001','expired',0,'unavailable')",
        ),
        (
            "gateway_inbox_loss",
            "count",
            "INSERT INTO gateway_inbox_loss VALUES('t','e',x'0000000000000001',x'0000000000000001',@SEQ@,'expired',0,'unavailable')",
        ),
    ] {
        for value in ["x'0000000000000000'", "x'01'", "x'000000000000000001'", "1"] {
            check_rejection(
                &db,
                &insert.replace("@SEQ@", value),
                &format!(
                    "typeof({column})='blob' AND length({column})=8 AND {column}>x'0000000000000000'"
                ),
            );
        }
        for value in ["x'0000000000000001'", "x'ffffffffffffffff'"] {
            if table == "gateway_receive_work" {
                db.connection.execute_batch(&format!(
                    "INSERT INTO gateway_receive_receipt VALUES('t','e',{value},'staged',0,0)"
                ))?;
            }
            db.connection.execute_batch(&insert.replace("@SEQ@", value))?;
            db.connection.execute_batch(&format!("DELETE FROM {table}"))?;
            if table == "gateway_receive_work" {
                db.connection.execute_batch("DELETE FROM gateway_receive_receipt")?;
            }
        }
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn schema_cross_fields_and_epoch_bounds() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-cross-fields")?;
    db.install_receive_ledger_schema()?;
    check_rejection(
        &db,
        "INSERT INTO gateway_inbox_loss VALUES('t','e',x'0000000000000002',x'0000000000000001',x'0000000000000001','expired',0,'unavailable')",
        "typeof(to_seq)='blob' AND length(to_seq)=8 AND to_seq>=from_seq",
    );
    for value in ["x'01'", "x'000000000000000001'", "1"] {
        check_rejection(
            &db,
            &format!(
                "INSERT INTO gateway_inbox_loss VALUES('t','e',x'0000000000000001',{value},x'0000000000000001','expired',0,'unavailable')"
            ),
            "typeof(to_seq)='blob' AND length(to_seq)=8 AND to_seq>=from_seq",
        );
    }
    check_rejection(
        &db,
        "INSERT INTO gateway_receive_receipt VALUES('t','e',x'0000000000000001','unknown',0,0)",
        "disposition IN ('staged','held','quarantined','completed','rejected','erased')",
    );
    for disposition in ["staged", "held", "quarantined", "completed", "rejected", "erased"] {
        db.connection.execute(
            "INSERT INTO gateway_receive_receipt VALUES('t','e',?1,?2,0,0)",
            params![1u64.to_be_bytes().as_slice(), disposition],
        )?;
        db.connection.execute_batch("DELETE FROM gateway_receive_receipt")?;
    }
    check_rejection(
        &db,
        "INSERT INTO gateway_ack_intent VALUES('t','e',x'0000000000000001',0,-1,0,0)",
        "attempts>=0",
    );
    for attempts in [0, i64::MAX] {
        db.connection.execute(
            "INSERT INTO gateway_ack_intent VALUES('t','e',?1,0,?2,0,0)",
            params![1u64.to_be_bytes().as_slice(), attempts],
        )?;
        db.connection.execute_batch("DELETE FROM gateway_ack_intent")?;
    }
    db.connection.execute_batch(
        "INSERT INTO gateway_receive_receipt VALUES('t','e',x'0000000000000001','staged',0,0)",
    )?;
    check_rejection(
        &db,
        "INSERT INTO gateway_receive_work VALUES('t','e',x'0000000000000001',x'','key',-1)",
        "byte_len>=0 AND byte_len=length(entry_json)",
    );
    check_rejection(
        &db,
        "INSERT INTO gateway_receive_work VALUES('t','e',x'0000000000000001',x'01','key',0)",
        "byte_len>=0 AND byte_len=length(entry_json)",
    );
    for bytes in [vec![], vec![1u8, 2, 3]] {
        db.connection.execute(
            "INSERT INTO gateway_receive_work VALUES('t','e',?1,?2,'key',?3)",
            params![1u64.to_be_bytes().as_slice(), bytes, bytes.len()],
        )?;
        db.connection.execute_batch("DELETE FROM gateway_receive_work")?;
    }
    for column in ["activated_cursor", "legacy_uncertain_through"] {
        for value in ["x'01'", "x'000000000000000001'", "1"] {
            let (a, b) = if column == "activated_cursor" {
                (value, "x'0000000000000000'")
            } else {
                ("x'0000000000000000'", value)
            };
            check_rejection(
                &db,
                &format!("INSERT INTO gateway_receive_epoch VALUES('t','e',1,x'',{a},{b})"),
                &format!("typeof({column})='blob' AND length({column})=8"),
            );
        }
    }
    check_rejection(
        &db,
        "INSERT INTO gateway_receive_epoch VALUES('t','e',2,x'',x'0000000000000000',x'0000000000000000')",
        "incarnation_verified IN (0,1)",
    );
    for verified in [0, 1] {
        for cursor in [0u64, u64::MAX] {
            db.connection.execute(
                "INSERT INTO gateway_receive_epoch VALUES('t','e',?1,x'',?2,?2)",
                params![verified, cursor.to_be_bytes().as_slice()],
            )?;
            db.connection.execute_batch("DELETE FROM gateway_receive_epoch")?;
        }
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn schema_work_requires_receipt() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-work-foreign-key")?;
    db.install_receive_ledger_schema()?;
    let error = db
        .connection
        .execute_batch(
            "INSERT INTO gateway_receive_work VALUES('t','e',x'0000000000000001',x'','key',0)",
        )
        .expect_err("valid work key with no receipt must fail only the foreign key");
    match error {
        rusqlite::Error::SqliteFailure(code, message) => {
            assert_eq!(code.extended_code, 787);
            assert_eq!(message.as_deref(), Some("FOREIGN KEY constraint failed"));
        }
        other => panic!("unexpected work foreign-key error: {other:?}"),
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
