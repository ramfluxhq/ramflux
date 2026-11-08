// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P08 first-leg cells: expiry/eviction and failure-policy admission crash cuts.
#![allow(clippy::expect_used, clippy::panic)]
use super::cover::{ReceiveCover, ReceiveCoverKind, ReceiveCoverResult};
use super::removal::{
    FaultKind, ReceiveFailure, ReceiveFailureKind as FailKind, ReceiveFailureResult as FailOut,
    run as with_fault,
};
use super::stage::{ReceiveStage, ReceiveStageResult};
use super::stage_tests::{bytes, setup};
use super::*;
use crate::{ProjectionStore, StorageError};
use rusqlite::params;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snap {
    cursor: u64,
    intents: Vec<u64>,
    work: Vec<u64>,
    receipts: Vec<(u64, String)>,
}

fn expect(db: &AccountDb, cursor: u64) -> Result<ReceiveExpectation<'static>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation: "e",
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn stage(db: &AccountDb, cursor: u64, sequence: u64, key: &str) -> Result<Vec<u8>, StorageError> {
    let wire = bytes(sequence);
    let result = db.receive_transaction(expect(db, cursor)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation: "e",
            sequence,
            entry_json: &wire,
            admission_key: key,
            retain_until: 100,
            first_seen: i64::try_from(sequence).unwrap_or(i64::MAX),
        })
    })?;
    assert!(matches!(result, ReceiveStageResult::Staged | ReceiveStageResult::Existing));
    Ok(wire)
}

fn cover_held(db: &AccountDb, cursor: u64, sequence: u64) -> Result<(), StorageError> {
    let out = db.receive_transaction(expect(db, cursor)?, 1, |tx| {
        tx.cover(ReceiveCover {
            sequence,
            kind: ReceiveCoverKind::Held,
            gaps: &[],
            retain_until: 0,
        })
    })?;
    assert_eq!(out, ReceiveCoverResult::Covered);
    Ok(())
}

fn admit(db: &AccountDb, cursor: u64, input: ReceiveFailure<'_>) -> Result<FailOut, StorageError> {
    db.receive_transaction(expect(db, cursor)?, 1, |tx| tx.admit_failure(input))
}

fn expire_tx(db: &AccountDb, cursor: u64, at: i64) -> Result<Vec<u64>, StorageError> {
    db.receive_transaction(expect(db, cursor)?, 1, |tx| tx.expire_holds(at))
}

fn snap(db: &AccountDb) -> Result<Snap, StorageError> {
    let cursor = db
        .projection_checkpoint("gateway_receive_cursor:t")?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?;
    Ok(Snap {
        cursor,
        intents: seqs(
            db,
            "SELECT inbox_seq FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq",
        )?,
        work: seqs(
            db,
            "SELECT inbox_seq FROM gateway_receive_work WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq",
        )?,
        receipts: {
            let mut out = Vec::new();
            let mut query = db.connection.prepare(
                "SELECT inbox_seq,disposition FROM gateway_receive_receipt WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq",
            )?;
            for row in query.query_map([], |row| Ok((be(row.get(0)?), row.get(1)?)))? {
                out.push(row?);
            }
            out
        },
    })
}

fn seqs(db: &AccountDb, sql: &str) -> Result<Vec<u64>, StorageError> {
    let mut query = db.connection.prepare(sql)?;
    let rows = query.query_map([], |row| Ok(be(row.get(0)?)))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(StorageError::from)
}

fn be(bytes: Vec<u8>) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("be-u64"))
}

fn failure_count(db: &AccountDb, reason: &str) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='inbox.receive_failure'
           AND json_extract(CAST(body_json AS TEXT),'$.reason')=?1",
        params![reason],
        |row| row.get(0),
    )?)
}

fn retry_count(db: &AccountDb, key: &str) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM runtime_inbox_retry WHERE envelope_key=?1",
        params![key],
        |row| row.get(0),
    )?)
}

fn reopen(root: &std::path::Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &crate::AccountIndex::open(root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn assert_fault(result: Result<impl std::fmt::Debug, StorageError>) {
    match result {
        Err(StorageError::Integrity(
            "receive failure before-commit" | "receive settle before-commit",
        )) => {}
        other => panic!("expected before-commit, got {other:?}"),
    }
}

fn fill_unrouted_holds(db: &AccountDb, n: u64) -> Result<u64, StorageError> {
    let mut cursor = 0u64;
    for sequence in 1..=n {
        let key = format!("k{sequence}");
        let wire = stage(db, cursor, sequence, &key)?;
        cover_held(db, cursor, sequence)?;
        db.hold_unrouted(&key, sequence, &wire, i64::try_from(sequence).expect("at"))?;
        cursor = sequence;
    }
    Ok(cursor)
}

#[test]
fn held_local_expiry_and_eviction_crash() -> Result<(), StorageError> {
    eviction_cut()?;
    expire_cut()?;
    dead_letter_cut()?;
    contact_expiry_cut()?;
    retired_expiry_cut()?;
    Ok(())
}

fn eviction_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-evict")?;
    let cursor = fill_unrouted_holds(&db, 64)?;
    assert_eq!(cursor, 64);
    assert_eq!(db.unrouted_count()?, 64);
    let pre = snap(&db)?;
    assert_eq!(pre.cursor, 64);
    assert_eq!(pre.work.len(), 64);
    let extra = bytes(65);
    assert_fault(super::settle::run(super::settle::FaultKind::BeforeCommit, || {
        db.hold_unrouted("k65", 65, &extra, 65)
    }));
    assert_eq!(snap(&db)?, pre, "eviction pause keeps C/work/receipt");
    db.hold_unrouted("k65", 65, &extra, 65)?;
    let done = snap(&db)?;
    assert_eq!(done.cursor, 64, "eviction is WS below C");
    assert_eq!(done.work.len(), 63);
    assert!(!done.work.contains(&1), "oldest hold is settled");
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "held_evicted")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    assert_eq!(failure_count(&db, "held_evicted")?, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn expire_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-expire")?;
    let wire = stage(&db, 0, 1, "exp")?;
    cover_held(&db, 0, 1)?;
    db.hold_unrouted("exp", 1, &wire, 1)?;
    db.defer_inbox_entry("exp", &wire, 1)?;
    db.connection
        .execute("UPDATE runtime_inbox_policy SET expires_at=10 WHERE envelope_key='exp'", [])?;
    let pre = snap(&db)?;
    assert_eq!(pre.cursor, 1);
    assert_eq!(pre.work, vec![1]);
    assert_fault(super::settle::run(super::settle::FaultKind::BeforeCommit, || {
        db.expire_inbox_holds(20)
    }));
    assert_eq!(snap(&db)?, pre);
    db.expire_inbox_holds(20)?;
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "held_expired")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn dead_letter_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-dead")?;
    let wire = stage(&db, 0, 1, "dead")?;
    cover_held(&db, 0, 1)?;
    let pre = snap(&db)?;
    assert_fault(super::settle::run(super::settle::FaultKind::BeforeCommit, || {
        db.dead_letter_inbox(
            "dead",
            &wire,
            &serde_json::json!({"error_code":"authentication_failed"}),
            50,
        )
    }));
    assert_eq!(snap(&db)?, pre);
    db.dead_letter_inbox(
        "dead",
        &wire,
        &serde_json::json!({"error_code":"authentication_failed"}),
        50,
    )?;
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "policy_rejected")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn contact_expiry_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-contact")?;
    stage(&db, 0, 1, "contact")?;
    cover_held(&db, 0, 1)?;
    db.connection.execute(
        "INSERT INTO runtime_inbox_policy VALUES('contact','root/device',1,1,10,0,'receive_hold_contact','contact-root',0,0)",
        [],
    )?;
    let pre = snap(&db)?;
    assert_fault(with_fault(FaultKind::BeforeCommit, || expire_tx(&db, 1, 20)));
    assert_eq!(snap(&db)?, pre);
    assert_eq!(expire_tx(&db, 1, 20)?, vec![1]);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "held_expired")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn retired_expiry_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-retired")?;
    stage(&db, 0, 1, "ret")?;
    cover_held(&db, 0, 1)?;
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET incarnation_id='live', retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&["e"])?],
    )?;
    let pre = snap(&db)?;
    assert_eq!(pre.cursor, 1);
    assert_eq!(pre.work, vec![1]);
    assert_eq!(pre.intents, Vec::<u64>::new());
    assert_fault(with_fault(FaultKind::BeforeCommit, || expire_tx(&db, 1, 200)));
    assert_eq!(snap(&db)?, pre, "retired expiry pause keeps work and writes no intent");
    assert_eq!(expire_tx(&db, 1, 200)?, vec![1]);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1, "retired E never writes C");
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, Vec::<u64>::new(), "retired E never writes an ACK intent");
    assert_eq!(failure_count(&db, "held_expired")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn failure_policy_stage_crash() -> Result<(), StorageError> {
    retryable_cut()?;
    deterministic_cut()?;
    exhausted_cut()?;
    Ok(())
}

fn retryable_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-retry")?;
    let wire = stage(&db, 0, 1, "retry")?;
    let pre = snap(&db)?;
    assert_eq!(pre.work, vec![1]);
    assert_eq!(pre.receipts, vec![(1, "staged".into())]);
    let input = ReceiveFailure {
        sequence: 1,
        admission_key: "retry",
        entry: &wire,
        kind: FailKind::Retryable,
        error_code: "directory_miss",
        at: 1,
    };
    assert_fault(with_fault(FaultKind::BeforeCommit, || admit(&db, 0, input)));
    assert_eq!(snap(&db)?, pre, "W0 survives a failed retryable admission");
    assert_eq!(retry_count(&db, "retry")?, 0);
    assert_eq!(admit(&db, 0, input)?, FailOut::Held);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, vec![1]);
    assert_eq!(done.receipts, vec![(1, "held".into())]);
    assert_eq!(done.intents, Vec::<u64>::new());
    assert_eq!(retry_count(&db, "retry")?, 1);
    assert_eq!(failure_count(&db, "policy_rejected")?, 0);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn deterministic_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-det")?;
    let wire = stage(&db, 0, 1, "det")?;
    let pre = snap(&db)?;
    let input = ReceiveFailure {
        sequence: 1,
        admission_key: "det",
        entry: &wire,
        kind: FailKind::Deterministic,
        error_code: "authentication_failed",
        at: 1,
    };
    assert_fault(with_fault(FaultKind::BeforeCommit, || admit(&db, 0, input)));
    assert_eq!(snap(&db)?, pre);
    assert_eq!(admit(&db, 0, input)?, FailOut::Rejected);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "policy_rejected")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn exhausted_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-exh")?;
    let wire = stage(&db, 0, 1, "exh")?;
    let input = ReceiveFailure {
        sequence: 1,
        admission_key: "exh",
        entry: &wire,
        kind: FailKind::Exhausted,
        error_code: "retry_exhausted",
        at: 1,
    };
    assert_eq!(admit(&db, 0, input)?, FailOut::Rejected);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "policy_rejected")?, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
