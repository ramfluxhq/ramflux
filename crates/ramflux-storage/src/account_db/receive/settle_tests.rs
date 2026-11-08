// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WS below-C settlement: retained work survives later cover; crash cuts keep C frozen.
#![allow(clippy::expect_used, clippy::panic)]
use super::cover::{ReceiveCover, ReceiveCoverKind, ReceiveCoverResult};
use super::settle::{
    FaultKind, ReceiveSettle, ReceiveSettleKind as Kind, ReceiveSettleResult as Out,
    run as with_fault,
};
use super::stage_tests::{bytes, input, setup};
use super::*;
use crate::StorageError;
use rusqlite::params;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snap {
    cursor: u64,
    intents: Vec<u64>,
    work: Vec<u64>,
    receipts: Vec<(u64, String)>,
}

fn expect(db: &AccountDb, cursor: u64) -> Result<ReceiveExpectation<'_>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation: "e",
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn cover(
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    kind: ReceiveCoverKind,
) -> Result<ReceiveCoverResult, StorageError> {
    db.receive_transaction(expect(db, cursor)?, 1, |tx| {
        tx.cover(ReceiveCover { sequence, kind, gaps: &[] })
    })
}

fn stage(db: &AccountDb, cursor: u64, sequence: u64) -> Result<Vec<u8>, StorageError> {
    let wire = bytes(sequence);
    let result =
        db.receive_transaction(expect(db, cursor)?, 1, |tx| tx.stage(input(&wire, sequence)))?;
    match result {
        stage::ReceiveStageResult::Staged => Ok(wire),
        other => panic!("expected staged, got {other:?}"),
    }
}

fn settle(db: &AccountDb, cursor: u64, sequence: u64, kind: Kind) -> Result<Out, StorageError> {
    db.receive_transaction(expect(db, cursor)?, 1, |tx| tx.settle(ReceiveSettle { sequence, kind }))
}

fn due(db: &AccountDb, cursor: u64) -> Result<Vec<u64>, StorageError> {
    db.receive_transaction(expect(db, cursor)?, 1, |tx| tx.due_retained(64))
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

fn payload(db: &AccountDb, sequence: u64) -> Result<Vec<u8>, StorageError> {
    Ok(db.connection.query_row(
        "SELECT entry_json FROM gateway_receive_work WHERE target_delivery_id='t' AND incarnation_id='e' AND inbox_seq=?1",
        params![sequence.to_be_bytes().as_slice()],
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

fn assert_fault(result: Result<Out, StorageError>) {
    match result {
        Err(StorageError::Integrity("receive settle before-commit")) => {}
        other => panic!("expected before-commit, got {other:?}"),
    }
}

fn hold_then_advance(db: &AccountDb) -> Result<(Vec<u8>, Snap), StorageError> {
    let original = stage(db, 0, 1)?;
    assert_eq!(cover(db, 0, 1, ReceiveCoverKind::Held)?, ReceiveCoverResult::Covered);
    let held = snap(db)?;
    assert_eq!(held.cursor, 1);
    assert_eq!(held.work, vec![1]);
    assert_eq!(held.intents, Vec::<u64>::new());
    assert_eq!(held.receipts, vec![(1, "held".into())]);
    stage(db, 1, 2)?;
    assert_eq!(cover(db, 1, 2, ReceiveCoverKind::Terminal)?, ReceiveCoverResult::Covered);
    let advanced = snap(db)?;
    assert_eq!(advanced.cursor, 2);
    assert_eq!(advanced.work, vec![1], "held W2 keeps seq1 work");
    assert_eq!(advanced.intents, vec![2]);
    assert_eq!(advanced.receipts, vec![(1, "held".into())]);
    assert_eq!(payload(db, 1)?, original, "router dead-letter does not drop the local copy");
    assert_eq!(due(db, 2)?, vec![1]);
    Ok((original, advanced))
}

#[test]
fn held_below_cursor_settles() -> Result<(), StorageError> {
    let (root, db) = setup("ws-held")?;
    let (_original, advanced) = hold_then_advance(&db)?;
    assert_eq!(settle(&db, 2, 1, Kind::Terminal)?, Out::Settled);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 2, "WS never moves C");
    assert_eq!(done.intents, vec![1, 2], "one eventual intent for the held sequence");
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.receipts, Vec::<(u64, String)>::new());
    assert_eq!(due(&db, 2)?, Vec::<u64>::new());
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done, "reopen keeps the terminal intent and frozen C");
    assert_eq!(
        settle(&db, 2, 1, Kind::Terminal)?,
        Out::Settled,
        "already-settled WS is idempotent"
    );
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    let _ = advanced;
    Ok(())
}

#[test]
fn retry_settlement_atomic() -> Result<(), StorageError> {
    let (root, db) = setup("ws-atomic")?;
    let (_original, pre) = hold_then_advance(&db)?;
    assert_fault(with_fault(FaultKind::BeforeCommit, || settle(&db, 2, 1, Kind::Terminal)));
    assert_eq!(snap(&db)?, pre, "before-commit keeps work, omits seq1 intent, freezes C");
    assert_ne!(payload(&db, 1)?, Vec::<u8>::new());
    assert_eq!(settle(&db, 2, 1, Kind::Terminal)?, Out::Settled);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 2);
    assert_eq!(done.intents, vec![1, 2]);
    assert_eq!(done.work, Vec::<u64>::new());
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done, "after commit the intent survives reopen and C stays");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn above_cursor_delegates_and_inactive_is_local() -> Result<(), StorageError> {
    let (root, db) = setup("ws-delegate")?;
    hold_then_advance(&db)?;
    stage(&db, 2, 3)?;
    assert_eq!(settle(&db, 2, 3, Kind::Terminal)?, Out::Settled);
    let covered = snap(&db)?;
    assert_eq!(covered.cursor, 3, "s=C+1 is ordered W2 and advances C");
    assert_eq!(covered.intents, vec![2, 3]);
    assert_eq!(covered.work, vec![1]);

    let jump = settle(&db, 3, 5, Kind::Terminal);
    assert!(
        matches!(jump, Err(StorageError::Integrity("receive cover interval outside page"))),
        "{jump:?}"
    );
    assert_eq!(snap(&db)?.cursor, 3);

    db.connection.execute(
        "UPDATE gateway_receive_epoch SET incarnation_verified=0 WHERE target_delivery_id='t'",
        [],
    )?;
    assert_eq!(settle(&db, 3, 1, Kind::Terminal)?, Out::Settled);
    let local = snap(&db)?;
    assert_eq!(local.cursor, 3, "inactive E below-C settle never writes C");
    assert_eq!(local.intents, vec![1, 2, 3]);
    assert_eq!(local.work, Vec::<u64>::new());

    stage(&db, 3, 4)?;
    let above = settle(&db, 3, 4, Kind::Terminal);
    assert!(
        matches!(
            above,
            Err(StorageError::Integrity("inactive incarnation allows local recovery only"))
        ),
        "{above:?}"
    );
    assert_eq!(snap(&db)?.cursor, 3);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
