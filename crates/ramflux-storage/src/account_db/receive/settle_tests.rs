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
use crate::{ProjectionStore, StorageError};
use rusqlite::params;
use serde_json::json;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Intent {
    seq: u64,
    created_at: i64,
    next_attempt_at: i64,
    expires_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snap {
    cursor: u64,
    intents: Vec<Intent>,
    work: Vec<u64>,
    receipts: Vec<(u64, String)>,
}

fn expect<'a>(
    db: &AccountDb,
    incarnation: &'a str,
    cursor: u64,
) -> Result<ReceiveExpectation<'a>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation,
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
    cover_as(db, "e", cursor, sequence, kind)
}

fn cover_as(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    sequence: u64,
    kind: ReceiveCoverKind,
) -> Result<ReceiveCoverResult, StorageError> {
    db.receive_transaction(expect(db, incarnation, cursor)?, 1, |tx| {
        tx.cover(ReceiveCover { sequence, kind, gaps: &[], retain_until: 0 })
    })
}

fn stage(db: &AccountDb, cursor: u64, sequence: u64) -> Result<Vec<u8>, StorageError> {
    let wire = bytes(sequence);
    let result =
        db.receive_transaction(expect(db, "e", cursor)?, 1, |tx| tx.stage(input(&wire, sequence)))?;
    match result {
        stage::ReceiveStageResult::Staged => Ok(wire),
        other => panic!("expected staged, got {other:?}"),
    }
}

fn settle(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    sequence: u64,
    kind: Kind,
) -> Result<Out, StorageError> {
    db.receive_transaction(expect(db, incarnation, cursor)?, 1, |tx| {
        tx.settle(ReceiveSettle { sequence, kind })
    })
}

fn due(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    limit: u32,
) -> Result<Vec<u64>, StorageError> {
    db.receive_transaction(expect(db, incarnation, cursor)?, 1, |tx| tx.due_retained(limit))
}

fn snap(db: &AccountDb, incarnation: &str) -> Result<Snap, StorageError> {
    let cursor = db
        .projection_checkpoint("gateway_receive_cursor:t")?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?;
    Ok(Snap {
        cursor,
        intents: {
            let mut out = Vec::new();
            let mut query = db.connection.prepare(
                "SELECT inbox_seq,created_at,next_attempt_at,expires_at FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id=?1 ORDER BY inbox_seq",
            )?;
            for row in query.query_map(params![incarnation], |row| {
                Ok(Intent {
                    seq: be(row.get(0)?),
                    created_at: row.get(1)?,
                    next_attempt_at: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            })? {
                out.push(row?);
            }
            out
        },
        work: seqs(
            db,
            "SELECT inbox_seq FROM gateway_receive_work WHERE target_delivery_id='t' AND incarnation_id=?1 ORDER BY inbox_seq",
            incarnation,
        )?,
        receipts: {
            let mut out = Vec::new();
            let mut query = db.connection.prepare(
                "SELECT inbox_seq,disposition FROM gateway_receive_receipt WHERE target_delivery_id='t' AND incarnation_id=?1 ORDER BY inbox_seq",
            )?;
            for row in
                query.query_map(params![incarnation], |row| Ok((be(row.get(0)?), row.get(1)?)))?
            {
                out.push(row?);
            }
            out
        },
    })
}

fn seqs(db: &AccountDb, sql: &str, incarnation: &str) -> Result<Vec<u64>, StorageError> {
    let mut query = db.connection.prepare(sql)?;
    let rows = query.query_map(params![incarnation], |row| Ok(be(row.get(0)?)))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(StorageError::from)
}

fn intent_seqs(snap: &Snap) -> Vec<u64> {
    snap.intents.iter().map(|intent| intent.seq).collect()
}

fn assert_intent_times(snap: &Snap) {
    for intent in &snap.intents {
        assert_eq!(intent.next_attempt_at, intent.created_at);
        assert_eq!(intent.expires_at, intent.created_at.saturating_add(604_800));
    }
}

fn be(bytes: Vec<u8>) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("be-u64"))
}

fn payload(db: &AccountDb, incarnation: &str, sequence: u64) -> Result<Vec<u8>, StorageError> {
    Ok(db.connection.query_row(
        "SELECT entry_json FROM gateway_receive_work WHERE target_delivery_id='t' AND incarnation_id=?1 AND inbox_seq=?2",
        params![incarnation, sequence.to_be_bytes().as_slice()],
        |row| row.get(0),
    )?)
}

fn retain_until(db: &AccountDb, incarnation: &str, sequence: u64) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT retain_until FROM gateway_receive_receipt WHERE target_delivery_id='t' AND incarnation_id=?1 AND inbox_seq=?2",
        params![incarnation, sequence.to_be_bytes().as_slice()],
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

fn assert_integrity(result: Result<Out, StorageError>, text: &str) {
    match result {
        Err(StorageError::Integrity(got)) if got == text => {}
        other => panic!("expected Integrity({text:?}), got {other:?}"),
    }
}

fn dead_letter(db: &AccountDb, sequence: u64) -> Result<(), StorageError> {
    db.append_journal(
        &format!("receive-dead-letter:t:e:{sequence}"),
        "inbox.unrouted",
        &json!({"sequence": sequence, "reason": "router_dead_letter"}),
        crate::unix_now(),
        None,
    )?;
    Ok(())
}

fn hold_then_advance(db: &AccountDb) -> Result<(Vec<u8>, Snap), StorageError> {
    let original = stage(db, 0, 1)?;
    assert_eq!(cover(db, 0, 1, ReceiveCoverKind::Held)?, ReceiveCoverResult::Covered);
    let held = snap(db, "e")?;
    assert_eq!(held.cursor, 1);
    assert_eq!(held.work, vec![1]);
    assert_eq!(intent_seqs(&held), Vec::<u64>::new());
    assert_eq!(held.receipts, vec![(1, "held".into())]);
    stage(db, 1, 2)?;
    assert_eq!(cover(db, 1, 2, ReceiveCoverKind::Terminal)?, ReceiveCoverResult::Covered);
    let advanced = snap(db, "e")?;
    assert_eq!(advanced.cursor, 2);
    assert_eq!(advanced.work, vec![1], "held W2 keeps seq1 work");
    assert_eq!(intent_seqs(&advanced), vec![2]);
    assert_intent_times(&advanced);
    assert_eq!(advanced.receipts, vec![(1, "held".into())]);
    dead_letter(db, 1)?;
    assert_eq!(payload(db, "e", 1)?, original, "router dead-letter does not drop the local copy");
    assert_eq!(due(db, "e", 2, 64)?, vec![1]);
    Ok((original, advanced))
}

fn put_row(
    db: &AccountDb,
    incarnation: &str,
    sequence: u64,
    disposition: &str,
    work: bool,
) -> Result<(), StorageError> {
    let seq = sequence.to_be_bytes();
    let wire = bytes(sequence);
    db.connection.execute(
        "INSERT INTO gateway_receive_receipt VALUES('t',?1,?2,?3,100,1)",
        params![incarnation, seq.as_slice(), disposition],
    )?;
    if work {
        db.connection.execute(
            "INSERT INTO gateway_receive_work VALUES('t',?1,?2,?3,'authenticated-key',?4)",
            params![
                incarnation,
                seq.as_slice(),
                wire,
                i64::try_from(wire.len()).expect("bounded fixture")
            ],
        )?;
    }
    Ok(())
}

#[test]
fn held_below_cursor_settles() -> Result<(), StorageError> {
    let (root, db) = setup("ws-held")?;
    let (_original, advanced) = hold_then_advance(&db)?;
    assert_eq!(settle(&db, "e", 2, 1, Kind::Terminal)?, Out::Settled);
    let done = snap(&db, "e")?;
    assert_eq!(done.cursor, 2, "WS never moves C");
    assert_eq!(intent_seqs(&done), vec![1, 2], "one eventual intent for the held sequence");
    assert_intent_times(&done);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.receipts, Vec::<(u64, String)>::new());
    assert_eq!(due(&db, "e", 2, 64)?, Vec::<u64>::new());
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db, "e")?, done, "reopen keeps the terminal intent and frozen C");
    assert_eq!(
        settle(&db, "e", 2, 1, Kind::Terminal)?,
        Out::Settled,
        "already-settled WS is idempotent"
    );
    assert_eq!(snap(&db, "e")?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    let _ = advanced;
    Ok(())
}

#[test]
fn retry_settlement_atomic() -> Result<(), StorageError> {
    let (root, db) = setup("ws-atomic")?;
    let (_original, pre) = hold_then_advance(&db)?;
    assert_fault(with_fault(FaultKind::BeforeCommit, || settle(&db, "e", 2, 1, Kind::Terminal)));
    assert_eq!(snap(&db, "e")?, pre, "before-commit keeps work, omits seq1 intent, freezes C");
    assert_ne!(payload(&db, "e", 1)?, Vec::<u8>::new());
    assert_eq!(settle(&db, "e", 2, 1, Kind::Terminal)?, Out::Settled);
    let done = snap(&db, "e")?;
    assert_eq!(done.cursor, 2);
    assert_eq!(intent_seqs(&done), vec![1, 2]);
    assert_intent_times(&done);
    assert_eq!(done.work, Vec::<u64>::new());
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db, "e")?, done, "after commit the intent survives reopen and C stays");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn above_cursor_delegates_and_inactive_is_local() -> Result<(), StorageError> {
    let (root, db) = setup("ws-delegate")?;
    hold_then_advance(&db)?;
    stage(&db, 2, 3)?;
    assert_eq!(settle(&db, "e", 2, 3, Kind::Terminal)?, Out::Settled);
    let covered = snap(&db, "e")?;
    assert_eq!(covered.cursor, 3, "s=C+1 is ordered W2 and advances C");
    assert_eq!(intent_seqs(&covered), vec![2, 3]);
    assert_intent_times(&covered);
    assert_eq!(covered.work, vec![1]);

    let jump = settle(&db, "e", 3, 5, Kind::Terminal);
    assert!(
        matches!(jump, Err(StorageError::Integrity("receive cover interval outside page"))),
        "{jump:?}"
    );
    assert_eq!(snap(&db, "e")?.cursor, 3);

    db.connection.execute(
        "UPDATE gateway_receive_epoch SET incarnation_verified=0 WHERE target_delivery_id='t'",
        [],
    )?;
    stage(&db, 3, 4)?;
    assert_eq!(
        settle(&db, "e", 3, 4, Kind::Terminal)?,
        Out::Settled,
        "compat U (verified=0) still covers above C"
    );
    let live_u = snap(&db, "e")?;
    assert_eq!(live_u.cursor, 4);
    assert_eq!(intent_seqs(&live_u), vec![2, 3, 4]);

    put_row(&db, "old", 1, "held", true)?;
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&["old"])?],
    )?;
    assert_eq!(settle(&db, "old", 4, 1, Kind::Terminal)?, Out::Settled);
    let retired = snap(&db, "old")?;
    assert_eq!(retired.cursor, 4, "retired E below-C settle never writes C");
    assert_eq!(intent_seqs(&retired), Vec::<u64>::new(), "retired E never writes an ACK intent");
    assert_eq!(retired.work, Vec::<u64>::new());
    assert_eq!(retired.receipts, Vec::<(u64, String)>::new());
    assert_eq!(intent_seqs(&snap(&db, "e")?), vec![2, 3, 4]);

    put_row(&db, "old", 5, "staged", true)?;
    assert_eq!(due(&db, "old", 4, 64)?, vec![5], "retired due_retained ignores the active C");
    assert_eq!(
        settle(&db, "old", 4, 5, Kind::Terminal)?,
        Out::Settled,
        "retired E with s>C still cleans up locally"
    );
    let retired_above = snap(&db, "old")?;
    assert_eq!(retired_above.cursor, 4, "retired E never writes C");
    assert_eq!(intent_seqs(&retired_above), Vec::<u64>::new());
    assert_eq!(retired_above.work, Vec::<u64>::new());
    assert_eq!(retired_above.receipts, Vec::<(u64, String)>::new());
    assert_eq!(snap(&db, "e")?.cursor, 4);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn retired_incarnation_refuses_cover_and_stage() -> Result<(), StorageError> {
    let (root, db) = setup("ws-retired-fence")?;
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&["old"])?],
    )?;
    put_row(&db, "old", 1, "staged", true)?;
    let before = snap(&db, "old")?;
    match cover_as(&db, "old", 0, 1, ReceiveCoverKind::Terminal) {
        Err(StorageError::Integrity(super::RETIRED_INCARNATION)) => {}
        other => panic!("cover under retired E: {other:?}"),
    }
    assert_eq!(snap(&db, "old")?, before, "retired cover writes nothing");
    assert_eq!(snap(&db, "e")?.cursor, 0, "retired cover must not move C");
    assert_eq!(intent_seqs(&snap(&db, "e")?), Vec::<u64>::new());

    let wire = bytes(2);
    let mut page = input(&wire, 2);
    page.incarnation = "old";
    match db.receive_transaction(expect(&db, "old", 0)?, 1, |tx| tx.stage(page)) {
        Err(StorageError::Integrity(super::RETIRED_INCARNATION)) => {}
        other => panic!("stage under retired E: {other:?}"),
    }
    assert_eq!(snap(&db, "old")?.work, vec![1], "retired stage writes no new work");

    match db.receive_transaction(expect(&db, "old", 0)?, 1, |tx| tx.require_open_input(1)) {
        Err(StorageError::Integrity(super::RETIRED_INCARNATION)) => {}
        other => panic!("source gate under retired E: {other:?}"),
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn held_below_cursor_keeps_hold() -> Result<(), StorageError> {
    let (root, db) = setup("ws-keep-held")?;
    hold_then_advance(&db)?;
    let until = retain_until(&db, "e", 1)?;
    let pre = snap(&db, "e")?;
    assert_eq!(settle(&db, "e", 2, 1, Kind::Held)?, Out::Held);
    let kept = snap(&db, "e")?;
    assert_eq!(kept, pre, "Held below C leaves work, receipt and C");
    assert_eq!(retain_until(&db, "e", 1)?, until, "keep_held must not overwrite retain_until");

    db.set_projection_checkpoint("gateway_receive_cursor:t", "4")?;
    put_row(&db, "e", 3, "staged", true)?;
    assert_eq!(settle(&db, "e", 4, 3, Kind::Held)?, Out::Held);
    assert_eq!(
        snap(&db, "e")?.receipts.iter().find(|row| row.0 == 3).map(|row| row.1.as_str()),
        Some("held")
    );
    assert_eq!(retain_until(&db, "e", 3)?, 100);

    put_row(&db, "e", 4, "quarantined", true)?;
    assert_eq!(settle(&db, "e", 4, 4, Kind::Held)?, Out::Held);
    assert_eq!(
        snap(&db, "e")?.receipts.iter().find(|row| row.0 == 4).map(|row| row.1.as_str()),
        Some("quarantined")
    );
    assert_eq!(retain_until(&db, "e", 4)?, 100);
    assert_eq!(snap(&db, "e")?.cursor, 4);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn erased_receipt_settles() -> Result<(), StorageError> {
    let (root, db) = setup("ws-erased")?;
    hold_then_advance(&db)?;
    put_row(&db, "e", 5, "erased", false)?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "5")?;
    assert_eq!(due(&db, "e", 5, 64)?, vec![1, 5]);
    assert_eq!(settle(&db, "e", 5, 5, Kind::Terminal)?, Out::Settled);
    let done = snap(&db, "e")?;
    assert_eq!(done.cursor, 5);
    assert!(intent_seqs(&done).contains(&5));
    assert_intent_times(&done);
    assert!(!done.receipts.iter().any(|row| row.0 == 5));
    assert_eq!(due(&db, "e", 5, 64)?, vec![1]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn existing_intent_still_cleans_up() -> Result<(), StorageError> {
    let (root, db) = setup("ws-intent-cleanup")?;
    let (original, _) = hold_then_advance(&db)?;
    assert_eq!(settle(&db, "e", 2, 1, Kind::Terminal)?, Out::Settled);
    let after = snap(&db, "e")?;
    db.receive_transaction(expect(&db, "e", 2)?, 1, |tx| tx.stage(input(&original, 1)))?;
    assert_eq!(snap(&db, "e")?.work, vec![1]);
    assert_eq!(settle(&db, "e", 2, 1, Kind::Terminal)?, Out::Settled);
    let cleaned = snap(&db, "e")?;
    assert_eq!(intent_seqs(&cleaned), intent_seqs(&after));
    assert_eq!(cleaned.intents, after.intents, "existing intent timestamps stay");
    assert_eq!(cleaned.work, Vec::<u64>::new());
    assert_eq!(cleaned.receipts, Vec::<(u64, String)>::new());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn settle_negatives_and_due_cap() -> Result<(), StorageError> {
    let (root, db) = setup("ws-negatives")?;
    assert_integrity(settle(&db, "e", 0, 0, Kind::Terminal), "receive sequence must be positive");
    assert_integrity(settle(&db, "e", 0, 0, Kind::Held), "receive sequence must be positive");
    db.set_projection_checkpoint("gateway_receive_cursor:t", "1")?;
    assert_integrity(settle(&db, "e", 1, 1, Kind::Terminal), "settle requires retained work");
    assert_integrity(settle(&db, "e", 1, 1, Kind::Held), "settle requires retained work");
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&["old"])?],
    )?;
    assert_integrity(settle(&db, "old", 1, 1, Kind::Terminal), "settle requires retained work");

    db.set_projection_checkpoint("gateway_receive_cursor:t", "65")?;
    for sequence in 1..=65 {
        put_row(&db, "e", sequence, "held", true)?;
    }
    assert_eq!(due(&db, "e", 65, 64)?.len(), 64);
    assert_eq!(due(&db, "e", 65, 65)?.len(), 64);
    assert_eq!(due(&db, "e", 65, 64)?, (1..=64).collect::<Vec<_>>());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
