// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! W2 atomic cover: loss, unpublished gap outbox, intent, cleanup and C.
#![allow(clippy::expect_used, clippy::panic)]
use super::cover::{
    FaultKind, ReceiveCover, ReceiveCoverKind as Kind, ReceiveCoverResult as Out, ReceiveGap,
    run as with_fault,
};
use super::stage_tests::{bytes, input, setup};
use super::*;
use crate::{ProjectionStore, StorageError};
use rusqlite::params;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Snap {
    pub(super) cursor: u64,
    losses: Vec<(u64, u64, u64, String, i64, String)>,
    outbox: Vec<String>,
    intents: Vec<(u64, i64, i64, i64)>,
    work: Vec<u64>,
    receipts: Vec<(u64, String)>,
}

pub(super) fn gap(from: u64, to: u64) -> ReceiveGap<'static> {
    ReceiveGap { from_seq: from, to_seq: to, reason: "expired", classification: "unavailable" }
}

fn gap_keys(from: u64, to: u64, count: u64, reason: &str, classification: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "source_key": format!("receive-gap:t:e:{from}:{to}"),
        "target": "t",
        "incarnation": "e",
        "from_seq": from,
        "to_seq": to,
        "count": count,
        "reason": reason,
        "classification": classification,
    }))
    .expect("gap keys")
}

fn slots(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM (
           SELECT incarnation_id,inbox_seq FROM gateway_ack_intent WHERE target_delivery_id='t'
           UNION
           SELECT incarnation_id,inbox_seq FROM gateway_receive_receipt WHERE target_delivery_id='t'
         )",
        [],
        |row| row.get(0),
    )?)
}

fn insert_receipt(db: &AccountDb, sequence: u64, disposition: &str) -> Result<(), StorageError> {
    db.write_transaction(|| {
        db.connection.execute(
            "INSERT INTO gateway_receive_receipt VALUES('t','e',?1,?2,100,1)",
            params![sequence.to_be_bytes().as_slice(), disposition],
        )?;
        Ok(())
    })
}

fn assert_refused(
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    kind: Kind,
    gaps: &[ReceiveGap<'_>],
    error: &'static str,
) -> Result<(), StorageError> {
    let pre = snap(db)?;
    let result = cover(db, cursor, sequence, kind, gaps);
    match result {
        Err(StorageError::Integrity(found)) if found == error => {}
        other => panic!("expected {error}, got {other:?}"),
    }
    assert_eq!(snap(db)?, pre, "refused cover writes nothing");
    Ok(())
}

pub(super) fn alternating(from: u64, count: usize) -> Vec<ReceiveGap<'static>> {
    const REASONS: [&str; 2] = ["expired", "nacked"];
    (0..count)
        .map(|i| {
            let seq = from + i as u64;
            ReceiveGap {
                from_seq: seq,
                to_seq: seq,
                reason: REASONS[i % 2],
                classification: "unavailable",
            }
        })
        .collect()
}

pub(super) fn cover(
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    kind: Kind,
    gaps: &[ReceiveGap<'_>],
) -> Result<Out, StorageError> {
    db.receive_transaction(
        ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        1,
        |tx| tx.cover(ReceiveCover { sequence, kind, gaps, retain_until: 0 }),
    )
}

fn stage(db: &AccountDb, cursor: u64, sequence: u64) -> Result<(), StorageError> {
    let wire = bytes(sequence);
    let result = db.receive_transaction(
        ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        1,
        |tx| tx.stage(input(&wire, sequence)),
    )?;
    match result {
        stage::ReceiveStageResult::Staged => Ok(()),
        other => panic!("expected staged, got {other:?}"),
    }
}

pub(super) fn snap(db: &AccountDb) -> Result<Snap, StorageError> {
    let cursor = db
        .projection_checkpoint("gateway_receive_cursor:t")?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?;
    let mut losses = Vec::new();
    let mut query = db.connection.prepare(
        "SELECT from_seq,to_seq,count,reason,recorded_at,classification FROM gateway_inbox_loss WHERE target_delivery_id='t' ORDER BY from_seq",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            be(row.get(0)?),
            be(row.get(1)?),
            be(row.get(2)?),
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ))
    })?;
    for row in rows {
        losses.push(row?);
    }
    let mut outbox = Vec::new();
    let mut query = db.connection.prepare(
        "SELECT keys_json FROM runtime_outbox WHERE published=0 AND json_extract(keys_json,'$.source_key') LIKE 'receive-gap:%' ORDER BY json_extract(keys_json,'$.source_key')",
    )?;
    for row in query.query_map([], |row| row.get(0))? {
        outbox.push(row?);
    }
    Ok(Snap {
        cursor,
        losses,
        outbox,
        intents: {
            let mut out = Vec::new();
            let mut query = db.connection.prepare(
                "SELECT inbox_seq,created_at,next_attempt_at,expires_at FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq",
            )?;
            for row in query
                .query_map([], |row| Ok((be(row.get(0)?), row.get(1)?, row.get(2)?, row.get(3)?)))?
            {
                out.push(row?);
            }
            out
        },
        work: seqs(
            db,
            "SELECT inbox_seq FROM gateway_receive_work WHERE target_delivery_id='t' AND incarnation_id='e'",
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

fn reopen(root: &std::path::Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &crate::AccountIndex::open(root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn assert_fault(result: Result<Out, StorageError>) {
    match result {
        Err(StorageError::Integrity("receive cover before-commit")) => {}
        other => panic!("expected before-commit, got {other:?}"),
    }
}

#[test]
fn atomic_cover_crash_sweep() -> Result<(), StorageError> {
    sweep_interleaved_cover()?;
    cover_when_all_slots_are_receipts()?;
    pauses_when_slots_are_held_by_other_sequences()?;
    held_keeps_quarantined()?;
    covers_exactly_64_boundaries()?;
    covers_63_gaps_and_one_live()?;
    refuses_exact_interval_errors()?;
    Ok(())
}

fn sweep_interleaved_cover() -> Result<(), StorageError> {
    let (root, db) = setup("w2-atomic")?;
    let empty = snap(&db)?;
    stage(&db, 0, 2)?;
    let pre = snap(&db)?;
    assert_eq!(pre.work, vec![2]);
    assert_fault(with_fault(FaultKind::BeforeCommit, || {
        cover(&db, 0, 2, Kind::Terminal, &[gap(1, 1)])
    }));
    assert_eq!(snap(&db)?, pre, "before-commit rolls back loss/outbox/intent/C");

    assert_eq!(cover(&db, 0, 2, Kind::Terminal, &[gap(1, 1)])?, Out::Covered);
    let live = snap(&db)?;
    assert_eq!(live.cursor, 2);
    assert_eq!(live.losses.len(), 1);
    assert_eq!(live.losses[0].0, 1);
    assert_eq!(live.losses[0].1, 1);
    assert_eq!(live.losses[0].2, 1);
    assert_eq!(live.losses[0].3, "expired");
    assert!(live.losses[0].4 > 0, "loss recorded_at");
    assert_eq!(live.losses[0].5, "unavailable");
    assert_eq!(live.outbox, vec![gap_keys(1, 1, 1, "expired", "unavailable")]);
    assert_eq!(live.intents.len(), 1);
    assert_eq!(live.intents[0].0, 2);
    assert_eq!(live.intents[0].1, live.intents[0].2);
    assert_eq!(live.intents[0].3, live.intents[0].1.saturating_add(604_800));
    assert_eq!(live.work, Vec::<u64>::new());
    assert_eq!(live.receipts, Vec::<(u64, String)>::new());
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, live, "reopen keeps interleaved loss1/live2 values");

    assert_eq!(cover(&db, 2, 5, Kind::GapOnly, &[gap(3, 4), gap(5, 5)])?, Out::Covered);
    let page = snap(&db)?;
    assert_eq!(page.cursor, 5);
    assert_eq!(page.losses.len(), 2);
    assert_eq!((page.losses[0].0, page.losses[0].1, page.losses[0].2), (1, 1, 1));
    assert_eq!((page.losses[1].0, page.losses[1].1, page.losses[1].2), (3, 5, 3));
    assert_eq!(
        page.outbox,
        vec![
            gap_keys(1, 1, 1, "expired", "unavailable"),
            gap_keys(3, 5, 3, "expired", "unavailable")
        ]
    );
    assert_eq!(page.intents, live.intents, "gap-only emits no intent");

    stage(&db, 5, 7)?;
    assert_eq!(cover(&db, 5, 7, Kind::Held, &[gap(6, 6)])?, Out::Covered);
    let held = snap(&db)?;
    assert_eq!(held.cursor, 7);
    assert_eq!(held.work, vec![7]);
    assert_eq!(held.receipts, vec![(7, "held".into())]);
    assert_eq!(held.intents, live.intents, "held omits intent");

    assert_eq!(cover(&db, 7, 9, Kind::GapOnly, &[gap(8, 9)])?, Out::Covered);
    let trailing = snap(&db)?;
    assert_eq!(trailing.cursor, 9);
    assert!(trailing.losses.iter().any(|row| row.0 == 8 && row.1 == 9 && row.2 == 2));

    let inverted = cover(
        &db,
        9,
        11,
        Kind::GapOnly,
        &[ReceiveGap {
            from_seq: 11,
            to_seq: 10,
            reason: "expired",
            classification: "unavailable",
        }],
    );
    assert!(
        matches!(inverted, Err(StorageError::Integrity("receive cover interval inverted"))),
        "{inverted:?}"
    );
    let many = alternating(10, 65);
    let over = cover(&db, 9, 74, Kind::GapOnly, &many);
    assert!(
        matches!(over, Err(StorageError::Integrity("receive cover boundary limit"))),
        "{over:?}"
    );
    assert_eq!(snap(&db)?.cursor, 9, "refused intervals leave C unchanged");

    terminal_transfers_reserved_slot(&db)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    let _ = empty;
    Ok(())
}

fn terminal_transfers_reserved_slot(db: &AccountDb) -> Result<(), StorageError> {
    db.write_transaction(|| {
        for n in 1u64..=1021 {
            db.connection.execute(
                "INSERT INTO gateway_ack_intent VALUES('t','old',?1,0,0,0,100)",
                params![n.to_be_bytes().as_slice()],
            )?;
        }
        Ok::<(), StorageError>(())
    })?;
    stage(db, 9, 11)?;
    let slots_pre = slots(db)?;
    assert_eq!(slots_pre, 1024);
    assert_eq!(cover(db, 9, 11, Kind::Terminal, &[gap(10, 10)])?, Out::Covered);
    let transferred = snap(db)?;
    assert_eq!(transferred.cursor, 11);
    assert!(transferred.intents.iter().any(|row| row.0 == 11));
    assert!(!transferred.receipts.iter().any(|row| row.0 == 11));
    assert_eq!(slots(db)?, slots_pre, "terminal transfers the reserved slot");
    Ok(())
}

fn pauses_when_slots_are_held_by_other_sequences() -> Result<(), StorageError> {
    let (root, db) = setup("w2-capacity-pause")?;
    db.write_transaction(|| {
        for n in 1u64..=1024 {
            db.connection.execute(
                "INSERT INTO gateway_ack_intent VALUES('t','old',?1,0,0,0,100)",
                params![n.to_be_bytes().as_slice()],
            )?;
        }
        db.set_projection_checkpoint("gateway_receive_cursor:t", "1023")?;
        Ok::<(), StorageError>(())
    })?;
    insert_receipt(&db, 1025, "staged")?;
    assert_eq!(slots(&db)?, 1025, "1,024 other intents plus the covered receipt");
    let pre = snap(&db)?;
    assert_eq!(cover(&db, 1023, 1025, Kind::Terminal, &[gap(1024, 1024)])?, Out::Paused);
    assert_eq!(cover(&db, 1023, 1025, Kind::CompatTerminal, &[gap(1024, 1024)])?, Out::Paused);
    assert_eq!(snap(&db)?, pre, "paused cover writes no loss, outbox, intent, work, receipt or C");
    assert_eq!(slots(&db)?, 1025, "pause keeps the slot count");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn outbox_retry_writes_no_duplicate() -> Result<(), StorageError> {
    let (root, db) = setup("w2-gap-retry")?;
    let gaps = [gap(1, 3)];
    assert_eq!(cover(&db, 0, 3, Kind::GapOnly, &gaps)?, Out::Covered);
    let done = snap(&db)?;
    assert_eq!(done.outbox, vec![gap_keys(1, 3, 3, "expired", "unavailable")]);
    // Replay the same step from the same cursor, as a retry after a lost acknowledgement would.
    db.write_transaction(|| {
        db.set_projection_checkpoint("gateway_receive_cursor:t", "0")?;
        Ok::<(), StorageError>(())
    })?;
    let pre = snap(&db)?;
    assert!(cover(&db, 0, 3, Kind::GapOnly, &gaps).is_err(), "retry of a written gap must fail");
    let retried = snap(&db)?;
    assert_eq!(retried, pre, "failed retry writes nothing");
    assert_eq!(retried.outbox, done.outbox, "exactly one outbox row per gap");
    assert_eq!(retried.losses, done.losses, "exactly one loss row per gap");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn cover_when_all_slots_are_receipts() -> Result<(), StorageError> {
    let (root, db) = setup("w2-1024-receipts")?;
    db.write_transaction(|| {
        for n in 1u64..=1024 {
            db.connection.execute(
                "INSERT INTO gateway_receive_receipt VALUES('t','e',?1,'staged',100,1)",
                params![n.to_be_bytes().as_slice()],
            )?;
        }
        Ok::<(), StorageError>(())
    })?;
    assert_eq!(slots(&db)?, 1024, "all 1,024 slots are receipts");
    assert_eq!(cover(&db, 0, 1, Kind::Terminal, &[])?, Out::Covered);
    assert_eq!(snap(&db)?.cursor, 1);
    assert_eq!(slots(&db)?, 1024, "covering a reserved receipt keeps the slot count");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn held_keeps_quarantined() -> Result<(), StorageError> {
    let (root, db) = setup("w2-quarantine")?;
    insert_receipt(&db, 1, "quarantined")?;
    let quarantined_pre = snap(&db)?;
    assert_eq!(cover(&db, 0, 1, Kind::Held, &[])?, Out::Covered);
    let quarantined = snap(&db)?;
    assert_eq!(quarantined.cursor, 1);
    assert_eq!(quarantined.receipts, vec![(1, "quarantined".into())]);
    assert_eq!(quarantined.work, quarantined_pre.work);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn covers_exactly_64_boundaries() -> Result<(), StorageError> {
    let (root, db) = setup("w2-64-boundaries")?;
    let gaps64 = alternating(1, 64);
    assert_eq!(cover(&db, 0, 64, Kind::GapOnly, &gaps64)?, Out::Covered);
    assert_eq!(snap(&db)?.cursor, 64);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn covers_63_gaps_and_one_live() -> Result<(), StorageError> {
    let (root, db) = setup("w2-63-live")?;
    insert_receipt(&db, 64, "staged")?;
    let gaps63 = alternating(1, 63);
    assert_eq!(cover(&db, 0, 64, Kind::Terminal, &gaps63)?, Out::Covered);
    let mixed = snap(&db)?;
    assert_eq!(mixed.cursor, 64);
    assert!(mixed.intents.iter().any(|row| row.0 == 64));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn refuses_exact_interval_errors() -> Result<(), StorageError> {
    let (root, db) = setup("w2-refusals")?;
    assert_refused(&db, 0, 1, Kind::CompatTerminal, &[], "receive cover requires a receipt")?;
    assert_refused(
        &db,
        0,
        u64::MAX,
        Kind::Terminal,
        &[gap(1, u64::MAX)],
        "receive cover interval overflow",
    )?;
    assert_refused(
        &db,
        0,
        3,
        Kind::GapOnly,
        &[
            gap(1, 2),
            ReceiveGap { from_seq: 2, to_seq: 3, reason: "expired", classification: "unavailable" },
        ],
        "receive cover interval overlap",
    )?;
    assert_refused(
        &db,
        0,
        1,
        Kind::GapOnly,
        &[ReceiveGap { from_seq: 1, to_seq: 1, reason: "", classification: "unavailable" }],
        "receive cover interval missing reason",
    )?;
    assert_refused(
        &db,
        0,
        1,
        Kind::GapOnly,
        &[ReceiveGap { from_seq: 1, to_seq: 1, reason: "bogus", classification: "unavailable" }],
        "receive cover interval unknown reason",
    )?;
    assert_refused(
        &db,
        0,
        1,
        Kind::GapOnly,
        &[ReceiveGap { from_seq: 1, to_seq: 1, reason: "expired", classification: "bogus" }],
        "receive cover interval unknown classification",
    )?;
    db.write_transaction(|| {
        db.set_projection_checkpoint("gateway_receive_cursor:t", "5")?;
        Ok::<(), StorageError>(())
    })?;
    assert_refused(&db, 5, 7, Kind::GapOnly, &[gap(5, 7)], "receive cover interval outside page")?;
    assert_refused(&db, 5, 7, Kind::GapOnly, &[gap(6, 8)], "receive cover interval outside page")?;
    assert_refused(
        &db,
        5,
        9,
        Kind::GapOnly,
        &[gap(6, 6), gap(8, 9)],
        "receive cover interval outside page",
    )?;
    insert_receipt(&db, 7, "staged")?;
    assert_refused(&db, 5, 8, Kind::GapOnly, &[gap(6, 8)], "receive cover interval has a receipt")?;
    assert_refused(&db, 5, 0, Kind::GapOnly, &[], "receive sequence must be positive")?;
    insert_receipt(&db, 6, "completed")?;
    assert_refused(&db, 5, 6, Kind::Held, &[], "receive cover requires a receipt")?;
    assert_refused(&db, 5, 5, Kind::CompatTerminal, &[], "receive cover interval outside page")?;
    // L1: compat terminal only from a staged receipt with registered work.
    insert_receipt(&db, 9, "held")?;
    assert_refused(&db, 5, 9, Kind::CompatTerminal, &[], "receive cover requires a receipt")?;
    assert_refused(&db, 5, 7, Kind::CompatTerminal, &[], "receive cover requires a receipt")?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn loss_before_cursor_crash() -> Result<(), StorageError> {
    let (root, db) = setup("w2-loss-before")?;
    stage(&db, 0, 4)?;
    let pre = snap(&db)?;
    let gaps = [
        gap(1, 2),
        ReceiveGap { from_seq: 3, to_seq: 3, reason: "nacked", classification: "unavailable" },
    ];
    assert_fault(with_fault(FaultKind::BeforeCommit, || cover(&db, 0, 4, Kind::Terminal, &gaps)));
    assert_eq!(snap(&db)?, pre, "loss/outbox without C do not survive the cut");
    assert_eq!(cover(&db, 0, 4, Kind::Terminal, &gaps)?, Out::Covered);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 4);
    assert_eq!(
        done.outbox,
        vec![
            gap_keys(1, 2, 2, "expired", "unavailable"),
            gap_keys(3, 3, 1, "nacked", "unavailable")
        ],
        "exactly one unpublished outbox source key per expected gap"
    );
    assert_eq!(done.outbox.len(), done.losses.len());
    assert_eq!(done.losses[0].4, done.intents[0].1, "loss recorded_at matches intent created_at");
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn loss_after_cursor_crash() -> Result<(), StorageError> {
    let (root, db) = setup("w2-loss-after")?;
    let pre = snap(&db)?;
    assert_fault(with_fault(FaultKind::BeforeCommit, || {
        cover(&db, 0, 3, Kind::GapOnly, &[gap(1, 3)])
    }));
    assert_eq!(snap(&db)?, pre, "C without loss/outbox does not survive the cut");
    assert_eq!(cover(&db, 0, 3, Kind::GapOnly, &[gap(1, 3)])?, Out::Covered);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 3);
    assert_eq!(done.losses.len(), 1);
    assert_eq!((done.losses[0].0, done.losses[0].1, done.losses[0].2), (1, 3, 3));
    assert!(done.losses[0].4 > 0, "loss recorded_at");
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done, "gap survives restart before later writes");
    assert_eq!(done.outbox, vec![gap_keys(1, 3, 3, "expired", "unavailable")]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
