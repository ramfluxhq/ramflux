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
use crate::StorageError;
use rusqlite::params;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snap {
    cursor: u64,
    losses: Vec<(u64, u64, u64, String, String)>,
    journals: Vec<String>,
    intents: Vec<u64>,
    work: Vec<u64>,
    receipts: Vec<(u64, String)>,
}

fn gap(from: u64, to: u64) -> ReceiveGap<'static> {
    ReceiveGap { from_seq: from, to_seq: to, reason: "expired", classification: "unavailable" }
}

fn cover(
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
        |tx| tx.cover(ReceiveCover { sequence, kind, gaps }),
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

fn snap(db: &AccountDb) -> Result<Snap, StorageError> {
    let cursor = db
        .projection_checkpoint("gateway_receive_cursor:t")?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?;
    let mut losses = Vec::new();
    let mut query = db.connection.prepare(
        "SELECT from_seq,to_seq,count,reason,classification FROM gateway_inbox_loss WHERE target_delivery_id='t' ORDER BY from_seq",
    )?;
    let rows = query.query_map([], |row| {
        Ok((be(row.get(0)?), be(row.get(1)?), be(row.get(2)?), row.get(3)?, row.get(4)?))
    })?;
    for row in rows {
        losses.push(row?);
    }
    let mut journals = Vec::new();
    let mut query = db
        .connection
        .prepare("SELECT source_key FROM runtime_journal WHERE source_key LIKE 'receive-gap:%' ORDER BY source_key")?;
    for row in query.query_map([], |row| row.get(0))? {
        journals.push(row?);
    }
    Ok(Snap {
        cursor,
        losses,
        journals,
        intents: seqs(
            db,
            "SELECT inbox_seq FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e'",
        )?,
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
    assert_eq!(live.losses, vec![(1, 1, 1, "expired".into(), "unavailable".into())]);
    assert_eq!(live.journals, vec!["receive-gap:t:e:1:1".to_owned()]);
    assert_eq!(live.intents, vec![2]);
    assert_eq!(live.work, Vec::<u64>::new());
    assert_eq!(live.receipts, Vec::<(u64, String)>::new());
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, live, "reopen keeps interleaved loss1/live2 values");

    assert_eq!(cover(&db, 2, 5, Kind::GapOnly, &[gap(3, 4), gap(5, 5)])?, Out::Covered);
    let page = snap(&db)?;
    assert_eq!(page.cursor, 5);
    assert_eq!(
        page.losses,
        vec![
            (1, 1, 1, "expired".into(), "unavailable".into()),
            (3, 5, 3, "expired".into(), "unavailable".into())
        ]
    );
    assert_eq!(
        page.journals,
        vec!["receive-gap:t:e:1:1".to_owned(), "receive-gap:t:e:3:5".to_owned()]
    );
    assert_eq!(page.intents, vec![2], "gap-only emits no intent");

    stage(&db, 5, 7)?;
    assert_eq!(cover(&db, 5, 7, Kind::Held, &[gap(6, 6)])?, Out::Covered);
    let held = snap(&db)?;
    assert_eq!(held.cursor, 7);
    assert_eq!(held.work, vec![7]);
    assert_eq!(held.receipts, vec![(7, "held".into())]);
    assert_eq!(held.intents, vec![2], "held omits intent");

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
    let labels: Vec<String> = (0..65).map(|i| format!("r{i}")).collect();
    let many: Vec<ReceiveGap<'_>> = labels
        .iter()
        .enumerate()
        .map(|(i, reason)| ReceiveGap {
            from_seq: 10 + i as u64,
            to_seq: 10 + i as u64,
            reason,
            classification: "unavailable",
        })
        .collect();
    let over = cover(&db, 9, 74, Kind::GapOnly, &many);
    assert!(
        matches!(over, Err(StorageError::Integrity("receive cover boundary limit"))),
        "{over:?}"
    );
    assert_eq!(snap(&db)?.cursor, 9, "refused intervals leave C unchanged");

    db.write_transaction(|| {
        for n in 1u64..=1021 {
            db.connection.execute(
                "INSERT INTO gateway_ack_intent VALUES('t','old',?1,0,0,0,100)",
                params![n.to_be_bytes().as_slice()],
            )?;
        }
        Ok::<(), StorageError>(())
    })?;
    stage(&db, 9, 11)?;
    let paused_pre = snap(&db)?;
    assert_eq!(cover(&db, 9, 11, Kind::Terminal, &[gap(10, 10)])?, Out::Paused);
    let paused = snap(&db)?;
    assert_eq!(paused.cursor, paused_pre.cursor);
    assert_eq!(paused.work, paused_pre.work);
    assert_eq!(paused.losses, paused_pre.losses);
    assert_eq!(paused.journals, paused_pre.journals);
    drop(db);
    std::fs::remove_dir_all(root)?;
    let _ = empty;
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
        done.journals,
        vec!["receive-gap:t:e:1:2".to_owned(), "receive-gap:t:e:3:3".to_owned()],
        "exactly one journal source key per expected gap"
    );
    assert_eq!(done.journals.len(), done.losses.len());
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
    assert_eq!(done.losses, vec![(1, 3, 3, "expired".into(), "unavailable".into())]);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done, "gap survives restart before later writes");
    assert_eq!(done.journals, vec!["receive-gap:t:e:1:3".to_owned()]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
