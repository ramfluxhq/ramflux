// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receipt-subtracted page coverage. W1 done, crash before W2, router expires.
#![allow(clippy::expect_used, clippy::panic)]
use super::cover::{ReceiveCoverKind as Kind, ReceiveCoverResult as Out};
use super::page::{
    ReceiveKnownLoss, ReceivePageView, ReceiveReconcileResult, ReconcileFault, run as with_skip,
};
use super::stage_tests::{bytes, input, setup};
use super::*;
use crate::StorageError;
use rusqlite::params;

fn expect(db: &AccountDb, cursor: u64) -> Result<ReceiveExpectation<'static>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation: "e",
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn stage(db: &AccountDb, sequence: u64) -> Result<(), StorageError> {
    let wire = bytes(sequence);
    let result =
        db.receive_transaction(expect(db, 0)?, 1, |tx| tx.stage(input(&wire, sequence)))?;
    match result {
        stage::ReceiveStageResult::Staged => Ok(()),
        other => panic!("expected staged, got {other:?}"),
    }
}

fn hold(db: &AccountDb, sequence: u64) -> Result<(), StorageError> {
    db.connection.execute(
        "UPDATE gateway_receive_receipt SET disposition='held' WHERE inbox_seq=?1",
        params![sequence.to_be_bytes().as_slice()],
    )?;
    Ok(())
}

fn erase(db: &AccountDb, sequence: u64) -> Result<(), StorageError> {
    let seq = sequence.to_be_bytes();
    db.connection.execute(
        "UPDATE gateway_receive_receipt SET disposition='erased' WHERE inbox_seq=?1",
        params![seq.as_slice()],
    )?;
    db.connection
        .execute("DELETE FROM gateway_receive_work WHERE inbox_seq=?1", params![seq.as_slice()])?;
    Ok(())
}

fn view<'a>(losses: &'a [ReceiveKnownLoss<'a>], entries: &'a [u64]) -> ReceivePageView<'a> {
    ReceivePageView { after: 0, covered: 10, entries, known_losses: losses }
}

fn gap_count(result: &ReceiveReconcileResult) -> Result<u64, StorageError> {
    let mut total = 0u64;
    for step in result.prefix() {
        for gap in &step.gaps {
            total = total
                .checked_add(super::cover::interval_count(gap.from_seq, gap.to_seq)?)
                .expect("gap count");
        }
    }
    Ok(total)
}

fn reconcile(
    db: &AccountDb,
    cursor: u64,
    page: ReceivePageView<'_>,
) -> Result<ReceiveReconcileResult, StorageError> {
    db.receive_transaction(expect(db, cursor)?, 1, |tx| tx.reconcile(page))
}

fn losses(db: &AccountDb) -> Result<Vec<(u64, u64, u64, String)>, StorageError> {
    let mut query = db.connection.prepare(
        "SELECT from_seq,to_seq,count,reason FROM gateway_inbox_loss WHERE target_delivery_id='t' ORDER BY from_seq",
    )?;
    let rows = query.query_map([], |row| {
        Ok((be(row.get(0)?), be(row.get(1)?), be(row.get(2)?), row.get(3)?))
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(StorageError::from)
}

fn be(bytes: Vec<u8>) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("be-u64"))
}

fn cursor(db: &AccountDb) -> Result<u64, StorageError> {
    db.projection_checkpoint("gateway_receive_cursor:t")?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))
}

fn redrive(db: &AccountDb, sequence: u64, disposition: &str) -> Result<(), StorageError> {
    db.connection.execute(
        "UPDATE gateway_receive_receipt SET disposition=?1 WHERE inbox_seq=?2",
        params![disposition, sequence.to_be_bytes().as_slice()],
    )?;
    Ok(())
}

fn receipt_rows(db: &AccountDb) -> Result<Vec<(u64, String)>, StorageError> {
    let mut receipts = Vec::new();
    let mut query = db.connection.prepare(
        "SELECT inbox_seq,disposition FROM gateway_receive_receipt WHERE target_delivery_id='t' ORDER BY inbox_seq",
    )?;
    for row in query.query_map([], |row| Ok((be(row.get(0)?), row.get::<_, String>(1)?)))? {
        receipts.push(row?);
    }
    Ok(receipts)
}

fn intent_rows(db: &AccountDb) -> Result<Vec<u64>, StorageError> {
    let mut query = db.connection.prepare(
        "SELECT inbox_seq FROM gateway_ack_intent WHERE incarnation_id='e' ORDER BY inbox_seq",
    )?;
    query
        .query_map([], |row| Ok(be(row.get(0)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(StorageError::from)
}

fn work_count(db: &AccountDb) -> Result<i64, StorageError> {
    db.connection
        .query_row("SELECT count(*) FROM gateway_receive_work", [], |r| r.get(0))
        .map_err(StorageError::from)
}

#[test]
fn receipt_reconciles_absent_range() -> Result<(), StorageError> {
    let (root, db) = setup("w2-receipt-gap")?;
    stage(&db, 2)?;
    stage(&db, 4)?;
    hold(&db, 4)?;
    stage(&db, 6)?;
    erase(&db, 6)?;
    let expired = [ReceiveKnownLoss { from_seq: 1, to_seq: 10, reason: "expired" }];
    let page = view(&expired, &[]);

    // Staged 2 is not finished: the plan covers 1 and stops before it, changing nothing else.
    let plan = reconcile(&db, 0, page)?;
    match &plan {
        ReceiveReconcileResult::NeedStage { sequence, prefix } => {
            assert_eq!(*sequence, 2);
            assert_eq!(prefix.len(), 1);
        }
        other @ ReceiveReconcileResult::Plan(_) => {
            panic!("staged receipt must stop the plan, got {other:?}")
        }
    }
    assert_eq!(gap_count(&plan)?, 1);
    let plan_skip = with_skip(ReconcileFault::SkipReceipts, || reconcile(&db, 0, page))?;
    assert_eq!(gap_count(&plan_skip)?, 10, "skipping receipts infers every missing seq as loss");
    assert_eq!(db.apply_receive_plan(expect(&db, 0)?, 1, plan.prefix())?, Out::Covered);
    assert_eq!(cursor(&db)?, 1);
    assert_eq!(
        receipt_rows(&db)?,
        vec![(2, "staged".into()), (4, "held".into()), (6, "erased".into())]
    );
    assert_eq!(intent_rows(&db)?, Vec::<u64>::new(), "a staged sequence gets no ACK intent");
    assert_eq!(work_count(&db)?, 2, "staged and held work survive; erased work was cleaned");

    // W1 completes 2: it is covered, the hole 3 is a loss, then held 4 stops the plan again.
    redrive(&db, 2, "completed")?;
    let trimmed = [ReceiveKnownLoss { from_seq: 2, to_seq: 10, reason: "expired" }];
    let page = ReceivePageView { after: 1, covered: 10, entries: &[], known_losses: &trimmed };
    let plan = reconcile(&db, 1, page)?;
    match &plan {
        ReceiveReconcileResult::NeedStage { sequence, .. } => assert_eq!(*sequence, 4),
        other @ ReceiveReconcileResult::Plan(_) => {
            panic!("held receipt must stop the plan, got {other:?}")
        }
    }
    assert_eq!(db.apply_receive_plan(expect(&db, 1)?, 1, plan.prefix())?, Out::Covered);
    assert_eq!(cursor(&db)?, 3);
    assert_eq!(intent_rows(&db)?, vec![2]);
    assert_eq!(work_count(&db)?, 1);

    // Finished receipts (rejected 4, erased 6) cover; the holes 5 and 7..10 are losses.
    redrive(&db, 4, "rejected")?;
    let trimmed = [ReceiveKnownLoss { from_seq: 4, to_seq: 10, reason: "expired" }];
    let page = ReceivePageView { after: 3, covered: 10, entries: &[], known_losses: &trimmed };
    let plan = reconcile(&db, 3, page)?;
    assert!(matches!(plan, ReceiveReconcileResult::Plan(_)), "{plan:?}");
    assert_eq!(gap_count(&plan)?, 5);
    assert_eq!(db.apply_receive_plan(expect(&db, 3)?, 1, plan.prefix())?, Out::Covered);
    assert_eq!(cursor(&db)?, 10);
    assert_eq!(
        losses(&db)?,
        vec![
            (1, 1, 1, "expired".into()),
            (3, 3, 1, "expired".into()),
            (5, 5, 1, "expired".into()),
            (7, 10, 4, "expired".into()),
        ]
    );
    assert_eq!(receipt_rows(&db)?, Vec::<(u64, String)>::new());
    assert_eq!(intent_rows(&db)?, vec![2, 4, 6]);
    assert_eq!(work_count(&db)?, 0);
    let explain: String = db.connection.query_row(
        "EXPLAIN QUERY PLAN SELECT inbox_seq,disposition FROM gateway_receive_receipt \
         WHERE target_delivery_id='t' AND incarnation_id='e' AND inbox_seq>=?1 AND inbox_seq<=?2 \
         ORDER BY inbox_seq",
        params![1u64.to_be_bytes().as_slice(), 10u64.to_be_bytes().as_slice()],
        |r| r.get(3),
    )?;
    assert!(explain.contains("PRIMARY KEY"), "{explain}");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn reconcile_never_paints_beyond_covered() -> Result<(), StorageError> {
    let (root, db) = setup("w2-paint-beyond")?;
    let beyond = [ReceiveKnownLoss { from_seq: 5, to_seq: 15, reason: "expired" }];
    let page = view(&beyond, &[]);
    assert!(matches!(
        reconcile(&db, 0, page),
        Err(StorageError::Integrity("receive cover interval outside page"))
    ));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn reconcile_refuses_bad_bounds_exactly() -> Result<(), StorageError> {
    let (root, db) = setup("w2-bad-bounds")?;
    let cases: [(u64, u64, &[ReceiveKnownLoss<'_>], &str); 5] = [
        (11, 10, &[], "receive page after exceeds covered"),
        (
            3,
            10,
            &[ReceiveKnownLoss { from_seq: 2, to_seq: 4, reason: "expired" }],
            "receive cover interval outside page",
        ),
        (
            0,
            10,
            &[
                ReceiveKnownLoss { from_seq: 1, to_seq: 5, reason: "expired" },
                ReceiveKnownLoss { from_seq: 3, to_seq: 8, reason: "expired" },
            ],
            "receive cover interval overlap",
        ),
        (
            0,
            10,
            &[ReceiveKnownLoss { from_seq: 1, to_seq: 5, reason: "" }],
            "receive cover interval missing reason",
        ),
        (
            0,
            10,
            &[ReceiveKnownLoss { from_seq: 1, to_seq: 11, reason: "expired" }],
            "receive cover interval outside page",
        ),
    ];
    for (after, covered, losses_in, message) in cases {
        let result = reconcile(
            &db,
            0,
            ReceivePageView { after, covered, entries: &[], known_losses: losses_in },
        );
        match result {
            Err(StorageError::Integrity(got)) => assert_eq!(got, message),
            other => panic!("expected {message}, got {other:?}"),
        }
    }
    assert_eq!(cursor(&db)?, 0, "refused reconciles write nothing");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn reconcile_inclusive_boundaries_are_accepted() -> Result<(), StorageError> {
    let (root, db) = setup("w2-boundaries")?;
    // Entry at after+1 is the first live sequence and stops the plan with no prefix gap.
    let plan = reconcile(
        &db,
        0,
        ReceivePageView { after: 0, covered: 10, entries: &[1], known_losses: &[] },
    )?;
    assert!(matches!(plan, ReceiveReconcileResult::NeedStage { sequence: 1, .. }), "{plan:?}");
    // Entry at covered is the last live sequence: the prefix covers 1..9 as one gap.
    let plan = reconcile(
        &db,
        0,
        ReceivePageView { after: 0, covered: 10, entries: &[10], known_losses: &[] },
    )?;
    assert!(matches!(plan, ReceiveReconcileResult::NeedStage { sequence: 10, .. }), "{plan:?}");
    assert_eq!(gap_count(&plan)?, 9);
    // A loss spanning exactly (after, covered] is accepted.
    let whole = [ReceiveKnownLoss { from_seq: 1, to_seq: 10, reason: "expired" }];
    let plan = reconcile(
        &db,
        0,
        ReceivePageView { after: 0, covered: 10, entries: &[], known_losses: &whole },
    )?;
    assert_eq!(gap_count(&plan)?, 10);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn huge_hole_is_one_interval() -> Result<(), StorageError> {
    let (root, db) = setup("w2-huge-hole")?;
    let covered = 1_000_000_000_000_000u64;
    let expired = [ReceiveKnownLoss { from_seq: 1, to_seq: covered, reason: "expired" }];
    let page = ReceivePageView { after: 0, covered, entries: &[], known_losses: &expired };
    let plan = reconcile(&db, 0, page)?;
    match &plan {
        ReceiveReconcileResult::Plan(steps) => {
            assert_eq!(steps.len(), 1);
            assert_eq!(steps[0].kind, Kind::GapOnly);
            assert_eq!(steps[0].sequence, covered);
            assert_eq!(steps[0].gaps.len(), 1);
            assert_eq!(steps[0].gaps[0].from_seq, 1);
            assert_eq!(steps[0].gaps[0].to_seq, covered);
        }
        other @ ReceiveReconcileResult::NeedStage { .. } => {
            panic!("expected one interval, got {other:?}")
        }
    }
    assert_eq!(gap_count(&plan)?, covered);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
