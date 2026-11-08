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

fn covers(result: &ReceiveReconcileResult, seq: u64) -> bool {
    result
        .prefix()
        .iter()
        .any(|step| step.gaps.iter().any(|gap| seq >= gap.from_seq && seq <= gap.to_seq))
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
    let plan = reconcile(&db, 0, page)?;
    assert_eq!(gap_count(&plan)?, 7, "staged/held/erased receipts are not losses");
    assert!(!covers(&plan, 2) && !covers(&plan, 4) && !covers(&plan, 6));
    let plan_skip = with_skip(ReconcileFault::SkipReceipts, || reconcile(&db, 0, page))?;
    assert_eq!(gap_count(&plan_skip)?, 10, "skipping receipts infers every missing seq as loss");

    let expected = expect(&db, 0)?;
    assert_eq!(db.apply_receive_plan(expected, 1, plan.prefix())?, Out::Covered);
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
    let mut receipts = Vec::new();
    let mut query = db.connection.prepare(
        "SELECT inbox_seq,disposition FROM gateway_receive_receipt WHERE target_delivery_id='t' ORDER BY inbox_seq",
    )?;
    for row in query.query_map([], |row| Ok((be(row.get(0)?), row.get::<_, String>(1)?)))? {
        receipts.push(row?);
    }
    assert_eq!(receipts, vec![(4, "held".into())], "held keeps work; staged/erased settle");
    let intents: Vec<u64> = {
        let mut query = db.connection.prepare(
            "SELECT inbox_seq FROM gateway_ack_intent WHERE incarnation_id='e' ORDER BY inbox_seq",
        )?;
        query.query_map([], |row| Ok(be(row.get(0)?)))?.collect::<rusqlite::Result<Vec<_>>>()?
    };
    assert_eq!(intents, vec![2, 6]);
    let work: i64 =
        db.connection.query_row("SELECT count(*) FROM gateway_receive_work", [], |r| r.get(0))?;
    assert_eq!(work, 1);
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
