// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WA batch settlement: intents survive lost replies; never ACK above C; `invalid_seq`
//! is terminal; a stale-E batch cannot delete a new-E intent.
#![allow(clippy::expect_used, clippy::panic)]
use super::ack::{
    ReceiveAckApply, ReceiveAckApplyResult, ReceiveAckOutcome, ReceiveAckResult, run as with_fault,
};
use super::cover::{ReceiveCover, ReceiveCoverKind, ReceiveCoverResult};
use super::stage_tests::{bytes, input, setup};
use super::*;
use crate::StorageError;
use rusqlite::params;

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
    incarnation: &str,
    cursor: u64,
    sequence: u64,
    kind: ReceiveCoverKind,
) -> Result<ReceiveCoverResult, StorageError> {
    db.receive_transaction(expect(db, incarnation, cursor)?, 1, |tx| {
        tx.cover(ReceiveCover { sequence, kind, gaps: &[], retain_until: 0 })
    })
}

fn stage(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    sequence: u64,
) -> Result<(), StorageError> {
    let wire = bytes(sequence);
    let mut page = input(&wire, sequence);
    page.incarnation = incarnation;
    db.receive_transaction(expect(db, incarnation, cursor)?, 1, |tx| tx.stage(page))?;
    Ok(())
}

fn apply(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    now: i64,
    rows: &[ReceiveAckResult],
) -> Result<ReceiveAckApplyResult, StorageError> {
    let sequences: Vec<u64> = rows.iter().map(|row| row.sequence).collect();
    db.receive_transaction(expect(db, incarnation, cursor)?, 1, |tx| {
        tx.apply_ack_results(ReceiveAckApply {
            incarnation,
            sequences: &sequences,
            results: rows,
            now,
        })
    })
}

fn due(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    now: i64,
    force: bool,
) -> Result<Vec<u64>, StorageError> {
    db.receive_transaction(expect(db, incarnation, cursor)?, 1, |tx| {
        tx.select_ack_batch(now, force)
    })
}

fn now() -> i64 {
    crate::unix_now().saturating_add(60)
}

fn intents(db: &AccountDb, incarnation: &str) -> Result<Vec<u64>, StorageError> {
    let mut query = db.connection.prepare(
        "SELECT inbox_seq FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id=?1 ORDER BY inbox_seq",
    )?;
    let rows = query.query_map(params![incarnation], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for seq in rows {
        let bytes = seq?;
        let value: [u8; 8] = bytes.as_slice().try_into().expect("seq");
        out.push(u64::from_be_bytes(value));
    }
    Ok(out)
}

fn terminal(seq: u64) -> ReceiveAckResult {
    ReceiveAckResult { sequence: seq, outcome: ReceiveAckOutcome::Acked }
}

fn cover_range(db: &AccountDb, through: u64) -> Result<(), StorageError> {
    for sequence in 1..=through {
        stage(db, "e", sequence - 1, sequence)?;
        assert_eq!(
            cover(db, "e", sequence - 1, sequence, ReceiveCoverKind::Terminal)?,
            ReceiveCoverResult::Covered
        );
    }
    Ok(())
}

#[test]
fn ack_lost_before_and_after_commit() -> Result<(), StorageError> {
    let (root, db) = setup("ack-lost")?;
    cover_range(&db, 2)?;
    assert_eq!(intents(&db, "e")?, vec![1, 2]);
    assert_eq!(due(&db, "e", 2, now(), true)?, vec![1, 2], "select does not delete");
    assert_eq!(intents(&db, "e")?, vec![1, 2], "death before flush keeps intents");
    let lost = with_fault(true, || {
        apply(
            &db,
            "e",
            2,
            10,
            &[
                ReceiveAckResult { sequence: 1, outcome: ReceiveAckOutcome::Uncertain },
                ReceiveAckResult { sequence: 2, outcome: ReceiveAckOutcome::Uncertain },
            ],
        )
    });
    assert!(matches!(&lost, Err(StorageError::Integrity("receive ack before-commit"))), "{lost:?}");
    assert_eq!(intents(&db, "e")?, vec![1, 2], "abort after apply rolls back");
    assert_eq!(
        apply(
            &db,
            "e",
            2,
            10,
            &[
                ReceiveAckResult { sequence: 1, outcome: ReceiveAckOutcome::Uncertain },
                ReceiveAckResult { sequence: 2, outcome: ReceiveAckOutcome::Uncertain },
            ],
        )?,
        ReceiveAckApplyResult::Applied { settled: 0 }
    );
    assert_eq!(intents(&db, "e")?, vec![1, 2], "lost reply after WR retains");
    assert_eq!(
        apply(
            &db,
            "e",
            2,
            11,
            &[
                ReceiveAckResult { sequence: 1, outcome: ReceiveAckOutcome::AlreadySettled },
                ReceiveAckResult { sequence: 2, outcome: ReceiveAckOutcome::AlreadySettled },
            ],
        )?,
        ReceiveAckApplyResult::Applied { settled: 2 }
    );
    assert_eq!(intents(&db, "e")?, Vec::<u64>::new());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn never_ack_above_c() -> Result<(), StorageError> {
    let (root, db) = setup("ack-above-c")?;
    stage(&db, "e", 0, 1)?;
    assert_eq!(cover(&db, "e", 0, 1, ReceiveCoverKind::Held)?, ReceiveCoverResult::Covered);
    assert_eq!(due(&db, "e", 1, now(), true)?, Vec::<u64>::new(), "held never selected");
    stage(&db, "e", 1, 2)?;
    let above = apply(&db, "e", 1, now(), &[terminal(2)]).expect_err("seq>C");
    assert!(
        matches!(above, StorageError::Integrity("receive ack sequence exceeds cursor")),
        "{above:?}"
    );
    assert_eq!(cover(&db, "e", 1, 2, ReceiveCoverKind::Terminal)?, ReceiveCoverResult::Covered);
    assert_eq!(due(&db, "e", 2, now(), true)?, vec![2]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn invalid_seq_terminal() -> Result<(), StorageError> {
    let (root, db) = setup("ack-invalid")?;
    cover_range(&db, 1)?;
    assert_eq!(
        apply(
            &db,
            "e",
            1,
            10,
            &[ReceiveAckResult { sequence: 1, outcome: ReceiveAckOutcome::InvalidSeq }],
        )?,
        ReceiveAckApplyResult::Applied { settled: 1 }
    );
    assert_eq!(intents(&db, "e")?, Vec::<u64>::new());
    let events: i64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='inbox.receive_failure' AND json_extract(CAST(body_json AS TEXT),'$.reason')='invalid_seq'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(events, 1, "invalid_seq emits one diagnostic");
    stage(&db, "e", 1, 2)?;
    assert_eq!(cover(&db, "e", 1, 2, ReceiveCoverKind::Terminal)?, ReceiveCoverResult::Covered);
    assert_eq!(
        due(&db, "e", 2, now(), true)?,
        vec![2],
        "reused seq is a new intent, not the old retry"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn delayed_old_incarnation_ack() -> Result<(), StorageError> {
    let (root, db) = setup("ack-old-e")?;
    cover_range(&db, 1)?;
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET incarnation_id='e2', retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&["e"])?],
    )?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "0")?;
    db.connection.execute("DELETE FROM gateway_ack_intent", [])?;
    stage(&db, "e2", 0, 1)?;
    assert_eq!(cover(&db, "e2", 0, 1, ReceiveCoverKind::Terminal)?, ReceiveCoverResult::Covered);
    assert_eq!(intents(&db, "e2")?, vec![1]);
    let sequences = [1u64];
    let results = [terminal(1)];
    let outcome = db.receive_transaction(expect(&db, "e2", 1)?, 1, |tx| {
        tx.apply_ack_results(ReceiveAckApply {
            incarnation: "e",
            sequences: &sequences,
            results: &results,
            now: now(),
        })
    })?;
    assert_eq!(outcome, ReceiveAckApplyResult::ResetRequired);
    assert_eq!(intents(&db, "e2")?, vec![1], "stale-E batch leaves the new-E intent");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
