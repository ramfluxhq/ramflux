// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WA batch settlement: intents survive lost replies; never ACK above C; `invalid_seq`
//! is terminal and revalidates; a stale-E batch cannot delete a new-E intent; a terminal
//! outcome releases compat work in the same transaction; the wire batch shape is exact.
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
        ReceiveAckApplyResult::Applied { settled: 0, revalidate: false }
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
        ReceiveAckApplyResult::Applied { settled: 2, revalidate: false }
    );
    assert_eq!(intents(&db, "e")?, Vec::<u64>::new());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn held_at_or_below_c_is_not_selected() -> Result<(), StorageError> {
    let (root, db) = setup("ack-held-at-c")?;
    stage(&db, "e", 0, 1)?;
    assert_eq!(cover(&db, "e", 0, 1, ReceiveCoverKind::Terminal)?, ReceiveCoverResult::Covered);
    assert_eq!(due(&db, "e", 1, now(), true)?, vec![1], "terminal intent at C is due");
    // Terminal cover releases the receipt; plant a held row so the SQL exclusion is observable.
    db.write_transaction(|| -> Result<(), StorageError> {
        db.connection.execute(
            "INSERT INTO gateway_receive_receipt VALUES('t','e',?1,'held',0,1)",
            params![1u64.to_be_bytes().as_slice()],
        )?;
        Ok(())
    })?;
    assert_eq!(
        due(&db, "e", 1, now(), true)?,
        Vec::<u64>::new(),
        "held receipt at seq<=C is excluded"
    );
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
        ReceiveAckApplyResult::Applied { settled: 1, revalidate: true },
        "invalid_seq asks the caller to revalidate E"
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
    assert_eq!(outcome, ReceiveAckApplyResult::StaleIncarnation, "old-E outcome is dropped");
    assert_eq!(intents(&db, "e2")?, vec![1], "stale-E batch leaves the new-E intent");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn apply_raw(
    db: &AccountDb,
    cursor: u64,
    sequences: &[u64],
    results: &[ReceiveAckResult],
) -> Result<ReceiveAckApplyResult, StorageError> {
    db.receive_transaction(expect(db, "e", cursor)?, 1, |tx| {
        tx.apply_ack_results(ReceiveAckApply { incarnation: "e", sequences, results, now: 10 })
    })
}

fn rows_for(sequences: &[u64]) -> Vec<ReceiveAckResult> {
    sequences.iter().map(|seq| terminal(*seq)).collect()
}

fn integrity(result: Result<ReceiveAckApplyResult, StorageError>, text: &'static str) {
    let error = result.expect_err("refused");
    assert!(matches!(&error, StorageError::Integrity(got) if *got == text), "{error:?}");
}

#[test]
fn ack_batch_shape_refusals_are_exact() -> Result<(), StorageError> {
    const SHAPE: &str = "receive ack batch must be 1..=64 positive seqs";
    const ORDER: &str = "receive ack batch must be strictly increasing";
    let (root, db) = setup("ack-shape")?;
    cover_range(&db, 3)?;
    integrity(apply_raw(&db, 3, &[], &[]), SHAPE);
    integrity(apply_raw(&db, 3, &[0], &rows_for(&[0])), SHAPE);
    let over: Vec<u64> = (1..=65).collect();
    integrity(apply_raw(&db, 3, &over, &rows_for(&over)), SHAPE);
    integrity(apply_raw(&db, 3, &[2, 1], &rows_for(&[2, 1])), ORDER);
    integrity(apply_raw(&db, 3, &[1, 1], &rows_for(&[1, 1])), ORDER);
    assert_eq!(intents(&db, "e")?, vec![1, 2, 3], "a refused batch writes nothing");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn ack_result_set_must_match_the_batch() -> Result<(), StorageError> {
    const EXACT: &str = "receive ack result set must be exact";
    let (root, db) = setup("ack-exact")?;
    cover_range(&db, 3)?;
    integrity(apply_raw(&db, 3, &[1, 2], &rows_for(&[1])), EXACT);
    integrity(apply_raw(&db, 3, &[1], &rows_for(&[1, 2])), EXACT);
    integrity(apply_raw(&db, 3, &[1, 2], &rows_for(&[2, 1])), EXACT);
    integrity(apply_raw(&db, 3, &[1, 2], &rows_for(&[1, 3])), EXACT);
    assert_eq!(intents(&db, "e")?, vec![1, 2, 3], "a refused batch writes nothing");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn ack_batch_of_exactly_64_is_accepted() -> Result<(), StorageError> {
    let (root, db) = setup("ack-64")?;
    cover_range(&db, 64)?;
    let batch = due(&db, "e", 64, now(), true)?;
    assert_eq!(batch, (1..=64).collect::<Vec<u64>>());
    assert_eq!(
        apply_raw(&db, 64, &batch, &rows_for(&batch))?,
        ReceiveAckApplyResult::Applied { settled: 64, revalidate: false }
    );
    assert_eq!(intents(&db, "e")?, Vec::<u64>::new());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn next_attempt(db: &AccountDb) -> Result<(i64, i64), StorageError> {
    Ok(db.connection.query_row(
        "SELECT attempts,next_attempt_at FROM gateway_ack_intent WHERE inbox_seq=x'0000000000000001'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?)
}

#[test]
fn transient_backoff_stays_within_one_to_sixty_seconds() -> Result<(), StorageError> {
    let (root, db) = setup("ack-backoff")?;
    cover_range(&db, 1)?;
    let transient = [ReceiveAckResult { sequence: 1, outcome: ReceiveAckOutcome::Transient }];
    let mut delays = Vec::new();
    for attempt in 0..9 {
        let at = 1_000 + attempt;
        assert_eq!(
            apply(&db, "e", 1, at, &transient)?,
            ReceiveAckApplyResult::Applied { settled: 0, revalidate: false }
        );
        let (attempts, next) = next_attempt(&db)?;
        assert_eq!(attempts, attempt + 1, "transient retains and counts");
        delays.push(next - at);
    }
    assert_eq!(delays, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
    assert_eq!(intents(&db, "e")?, vec![1], "transient never deletes");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn selected_batch_is_ascending_after_a_retry_reorders_it() -> Result<(), StorageError> {
    let (root, db) = setup("ack-reorder")?;
    cover_range(&db, 3)?;
    let base = crate::unix_now();
    let retry = |sequence, at| {
        apply(
            &db,
            "e",
            3,
            at,
            &[ReceiveAckResult { sequence, outcome: ReceiveAckOutcome::Transient }],
        )
    };
    retry(1, base + 10)?;
    retry(2, base + 10)?;
    retry(2, base + 10)?;
    let order: Vec<u64> = {
        let mut query = db.connection.prepare(
            "SELECT inbox_seq FROM gateway_ack_intent ORDER BY next_attempt_at,inbox_seq",
        )?;
        let rows = query.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| Ok(u64::from_be_bytes(row?.as_slice().try_into().expect("seq"))))
            .collect::<Result<_, rusqlite::Error>>()?
    };
    assert_eq!(order, vec![3, 1, 2], "the retry really reorders the age order");
    let batch = due(&db, "e", 3, base + 100, true)?;
    assert_eq!(batch, vec![1, 2, 3], "the wire batch is ascending");
    assert!(
        apply_raw(&db, 3, &batch, &rows_for(&batch)).is_ok(),
        "the selected batch passes the wire validation"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn expired_intents_are_dropped_locally_without_network() -> Result<(), StorageError> {
    let (root, db) = setup("ack-expiry")?;
    cover_range(&db, 2)?;
    db.seed_compat_terminal_for_test("t", "e", 1, &bytes(1))?;
    db.connection.execute(
        "UPDATE gateway_ack_intent SET expires_at=50 WHERE inbox_seq=x'0000000000000001'",
        [],
    )?;
    assert_eq!(
        due(&db, "e", 2, now(), true)?,
        vec![2],
        "the expired intent never goes on the wire"
    );
    assert_eq!(intents(&db, "e")?, vec![2], "expiry deletes the intent locally");
    assert_eq!(db.receive_state_for_test(1)?, (None, 0), "expiry releases its compat rows");
    let events: i64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='inbox.receive_failure' AND json_extract(CAST(body_json AS TEXT),'$.reason')='ack_expired'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(events, 1, "expiry emits one diagnostic");
    assert_eq!(due(&db, "e", 2, now(), true)?, vec![2]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn terminal_settlement_releases_compat_work_in_one_transaction() -> Result<(), StorageError> {
    let (root, db) = setup("ack-release")?;
    cover_range(&db, 2)?;
    db.seed_compat_terminal_for_test("t", "e", 1, &bytes(1))?;
    db.seed_held_receive_for_test("t", "e", 5, &bytes(5))?;
    let rows = [terminal(1), terminal(2)];
    let rolled = with_fault(true, || apply(&db, "e", 2, 10, &rows));
    assert!(matches!(&rolled, Err(StorageError::Integrity("receive ack before-commit"))));
    assert_eq!(intents(&db, "e")?, vec![1, 2], "rollback keeps the intent");
    assert_eq!(db.receive_state_for_test(1)?, (Some("completed".to_owned()), 2), "and its work");
    assert_eq!(
        apply(&db, "e", 2, 10, &rows)?,
        ReceiveAckApplyResult::Applied { settled: 2, revalidate: false }
    );
    assert_eq!(intents(&db, "e")?, Vec::<u64>::new());
    assert_eq!(db.receive_state_for_test(1)?.0, None, "the compat receipt is released");
    assert_eq!(db.receive_state_for_test(5)?, (Some("held".to_owned()), 1), "only held work stays");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn wa_release_then_kill_around_reset_leaves_zero_orphans_after_reopen() -> Result<(), StorageError>
{
    use super::reset::{FaultKind, ReceiveReset, ReceiveResetReason, run as reset_fault};
    let (root, db) = setup("ack-reset-orphans")?;
    cover_range(&db, 2)?;
    db.seed_compat_terminal_for_test("t", "e", 1, &bytes(1))?;
    assert_eq!(
        apply(&db, "e", 2, 10, &[terminal(1), terminal(2)])?,
        ReceiveAckApplyResult::Applied { settled: 2, revalidate: false }
    );
    // A terminal compat row WA never settled, plus a held row the reset must keep.
    db.seed_compat_terminal_for_test("t", "e", 3, &bytes(3))?;
    db.seed_held_receive_for_test("t", "e", 5, &bytes(5))?;
    let reset = |db: &AccountDb| {
        db.receive_transaction(expect(db, "e", 2)?, 1, |tx| {
            tx.reset(ReceiveReset {
                new_incarnation: "n",
                settled: 1,
                issued: 1,
                after: 0,
                reason: ReceiveResetReason::RouterReset,
            })
        })
    };
    let killed = reset_fault(FaultKind::BeforeCommit, || reset(&db));
    assert!(matches!(&killed, Err(StorageError::Integrity("receive reset before-commit"))));
    assert_eq!(db.receive_state_for_test(3)?.0.as_deref(), Some("completed"), "kill rolls back");
    assert_eq!(reset(&db)?, super::reset::ReceiveResetResult::Reset);
    drop(db);
    let index = crate::AccountIndex::open(&root)?;
    let db = AccountDb::open(
        &index,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    let snap = db.receive_ledger_snap_for_test("t")?;
    assert_eq!(snap.intents, Vec::<u64>::new());
    assert_eq!(snap.receipts, vec![(5, "held".to_owned())], "zero orphan compat receipts");
    assert_eq!(snap.work, 1, "zero orphan work: only the held row");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
