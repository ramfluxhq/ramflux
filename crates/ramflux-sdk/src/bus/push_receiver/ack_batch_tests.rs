// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P21 WA: batch timing, compat intent completion, locator marking, and `SourceWa` composition.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::ack_batch::SourceWa;
use crate::SdkError;
use crate::client::own_device_copy::w1::{LOCATORS, SequenceLocator, locator_key};
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ProjectionStore, ReceiveAckApply, ReceiveAckApplyResult,
    ReceiveAckOutcome, ReceiveAckResult, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult,
    ReceiveExpectation, ReceiveReset, ReceiveResetReason, ReceiveResetResult, ReceiveStage,
    ReceiveStageResult, StorageError,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn open(name: &str) -> Result<(tempfile::TempDir, AccountDb), StorageError> {
    let _ = name;
    let root = tempfile::tempdir().expect("tmp");
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", "principal")?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test("t", "e")?;
    Ok((root, db))
}

fn expected(
    db: &AccountDb,
    incarnation: &'static str,
    cursor: u64,
) -> Result<ReceiveExpectation<'static>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation,
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn wa(
    db: &AccountDb,
    incarnation: &'static str,
    cursor: u64,
) -> Result<SourceWa<'static>, StorageError> {
    Ok(SourceWa { expected: expected(db, incarnation, cursor)?, generation: 1 })
}

fn wire(seq: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"inbox_seq":seq,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":format!("env-{seq}"),"source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":format!("hash-{seq}")
    }})).expect("entry")
}

fn cover_terminal(db: &AccountDb, cursor: u64, sequence: u64) -> Result<(), StorageError> {
    let bytes = wire(sequence);
    let staged = db.receive_transaction(expected(db, "e", cursor)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation: "e",
            sequence,
            entry_json: &bytes,
            admission_key: "authenticated-key",
            retain_until: 100,
            first_seen: 1,
        })
    })?;
    assert_eq!(staged, ReceiveStageResult::Staged);
    assert_eq!(
        db.receive_transaction(expected(db, "e", cursor)?, 1, |tx| {
            tx.cover(ReceiveCover {
                sequence,
                kind: ReceiveCoverKind::Terminal,
                gaps: &[],
                retain_until: 0,
            })
        })?,
        ReceiveCoverResult::Covered
    );
    Ok(())
}

fn apply_rows(
    db: &AccountDb,
    incarnation: &'static str,
    cursor: u64,
    rows: &[ReceiveAckResult],
) -> Result<ReceiveAckApplyResult, SdkError> {
    let sequences: Vec<u64> = rows.iter().map(|row| row.sequence).collect();
    wa(db, incarnation, cursor)?
        .apply(db, ReceiveAckApply { incarnation, sequences: &sequences, results: rows, now: 10 })
}

fn persist_locator(
    db: &AccountDb,
    message: &str,
    sequence: u64,
) -> Result<SequenceLocator, StorageError> {
    db.send_direct_message("thread", message, "peer", b"locator")?;
    let locator = SequenceLocator {
        target: "t".to_owned(),
        incarnation: "e".to_owned(),
        sequence,
        acknowledged: false,
    };
    db.persist_message_actor_state(message, &locator_key(message), &locator)?;
    Ok(locator)
}

#[test]
fn ack_batch_timing() -> TestResult {
    let (root, db) = open("ack-timing")?;
    for sequence in 1..=16 {
        cover_terminal(&db, sequence - 1, sequence)?;
    }
    db.set_ack_intent_clock_for_test(100, 100)?;
    assert_eq!(wa(&db, "e", 16)?.select(&db, 100, false)?, (1..=16).collect::<Vec<_>>());
    let (root3, db3) = open("ack-timing-3")?;
    for sequence in 1..=3 {
        cover_terminal(&db3, sequence - 1, sequence)?;
    }
    db3.set_ack_intent_clock_for_test(100, 100)?;
    assert_eq!(wa(&db3, "e", 3)?.select(&db3, 100, false)?, Vec::<u64>::new());
    assert_eq!(wa(&db3, "e", 3)?.select(&db3, 101, false)?, vec![1, 2, 3]);
    drop(db);
    drop(root);
    drop(db3);
    drop(root3);
    Ok(())
}

#[test]
fn compat_intent_transition() -> TestResult {
    let (root, db) = open("ack-compat")?;
    cover_terminal(&db, 0, 1)?;
    db.seed_compat_terminal_for_test("t", "e", 1, &wire(1))?;
    let rows = [ReceiveAckResult { sequence: 1, outcome: ReceiveAckOutcome::Acked }];
    assert_eq!(apply_rows(&db, "e", 1, &rows)?, ReceiveAckApplyResult::Applied { settled: 1 });
    let snap = db.receive_ledger_snap_for_test("t")?;
    assert_eq!(snap.intents, Vec::<u64>::new(), "WA drops the intent");
    assert_eq!(snap.work, 1, "terminal compat work stays until reset");
    db.rewrite_receive_incarnation_for_test("t", "e", "u", false)?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "1")?;
    db.seed_held_receive_for_test("t", "u", 2, &wire(2))?;
    db.publish_pending_receive_loss("t", "u", ramflux_storage::unix_now())?;
    let reset = db.receive_transaction(expected(&db, "u", 1)?, 1, |tx| {
        tx.reset(ReceiveReset {
            new_incarnation: "n",
            settled: 1,
            issued: 1,
            after: 0,
            reason: ReceiveResetReason::IncarnationFirstVerified,
        })
    })?;
    assert_eq!(reset, ReceiveResetResult::Reset);
    let snap = db.receive_ledger_snap_for_test("t")?;
    assert!(
        !snap.receipts.iter().any(|(seq, disposition)| *seq == 1 && disposition == "completed"),
        "U→E releases terminal compat work"
    );
    assert_eq!(snap.work, 1, "held work is retained");
    assert!(snap.receipts.iter().any(|(seq, disposition)| *seq == 2 && disposition == "held"));
    drop(db);
    drop(root);
    Ok(())
}

#[test]
fn own_copy_locator_terminal_and_expiry() -> TestResult {
    let (root, db) = open("ack-locator")?;
    cover_terminal(&db, 0, 1)?;
    persist_locator(&db, "expired", 1)?;
    let expired = [ReceiveAckResult { sequence: 1, outcome: ReceiveAckOutcome::Expired }];
    assert_eq!(apply_rows(&db, "e", 1, &expired)?, ReceiveAckApplyResult::Applied { settled: 1 });
    let locator =
        db.load_actor_state::<SequenceLocator>(&locator_key("expired"))?.expect("locator");
    assert!(!locator.acknowledged, "expiry never marks");
    assert!(db.actor_state_keys(LOCATORS)?.contains(&locator_key("expired")));

    cover_terminal(&db, 1, 2)?;
    persist_locator(&db, "settled", 2)?;
    let settled = [ReceiveAckResult { sequence: 2, outcome: ReceiveAckOutcome::AlreadySettled }];
    assert_eq!(apply_rows(&db, "e", 2, &settled)?, ReceiveAckApplyResult::Applied { settled: 1 });
    let locator =
        db.load_actor_state::<SequenceLocator>(&locator_key("settled"))?.expect("locator");
    assert!(locator.acknowledged, "already_settled marks the locator");

    cover_terminal(&db, 2, 3)?;
    persist_locator(&db, "gone", 3)?;
    let gone = [ReceiveAckResult { sequence: 3, outcome: ReceiveAckOutcome::NotFound }];
    assert_eq!(apply_rows(&db, "e", 3, &gone)?, ReceiveAckApplyResult::Applied { settled: 1 });
    let locator = db.load_actor_state::<SequenceLocator>(&locator_key("gone"))?.expect("locator");
    assert!(locator.acknowledged, "not_found marks the locator");
    drop(db);
    drop(root);
    Ok(())
}
