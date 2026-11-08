// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P20d complete: WS through [`SourceWs::settle_in`]. Storage first-leg stays in `settle_tests`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::bus::sync_driver::source::ws::SourceWs;
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult,
    ReceiveExpectation, ReceiveLedgerSnap, ReceiveSettle, ReceiveSettleKind, ReceiveSettleResult,
    ReceiveStage, ReceiveStageResult, StorageError,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Harness {
    root: tempfile::TempDir,
    db: AccountDb,
}

fn open() -> Result<Harness, StorageError> {
    let root = tempfile::tempdir().expect("tmp");
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", "principal")?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test("t", "e")?;
    Ok(Harness { root, db })
}

fn expected(db: &AccountDb, cursor: u64) -> Result<ReceiveExpectation<'static>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation: "e",
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn ws(db: &AccountDb, cursor: u64) -> Result<SourceWs<'static>, StorageError> {
    Ok(SourceWs { expected: expected(db, cursor)?, generation: 1 })
}

fn wire(seq: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"inbox_seq":seq,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":"env","source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":"hash"
    }}))
    .expect("entry")
}

fn stage(db: &AccountDb, cursor: u64, sequence: u64) -> Result<(), StorageError> {
    let bytes = wire(sequence);
    let result = db.receive_transaction(expected(db, cursor)?, 1, |tx| {
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
    assert!(matches!(result, ReceiveStageResult::Staged), "{result:?}");
    Ok(())
}

fn cover(
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    kind: ReceiveCoverKind,
) -> Result<ReceiveCoverResult, StorageError> {
    db.receive_transaction(expected(db, cursor)?, 1, |tx| {
        tx.cover(ReceiveCover { sequence, kind, gaps: &[], retain_until: 0 })
    })
}

fn snap(db: &AccountDb) -> Result<ReceiveLedgerSnap, StorageError> {
    db.receive_ledger_snap_for_test("t")
}

fn hold_then_advance(db: &AccountDb) -> Result<ReceiveLedgerSnap, StorageError> {
    stage(db, 0, 1)?;
    assert_eq!(cover(db, 0, 1, ReceiveCoverKind::Held)?, ReceiveCoverResult::Covered);
    stage(db, 1, 2)?;
    assert_eq!(cover(db, 1, 2, ReceiveCoverKind::Terminal)?, ReceiveCoverResult::Covered);
    db.append_journal(
        "receive-dead-letter:t:e:1",
        "inbox.unrouted",
        &serde_json::json!({"sequence":1,"reason":"router_dead_letter"}),
        ramflux_storage::unix_now(),
        None,
    )?;
    let advanced = snap(db)?;
    assert_eq!(advanced.cursor, 2);
    assert_eq!(advanced.work, 1, "held W2 keeps seq1 work");
    assert_eq!(advanced.intents, vec![2]);
    assert_eq!(advanced.receipts, vec![(1, "held".into())]);
    assert_eq!(
        db.receive_transaction(expected(db, 2)?, 1, |tx| SourceWs::due_retained_in(tx, 64))?,
        vec![1]
    );
    Ok(advanced)
}

fn reopen(harness: Harness) -> Result<Harness, StorageError> {
    let Harness { root, db } = harness;
    drop(db);
    let index = AccountIndex::open(root.path())?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    Ok(Harness { root, db })
}

#[test]
fn held_below_cursor_settles() -> TestResult {
    let harness = open()?;
    let db = &harness.db;
    hold_then_advance(db)?;
    assert_eq!(
        ws(db, 2)?.settle(db, ReceiveSettle { sequence: 1, kind: ReceiveSettleKind::Terminal })?,
        ReceiveSettleResult::Settled
    );
    let done = snap(db)?;
    assert_eq!(done.cursor, 2, "WS never moves C");
    assert_eq!(done.intents, vec![1, 2], "one eventual intent for the held sequence");
    assert_eq!(done.work, 0);
    assert_eq!(done.receipts, Vec::<(u64, String)>::new());
    assert_eq!(ws(db, 2)?.due_retained(db, 64)?, Vec::<u64>::new());
    let harness = reopen(harness)?;
    assert_eq!(snap(&harness.db)?, done, "reopen keeps the terminal intent and frozen C");
    assert_eq!(
        ws(&harness.db, 2)?.settle(
            &harness.db,
            ReceiveSettle { sequence: 1, kind: ReceiveSettleKind::Terminal }
        )?,
        ReceiveSettleResult::Settled,
        "already-settled WS is idempotent"
    );
    assert_eq!(snap(&harness.db)?, done);
    Ok(())
}

#[test]
fn retry_settlement_atomic() -> TestResult {
    let harness = open()?;
    let db = &harness.db;
    let pre = hold_then_advance(db)?;
    let aborted: Result<(), StorageError> = db.receive_transaction(expected(db, 2)?, 1, |tx| {
        SourceWs::settle_in(tx, ReceiveSettle { sequence: 1, kind: ReceiveSettleKind::Terminal })?;
        Err(StorageError::Integrity("caller abort before commit"))
    });
    assert!(
        matches!(aborted, Err(StorageError::Integrity("caller abort before commit"))),
        "{aborted:?}"
    );
    assert_eq!(snap(db)?, pre, "failed outer tx keeps work, omits seq1 intent, freezes C");
    assert_eq!(
        ws(db, 2)?.settle(db, ReceiveSettle { sequence: 1, kind: ReceiveSettleKind::Terminal })?,
        ReceiveSettleResult::Settled
    );
    let done = snap(db)?;
    assert_eq!(done.cursor, 2);
    assert_eq!(done.intents, vec![1, 2]);
    assert_eq!(done.work, 0);
    let harness = reopen(harness)?;
    assert_eq!(snap(&harness.db)?, done, "after commit the intent survives reopen and C stays");
    Ok(())
}
