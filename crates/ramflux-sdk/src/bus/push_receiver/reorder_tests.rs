// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named P22 cells: durable-before-reorder, 500 ms gap, coalesced catch-up, router retirement.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use super::apply::{ApplyError, ApplyLoss, ApplyOutcome, ApplyPage, apply_page};
use super::reorder::{
    AdmitOutcome, CatchUpHint, MAX_REF_BYTES, MAX_REFS, PAGE_LIMIT, ReorderBuffer, ReorderError,
    Tick, YIELD_AFTER_PAGES,
};
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveExpectation, ReceiveLedgerSnap, ReceiveStage,
    ReceiveStageResult, StorageError,
};

fn buf() -> ReorderBuffer {
    ReorderBuffer::new(0)
}

fn buffered(seq: u64) -> AdmitOutcome {
    AdmitOutcome::Buffered { seq, dropped: None }
}

fn catch_up(after: u64) -> Tick {
    Tick::CatchUp { after, page_limit: PAGE_LIMIT }
}

fn apply_order(buffer: &mut ReorderBuffer, first: u64) -> Result<Vec<u64>, ReorderError> {
    let mut order = vec![first];
    buffer.applied(first)?;
    for seq in buffer.peek_contiguous() {
        buffer.applied(seq)?;
        order.push(seq);
    }
    Ok(order)
}

fn admit_range(buffer: &mut ReorderBuffer, from: u64, count: usize, bytes: usize) {
    for offset in 0..count {
        let seq = from.saturating_add(offset as u64);
        let got = buffer.admit(0, seq, bytes, true);
        assert!(
            matches!(got, AdmitOutcome::Buffered { seq: got_seq, dropped: None } if got_seq == seq),
            "{got:?}"
        );
    }
}

#[test]
fn reorder_and_gap() -> Result<(), ReorderError> {
    let mut filled = buf();
    assert_eq!(filled.admit(0, 2, 8, true), buffered(2));
    assert_eq!(filled.tick(200), Tick::Idle, "no Resume before the sibling arrives");
    assert_eq!(filled.admit(200, 1, 8, true), AdmitOutcome::ReadyToApply { seq: 1 });
    assert!(
        matches!(filled.applied(2), Err(ReorderError::Protocol(msg)) if msg.contains("contiguous")),
        "arrival order must not apply"
    );
    assert_eq!(apply_order(&mut filled, 1)?, vec![1, 2]);
    filled.note_local_work();
    assert_eq!(filled.tick(200), Tick::Idle, "local-only WS avoids a pull");
    assert_eq!(filled.tick(500), Tick::Idle, "hole filled before 500 ms, no Resume");

    let mut missing = buf();
    assert_eq!(missing.admit(0, 2, 8, true), buffered(2));
    assert_eq!(missing.tick(499), Tick::Idle);
    assert_eq!(missing.tick(500), catch_up(0), "one pull at 500 ms for a missing sibling");
    assert_eq!(missing.tick(500), Tick::Idle, "exactly one catch-up in flight");
    Ok(())
}

#[test]
fn gap_timer() {
    let mut buffer = buf();
    assert_eq!(buffer.admit(0, 2, 8, true), buffered(2));
    assert_eq!(buffer.tick(0), Tick::Idle);
    assert_eq!(buffer.tick(499), Tick::Idle, "no Resume before 500 ms");
    assert_eq!(buffer.tick(500), catch_up(0), "exactly one Resume at 500 ms");
    assert!(buffer.in_flight());
    assert_eq!(buffer.tick(5_000), Tick::Idle, "a 5 s wait must not spawn a second Resume");
}

#[test]
fn coalesced_resync() {
    let mut held = buf();
    assert_eq!(held.admit(0, 2, 8, true), buffered(2));
    held.note_hint(CatchUpHint::Resync);
    assert_eq!(held.tick(0), catch_up(0));
    held.note_hint(CatchUpHint::Lagged);
    held.note_hint(CatchUpHint::SafetySweep);
    held.note_hint(CatchUpHint::Retry);
    held.note_hint(CatchUpHint::Connected);
    assert!(held.follow_up(), "hints during the held run coalesce to one follow-up");
    assert_eq!(held.tick(0), Tick::Idle);
    held.finish_catch_up();
    assert_eq!(held.tick(0), catch_up(0), "exactly one follow-up after the held run");
    held.finish_catch_up();
    assert_eq!(held.tick(0), Tick::Idle, "no third catch-up");

    overflow_and_yield();
}

fn overflow_and_yield() {
    let mut refs = buf();
    admit_range(&mut refs, 2, MAX_REFS, 8);
    assert_eq!(refs.len(), MAX_REFS);
    let overflow = refs.admit(0, 2 + MAX_REFS as u64, 8, true);
    assert_eq!(
        overflow,
        AdmitOutcome::Buffered { seq: 2 + MAX_REFS as u64, dropped: Some(2 + MAX_REFS as u64) }
    );
    assert_eq!(refs.len(), MAX_REFS, "lowest-first retention");
    assert!(!refs.contains(2 + MAX_REFS as u64));
    assert_eq!(refs.overflow_acks(), 0, "overflow sends no ACK");

    let mut bulky = buf();
    admit_range(&mut bulky, 2, 8, MAX_REF_BYTES / 8);
    let over_bytes = bulky.admit(0, 10, 1, true);
    assert_eq!(over_bytes, AdmitOutcome::Buffered { seq: 10, dropped: Some(10) });
    assert_eq!(bulky.bytes(), MAX_REF_BYTES);
    assert_eq!(bulky.overflow_acks(), 0);

    let mut pages = buf();
    pages.note_hint(CatchUpHint::Resync);
    assert_eq!(pages.tick(0), catch_up(0));
    for _ in 1..YIELD_AFTER_PAGES {
        assert!(!pages.record_page());
    }
    assert!(pages.record_page(), "yield every 16 pages");
    assert_eq!(pages.tick(0), catch_up(0), "yield coalesces one follow-up");

    let mut turn = buf();
    admit_range(&mut turn, 2, 70, 8);
    assert_eq!(turn.admit(0, 1, 8, true), AdmitOutcome::ReadyToApply { seq: 1 });
    turn.applied(1).expect("C+1");
    assert_eq!(turn.peek_contiguous().len(), PAGE_LIMIT as usize, "64 boundaries per turn");
}

struct Harness {
    _root: tempfile::TempDir,
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
    Ok(Harness { _root: root, db })
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

fn retired_page<'a>(losses: &'a [ApplyLoss<'a>]) -> ApplyPage<'a> {
    ApplyPage {
        target: "t",
        incarnation: "e",
        after: 0,
        covered: 2,
        issued: 2,
        settled: 0,
        entries: &[],
        known_losses: losses,
        oversize_next: None,
        more: false,
    }
}

fn snap(db: &AccountDb) -> Result<ReceiveLedgerSnap, StorageError> {
    db.receive_ledger_snap_for_test("t")
}

#[test]
fn buffered_push_survives_router_retirement() -> Result<(), ApplyError> {
    ram_only_page_marks_loss()?;
    durable_stage_survives_retirement()?;
    Ok(())
}

fn ram_only_page_marks_loss() -> Result<(), ApplyError> {
    let harness = open()?;
    let db = &harness.db;
    let mut ram = buf();
    assert_eq!(
        ram.admit(0, 2, 8, false),
        AdmitOutcome::Refused { seq: 2 },
        "higher push without W0 is not a RAM-only copy"
    );
    let losses = [ApplyLoss { from_seq: 1, to_seq: 2, reason: "expired" }];
    assert_eq!(
        apply_page(db, expected(db, 0)?, 1, retired_page(&losses))?,
        ApplyOutcome::Covered { cursor: 2 }
    );
    let lost = snap(db)?;
    assert!(
        lost.losses.iter().any(|row| row.0 <= 2 && row.1 >= 2 && row.3 == "expired"),
        "RAM-only content is marked lost: {lost:?}"
    );
    Ok(())
}

fn durable_stage_survives_retirement() -> Result<(), ApplyError> {
    let harness = open()?;
    let db = &harness.db;
    stage(db, 0, 2)?;
    let mut buffer = buf();
    assert_eq!(buffer.admit(0, 2, 8, true), buffered(2));
    drop(buffer);
    let losses = [ApplyLoss { from_seq: 1, to_seq: 2, reason: "expired" }];
    assert_eq!(
        apply_page(db, expected(db, 0)?, 1, retired_page(&losses))?,
        ApplyOutcome::NeedStage { sequence: 2, cursor: 1 }
    );
    let held = snap(db)?;
    assert_eq!(held.receipts, vec![(2, "staged".into())]);
    assert_eq!(held.work, 1);
    assert!(
        !held.losses.iter().any(|row| row.0 <= 2 && row.1 >= 2 && row.3 == "expired" && row.0 != 1),
        "seq 2 is not a loss: {held:?}"
    );
    assert_eq!(held.losses, vec![(1, 1, 1, "expired".into())]);
    db.set_receipt_disposition_for_test(2, "completed")?;
    assert_eq!(
        apply_page(db, expected(db, 1)?, 1, retired_page(&losses))?,
        ApplyOutcome::Covered { cursor: 2 }
    );
    let once = snap(db)?;
    assert_eq!(once.cursor, 2);
    assert_eq!(once.receipts, Vec::<(u64, String)>::new());
    assert_eq!(once.intents, vec![2]);
    assert_eq!(once.work, 0);
    assert_eq!(
        apply_page(db, expected(db, 2)?, 1, retired_page(&losses))?,
        ApplyOutcome::AlreadyCovered { cursor: 2 },
        "C+2 processed once"
    );
    Ok(())
}
