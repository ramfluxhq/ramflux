// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named cells for the dormant S6b P18 compat executor.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::{
    AckDecision, AdmitRequest, CLOCK_SKEW_SECS, CompatExecutor, FRAME_LIMIT_FALLBACK,
    FRAME_LIMIT_INITIAL, FRAME_MAX_BYTES, FrameOutcome, LOOKUP_LIMIT, LookupReply, SWEEP_SECS,
    TURN_INTENTS, authorize_legacy_ack, fallback_deadline, on_legacy_frame, resume_same_e,
    start_session,
};
use crate::prelude::SdkError;
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult,
    ReceiveExpectation, ReceiveLedgerSnap, ReceiveReset, ReceiveResetReason, ReceiveResetResult,
    ReceiveStage, ReceiveStageResult, StorageError,
};
use std::time::Duration;

pub(super) struct HangGuard(Option<std::sync::mpsc::Sender<()>>);

impl Drop for HangGuard {
    fn drop(&mut self) {
        let _ = self.0.take();
    }
}

pub(super) fn hang_guard() -> HangGuard {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if matches!(
            rx.recv_timeout(Duration::from_secs(30)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            eprintln!("30-second hang guard expired");
            std::process::abort();
        }
    });
    HangGuard(Some(tx))
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

fn executor(db: &AccountDb, cursor: u64) -> Result<CompatExecutor<'static>, StorageError> {
    Ok(CompatExecutor { expected: expected(db, cursor)?, generation: 1 })
}

fn wire(seq: u64, envelope_id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"inbox_seq":seq,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":envelope_id,"source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":"hash"
    }}))
    .expect("entry")
}

fn stage(
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    envelope_id: &str,
) -> Result<(), StorageError> {
    let bytes = wire(sequence, envelope_id);
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

fn admit(db: &AccountDb, cursor: u64, sequence: u64) -> Result<(), SdkError> {
    let request = AdmitRequest { sequence, now: 10 };
    let result = executor(db, cursor)?.admit(db, &request)?;
    assert_eq!(result, ReceiveCoverResult::Covered);
    Ok(())
}

fn snap(db: &AccountDb) -> Result<ReceiveLedgerSnap, StorageError> {
    db.receive_ledger_snap_for_test("t")
}

fn due_retained(db: &AccountDb, cursor: u64) -> Result<Vec<u64>, StorageError> {
    db.receive_transaction(expected(db, cursor)?, 1, |tx| tx.due_retained(64))
}

fn proof_rows(db: &AccountDb) -> Result<u64, StorageError> {
    Ok(db.actor_state_usage("gateway/compat-proof/")?.0)
}

fn entry<'a>(seq: u64, envelope_id: &'a str, payload_hash: &'a str) -> LookupReply<'a> {
    LookupReply::Entry { seq, envelope_id, payload_hash, incarnation: None }
}

fn cut_admit_ack(db: &AccountDb) -> Result<(), SdkError> {
    stage(db, 0, 1, "env-1")?;
    admit(db, 0, 1)?;
    let after_admit = snap(db)?;
    assert_eq!(after_admit.cursor, 1);
    assert_eq!(after_admit.work, 1, "compat W2 keeps the registered proof copy");
    assert_eq!(after_admit.receipts, vec![(1, "completed".into())]);
    assert_eq!(after_admit.intents, vec![1]);
    assert!(due_retained(db, 1)?.is_empty(), "WS skips terminal compat rows");
    assert_eq!(proof_rows(db)?, 0, "equality proof is the work row, not actor state");
    assert_eq!(
        authorize_legacy_ack(db, "t", "e", 1, None, &entry(1, "env-1", "hash"))?,
        AckDecision::Authorize,
        "content equality authorizes"
    );
    assert_eq!(snap(db)?, after_admit, "ACK before WA retains work, receipt, intent and C");
    assert_eq!(
        authorize_legacy_ack(db, "t", "e", 1, None, &entry(1, "env-reused", "other"))?,
        AckDecision::RefuseSequenceAlone,
        "sequence alone never ACKs unseen reused content"
    );
    assert_eq!(
        authorize_legacy_ack(db, "t", "e", 1, None, &LookupReply::Empty { first_seq: None })?,
        AckDecision::SettleAbsent,
        "crash after ACK: empty lookup with local proof settles absent"
    );
    assert_eq!(
        authorize_legacy_ack(db, "t", "e", 1, Some("e"), &LookupReply::Empty { first_seq: None })?,
        AckDecision::SettleAbsent,
        "same-E empty lookup settles absence"
    );
    Ok(())
}

fn cut_reset_releases_terminal(db: &AccountDb) -> Result<(), SdkError> {
    stage(db, 1, 2, "env-2")?;
    db.receive_transaction(expected(db, 1)?, 1, |tx| {
        tx.cover(ReceiveCover {
            sequence: 2,
            kind: ReceiveCoverKind::Held,
            gaps: &[],
            retain_until: 0,
        })
    })?;
    assert_eq!(snap(db)?.work, 2, "held work plus terminal proof");
    db.mark_receive_incarnation_unverified_for_test("t")?;
    let reset_out = db.receive_transaction(expected(db, 2)?, 1, |tx| {
        tx.reset(ReceiveReset {
            new_incarnation: "e2",
            settled: 30,
            issued: 30,
            after: 0,
            reason: ReceiveResetReason::IncarnationFirstVerified,
        })
    })?;
    assert_eq!(reset_out, ReceiveResetResult::Reset);
    let after_reset = snap(db)?;
    assert!(after_reset.intents.is_empty(), "reset drops terminal intents");
    assert_eq!(after_reset.work, 1, "held work retained");
    assert_eq!(
        after_reset.receipts,
        vec![(2, "held".into())],
        "P10 reset releases terminal compat"
    );
    assert_eq!(after_reset.cursor, 30, "reset C=S");
    Ok(())
}

fn cut_erasure_refuses_ack() -> Result<(), SdkError> {
    let harness = open()?;
    let db = &harness.db;
    stage(db, 0, 1, "env-1")?;
    admit(db, 0, 1)?;
    db.erase_receive_work_for_test(1)?;
    assert_eq!(
        authorize_legacy_ack(db, "t", "e", 1, None, &entry(1, "env-1", "hash"))?,
        AckDecision::Suspend,
        "legacy ACK after erasure is refused"
    );
    Ok(())
}

fn cut_strict_proof_parse() -> Result<(), SdkError> {
    let harness = open()?;
    let db = &harness.db;
    stage(db, 0, 1, "env-1")?;
    admit(db, 0, 1)?;
    db.overwrite_receive_work_json_for_test(br#"{"envelope_id":"x","payload_hash":"y"}"#)?;
    match authorize_legacy_ack(db, "t", "e", 1, None, &entry(1, "x", "y")) {
        Err(SdkError::Storage(StorageError::Integrity("compat work encoding"))) => {}
        other => panic!("strict proof parse, got {other:?}"),
    }
    Ok(())
}

fn cut_turn_scan() -> Result<(), SdkError> {
    let harness = open()?;
    let db = &harness.db;
    for seq in 1..=17 {
        stage(db, seq - 1, seq, &format!("env-{seq}"))?;
        admit(db, seq - 1, seq)?;
    }
    let due = db.due_ack_intents("t", "e", 10, TURN_INTENTS)?;
    assert_eq!(due.len(), 16, "one turn scans 16");
    assert_eq!(due[0], 1);
    assert_eq!(due[15], 16);
    assert_eq!(db.due_ack_intents("t", "e", 10, 32)?.len(), 17);
    assert!(due_retained(db, 17)?.is_empty(), "seventeen terminal compat rows are not WS work");
    Ok(())
}

fn cut_proofless_suspend() -> Result<(), SdkError> {
    let harness = open()?;
    let db = &harness.db;
    assert_eq!(
        authorize_legacy_ack(db, "t", "e", 9, None, &entry(9, "ghost", "hash"))?,
        AckDecision::Suspend
    );
    resume_same_e(db, "t", "e", 9)?;
    let _ = snap(db)?;
    Ok(())
}

#[test]
fn compat_intent_transition() -> Result<(), SdkError> {
    let _hang = hang_guard();
    assert_eq!(LOOKUP_LIMIT, 1);
    assert_eq!(TURN_INTENTS, 16);
    assert_eq!(SWEEP_SECS, 5);
    let harness = open()?;
    cut_admit_ack(&harness.db)?;
    cut_reset_releases_terminal(&harness.db)?;
    cut_erasure_refuses_ack()?;
    cut_strict_proof_parse()?;
    cut_turn_scan()?;
    cut_proofless_suspend()?;
    Ok(())
}

#[test]
fn legacy_deadline_clock_skew() -> Result<(), SdkError> {
    let _hang = hang_guard();
    // ttl = 604800 so the first_seen+604800+120 term is the binding one when the
    // client clock is slow.
    let accepted = 1_000;
    let ttl = 604_800;
    let router_cap = accepted + ttl;
    // Client slow by exactly 120 s: fallback equals router cap, not flagged.
    let at_lag = fallback_deadline(accepted, ttl, accepted - CLOCK_SKEW_SECS, None)?;
    assert_eq!(at_lag.expires_at, router_cap, "lag 120s fallback is not earlier than router cap");
    assert!(!at_lag.fallback_clock_unverified);
    assert!(at_lag.guaranteed_retirement);

    // Client slow by 121 s: flagged, no guaranteed retirement.
    let over = fallback_deadline(accepted, ttl, accepted - CLOCK_SKEW_SECS - 1, None)?;
    assert!(over.fallback_clock_unverified);
    assert!(!over.guaranteed_retirement, "lag>120s never claims guaranteed retirement");

    // Delayed delivery with correct clocks (first_seen well after acceptance): not flagged.
    let delayed = fallback_deadline(accepted, ttl, accepted + 3_600, None)?;
    assert!(!delayed.fallback_clock_unverified, "delivery delay is not clock skew");
    assert_eq!(delayed.expires_at, router_cap);
    assert!(delayed.guaranteed_retirement);

    let first_seen = 1_000i64;
    let bound = fallback_deadline(first_seen + CLOCK_SKEW_SECS, 604_800, first_seen, None)?;
    assert_eq!(
        bound.expires_at,
        first_seen + 604_800 + CLOCK_SKEW_SECS,
        "first_seen+604800+120 is the binding minimum"
    );

    let supplied = fallback_deadline(accepted, ttl, accepted + 1_000, Some(9_999))?;
    assert_eq!(supplied.expires_at, 9_999);
    assert!(!supplied.fallback_clock_unverified);
    assert!(supplied.guaranteed_retirement);

    assert!(
        fallback_deadline(i64::MAX, 1, i64::MAX, None).is_err(),
        "checked add refuses overflow"
    );
    Ok(())
}

#[test]
fn compat_frame_limit_fallback() -> Result<(), SdkError> {
    let _hang = hang_guard();
    let mut session = start_session();
    assert_eq!(session.limit, FRAME_LIMIT_INITIAL);
    let oversize_page = FRAME_MAX_BYTES + 1;
    assert_eq!(
        on_legacy_frame(&mut session, oversize_page, 64, 0),
        FrameOutcome::RetryFresh { limit: FRAME_LIMIT_FALLBACK }
    );
    assert_eq!(session.limit, FRAME_LIMIT_FALLBACK);
    assert_eq!(session.reconnects, 1);
    assert_eq!(
        on_legacy_frame(&mut session, 1_024, 1, 0),
        FrameOutcome::Accept { limit: FRAME_LIMIT_FALLBACK }
    );

    let mut protocol = start_session();
    assert_eq!(
        on_legacy_frame(&mut protocol, oversize_page, 64, 0),
        FrameOutcome::RetryFresh { limit: FRAME_LIMIT_FALLBACK }
    );
    let before = protocol.reconnects;
    assert_eq!(
        on_legacy_frame(&mut protocol, oversize_page, 2, 0),
        FrameOutcome::Pause { reason: "legacy_frame_protocol" }
    );
    assert_eq!(protocol.paused_reason, Some("legacy_frame_protocol"));
    assert_eq!(protocol.reconnects, before, "protocol error does not reconnect");
    assert_eq!(
        on_legacy_frame(&mut protocol, 1_024, 1, 0),
        FrameOutcome::Pause { reason: "legacy_frame_protocol" },
        "paused_reason blocks a later Accept"
    );

    // L3: limit-1 frame under F with multiple entries is an exact protocol error.
    let mut under_size = start_session();
    on_legacy_frame(&mut under_size, oversize_page, 64, 0);
    assert_eq!(
        on_legacy_frame(&mut under_size, 1_024, 2, 0),
        FrameOutcome::Pause { reason: "legacy_frame_protocol" }
    );
    assert_eq!(under_size.paused_reason, Some("legacy_frame_protocol"));
    assert_eq!(under_size.reconnects, 1, "protocol error does not reconnect");

    let harness = open()?;
    let db = &harness.db;
    for seq in 1..=7 {
        stage(db, seq - 1, seq, &format!("env-{seq}"))?;
        admit(db, seq - 1, seq)?;
    }
    assert_eq!(snap(db)?.cursor, 7);
    let mut stuck = start_session();
    assert_eq!(
        on_legacy_frame(&mut stuck, oversize_page, 64, 7),
        FrameOutcome::RetryFresh { limit: FRAME_LIMIT_FALLBACK }
    );
    assert_eq!(
        on_legacy_frame(&mut stuck, oversize_page, 1, 7),
        FrameOutcome::Pause { reason: "legacy_entry_too_large" }
    );
    assert_eq!(stuck.paused_reason, Some("legacy_entry_too_large"));
    assert_eq!(snap(db)?.cursor, 7, "pause keeps C fixed");
    Ok(())
}
