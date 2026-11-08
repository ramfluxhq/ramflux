// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named cells for the dormant S6b P18 compat executor.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::{
    AckDecision, AdmitRequest, CLOCK_SKEW_SECS, CompatExecutor, ContentProof, FRAME_LIMIT_FALLBACK,
    FRAME_LIMIT_INITIAL, FRAME_MAX_BYTES, FrameOutcome, LOOKUP_LIMIT, LookupReply, SWEEP_SECS,
    TURN_INTENTS, authorize_legacy_ack, fallback_deadline, on_legacy_frame,
    reset_compat_incarnation, resume_same_e, start_session,
};
use crate::prelude::SdkError;
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult,
    ReceiveExpectation, ReceiveLedgerSnap, ReceiveStage, ReceiveStageResult, StorageError,
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

fn proof(envelope_id: &str) -> ContentProof {
    ContentProof { envelope_id: envelope_id.to_owned(), payload_hash: "hash".into() }
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

fn admit(db: &AccountDb, cursor: u64, sequence: u64, envelope_id: &str) -> Result<(), SdkError> {
    let bytes = wire(sequence, envelope_id);
    let request = AdmitRequest {
        sequence,
        entry_json: &bytes,
        admission_key: "authenticated-key",
        retain_until: 100,
        first_seen: 1,
        proof: proof(envelope_id),
        now: 10,
    };
    let result = executor(db, cursor)?.admit(db, &request)?;
    assert_eq!(result, ReceiveCoverResult::Covered);
    Ok(())
}

fn snap(db: &AccountDb) -> Result<ReceiveLedgerSnap, StorageError> {
    db.receive_ledger_snap_for_test("t")
}

#[test]
fn compat_intent_transition() -> Result<(), SdkError> {
    let _hang = hang_guard();
    assert_eq!(LOOKUP_LIMIT, 1);
    assert_eq!(TURN_INTENTS, 16);
    assert_eq!(SWEEP_SECS, 5);

    let harness = open()?;
    let db = &harness.db;
    stage(db, 0, 1, "env-1")?;
    admit(db, 0, 1, "env-1")?;
    let after_admit = snap(db)?;
    assert_eq!(after_admit.cursor, 1);
    assert_eq!(after_admit.work, 1, "compat W2 keeps the registered proof copy");
    assert_eq!(after_admit.receipts.len(), 1);
    assert_eq!(after_admit.intents, vec![1]);

    let lookup = LookupReply::Entry {
        seq: 1,
        envelope_id: "env-1",
        payload_hash: "hash",
        incarnation: None,
    };
    assert_eq!(
        authorize_legacy_ack(db, "t", "e", 1, None, &lookup)?,
        AckDecision::Authorize,
        "content equality authorizes"
    );
    assert_eq!(snap(db)?, after_admit, "ACK before WA retains work, receipt, intent and C");

    let reused = LookupReply::Entry {
        seq: 1,
        envelope_id: "env-reused",
        payload_hash: "other",
        incarnation: None,
    };
    assert_eq!(
        authorize_legacy_ack(db, "t", "e", 1, None, &reused)?,
        AckDecision::RefuseSequenceAlone,
        "sequence alone never ACKs unseen reused content"
    );

    assert_eq!(
        authorize_legacy_ack(db, "t", "e", 1, Some("e"), &LookupReply::Empty { first_seq: None })?,
        AckDecision::SettleAbsent,
        "same-E empty lookup settles absence"
    );

    stage(db, 1, 2, "env-2")?;
    db.receive_transaction(expected(db, 1)?, 1, |tx| {
        tx.cover(ReceiveCover {
            sequence: 2,
            kind: ReceiveCoverKind::Held,
            gaps: &[],
            retain_until: 0,
        })
    })?;
    let before_reset = snap(db)?;
    assert_eq!(before_reset.work, 2, "held work plus terminal proof");
    db.receive_transaction(expected(db, 2)?, 1, |tx| reset_compat_incarnation(tx, "t", 30))?;
    let after_reset = snap(db)?;
    assert!(after_reset.intents.is_empty(), "reset drops terminal intents");
    assert_eq!(after_reset.work, 1, "held work retained");
    assert_eq!(after_reset.receipts.len(), 1, "held receipt retained");
    assert_eq!(after_reset.cursor, 30, "reset C=S");

    let harness = open()?;
    let db = &harness.db;
    for seq in 1..=17 {
        stage(db, seq - 1, seq, &format!("env-{seq}"))?;
        admit(db, seq - 1, seq, &format!("env-{seq}"))?;
    }
    let due = db.due_ack_intents("t", "e", 10, TURN_INTENTS)?;
    assert_eq!(due.len(), 16, "one turn scans 16");
    assert_eq!(due[0], 1);
    assert_eq!(due[15], 16);
    let rest = db.due_ack_intents("t", "e", 10, 32)?;
    assert_eq!(rest.len(), 17);

    let harness = open()?;
    let db = &harness.db;
    assert_eq!(
        authorize_legacy_ack(
            db,
            "t",
            "e",
            9,
            None,
            &LookupReply::Entry {
                seq: 9,
                envelope_id: "ghost",
                payload_hash: "hash",
                incarnation: None
            }
        )?,
        AckDecision::Suspend
    );
    resume_same_e(db, "t", "e", 9)?;
    let _ = snap(db)?;
    Ok(())
}

#[test]
fn legacy_deadline_clock_skew() {
    let _hang = hang_guard();
    let created = 1_000;
    let ttl = 100;
    let first_seen = 1_000;
    let router_cap = created + ttl;
    let at_lag = fallback_deadline(created, ttl, first_seen, created + CLOCK_SKEW_SECS, None);
    assert_eq!(at_lag.expires_at, router_cap, "lag 120s fallback is not earlier than router cap");
    assert!(!at_lag.fallback_clock_unverified);
    assert!(at_lag.guaranteed_retirement);

    let over = fallback_deadline(created, ttl, first_seen, created + CLOCK_SKEW_SECS + 1, None);
    assert!(over.fallback_clock_unverified);
    assert!(!over.guaranteed_retirement, "lag>120s never claims guaranteed retirement");

    let supplied = fallback_deadline(created, ttl, first_seen, created + 1_000, Some(9_999));
    assert_eq!(supplied.expires_at, 9_999);
    assert!(!supplied.fallback_clock_unverified);
    assert!(supplied.guaranteed_retirement);
}

#[test]
fn compat_frame_limit_fallback() {
    let _hang = hang_guard();
    let mut session = start_session();
    let covered = 7u64;
    assert_eq!(session.limit, FRAME_LIMIT_INITIAL);
    let oversize_page = FRAME_MAX_BYTES + 1;
    assert_eq!(
        on_legacy_frame(&mut session, oversize_page, 64, covered),
        FrameOutcome::RetryFresh { limit: FRAME_LIMIT_FALLBACK }
    );
    assert_eq!(session.limit, FRAME_LIMIT_FALLBACK);
    assert_eq!(session.reconnects, 1);
    assert_eq!(
        on_legacy_frame(&mut session, 1_024, 1, covered),
        FrameOutcome::Accept { limit: FRAME_LIMIT_FALLBACK }
    );

    let mut stuck = start_session();
    assert_eq!(
        on_legacy_frame(&mut stuck, oversize_page, 64, covered),
        FrameOutcome::RetryFresh { limit: FRAME_LIMIT_FALLBACK }
    );
    let before = stuck.reconnects;
    assert_eq!(
        on_legacy_frame(&mut stuck, oversize_page, 1, covered),
        FrameOutcome::Pause { reason: "legacy_entry_too_large" }
    );
    assert_eq!(stuck.paused_reason, Some("legacy_entry_too_large"));
    assert_eq!(stuck.reconnects, before, "paused single entry does not reconnect");
    assert_eq!(covered, 7, "pause keeps C fixed");
}
