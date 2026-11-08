// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P20d complete: hold quotas through [`SourceHold::admit_in`]. Storage first-leg stays in `hold_tests`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::bus::sync_driver::source::hold::{HoldDisposition, SourceHold};
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveExpectation, ReceiveHold, ReceiveHoldClass,
    ReceiveHoldJournal, ReceiveHoldResult, ReceiveLedgerSnap, ReceiveStage, ReceiveStageResult,
    StorageError,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const SOURCE_BYTES: i64 = 4 * 1024 * 1024;

struct Harness {
    _root: tempfile::TempDir,
    db: AccountDb,
}

fn open(name: &str) -> Result<Harness, StorageError> {
    let _ = name;
    let root = tempfile::tempdir().expect("tmp");
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", "principal")?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test("t", "e")?;
    Ok(Harness { _root: root, db })
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

fn wire(seq: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"inbox_seq":seq,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":format!("env-{seq}"),"source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":format!("hash-{seq}")
    }}))
    .expect("entry")
}

fn stage(
    db: &AccountDb,
    incarnation: &'static str,
    cursor: u64,
    sequence: u64,
    key: &str,
) -> Result<Vec<u8>, StorageError> {
    let bytes = wire(sequence);
    let result = db.receive_transaction(expected(db, incarnation, cursor)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation,
            sequence,
            entry_json: &bytes,
            admission_key: key,
            retain_until: 604_801,
            first_seen: i64::try_from(sequence).unwrap_or(i64::MAX),
        })
    })?;
    assert!(matches!(result, ReceiveStageResult::Staged | ReceiveStageResult::Existing));
    Ok(bytes)
}

fn admit(
    db: &AccountDb,
    incarnation: &'static str,
    cursor: u64,
    sequence: u64,
    key: &str,
    class: ReceiveHoldClass,
) -> Result<HoldDisposition, StorageError> {
    let unrouted = class == ReceiveHoldClass::Unrouted;
    let source_key = format!("unrouted:{key}");
    let body = serde_json::json!({
        "envelope_id": format!("env-{sequence}"),
        "claimed_source_device_id": "claimed-only",
        "payload_hash": format!("hash-{sequence}"),
        "inbox_seq": sequence,
    });
    db.receive_transaction(expected(db, incarnation, cursor)?, 1, |tx| {
        SourceHold::admit_in(
            tx,
            ReceiveHold {
                sequence,
                admission_key: key,
                class,
                contact_root: None,
                unrouted_id: unrouted.then_some(key),
                journal: unrouted.then_some(ReceiveHoldJournal {
                    source_key: &source_key,
                    topic: "message.unrouted",
                    body: &body,
                    subject: None,
                }),
                at: i64::try_from(sequence).unwrap_or(i64::MAX),
            },
        )
    })
}

fn snap(db: &AccountDb) -> Result<ReceiveLedgerSnap, StorageError> {
    db.receive_ledger_snap_for_test("t")
}

fn evicted_events(db: &AccountDb) -> Result<usize, StorageError> {
    Ok(db
        .journal_after(0, 128)?
        .into_iter()
        .filter(|event| {
            event.topic == "inbox.receive_failure"
                && event.body.get("reason").and_then(serde_json::Value::as_str)
                    == Some("held_evicted")
        })
        .count())
}

fn row_unrouted_class_evicts(db: &AccountDb) -> TestResult {
    let mut cursor = 0u64;
    for sequence in 1..=65 {
        let key = format!("admission-{sequence}");
        let source = format!("root-unrouted-{sequence}/device");
        db.seed_inbox_policy_for_test(&key, &source)?;
        stage(db, "e", cursor, sequence, &key)?;
        let outcome = admit(db, "e", cursor, sequence, &key, ReceiveHoldClass::Unrouted)?;
        assert!(matches!(outcome, HoldDisposition::HeldLocal { .. }), "{outcome:?}");
        cursor = sequence;
    }
    let done = snap(db)?;
    assert_eq!(done.cursor, 65);
    assert_eq!(done.work, 64);
    assert_eq!(done.receipts.iter().filter(|(_, disposition)| disposition == "held").count(), 64);
    assert_eq!(evicted_events(db)?, 1, "oldest eviction has one typed event");
    assert!(done.intents.contains(&1), "evicted hold wrote an ACK intent");
    Ok(())
}

fn row_aggregate_over_evicts(db: &AccountDb) -> TestResult {
    let mut cursor = 0u64;
    for sequence in 1..=4 {
        let key = format!("agg-{sequence}");
        let source = format!("root-agg-{sequence}/device");
        db.seed_inbox_policy_for_test(&key, &source)?;
        stage(db, "e", cursor, sequence, &key)?;
        db.set_receive_work_bytes_for_test(sequence, SOURCE_BYTES)?;
        assert!(matches!(
            admit(db, "e", cursor, sequence, &key, ReceiveHoldClass::Policy)?,
            HoldDisposition::HeldLocal { .. }
        ));
        cursor = sequence;
    }
    db.seed_inbox_policy_for_test("agg-5", "root-agg-5/device")?;
    stage(db, "e", cursor, 5, "agg-5")?;
    db.set_receive_work_bytes_for_test(5, 1)?;
    assert_eq!(
        admit(db, "e", cursor, 5, "agg-5", ReceiveHoldClass::Policy)?,
        HoldDisposition::HeldLocal { evicted: vec![1] }
    );
    Ok(())
}

fn row_policy_retry_dropped(db: &AccountDb) -> TestResult {
    let source = "root-pol/device";
    db.seed_inbox_policy_for_test("admission-1", source)?;
    let wire = stage(db, "e", 0, 1, "admission-1")?;
    assert!(matches!(
        admit(db, "e", 0, 1, "admission-1", ReceiveHoldClass::Policy)?,
        HoldDisposition::HeldLocal { .. }
    ));
    db.defer_inbox_entry("admission-1", &wire, 1)?;
    assert_eq!(db.inbox_retry_and_policy_counts_for_test("admission-1")?, (1, 1));
    let mut cursor = 1u64;
    for sequence in 2..=8 {
        let key = format!("admission-{sequence}");
        db.seed_inbox_policy_for_test(&key, source)?;
        stage(db, "e", cursor, sequence, &key)?;
        assert!(matches!(
            admit(db, "e", cursor, sequence, &key, ReceiveHoldClass::Policy)?,
            HoldDisposition::HeldLocal { evicted } if evicted.is_empty()
        ));
        cursor = sequence;
    }
    db.seed_inbox_policy_for_test("admission-9", source)?;
    stage(db, "e", cursor, 9, "admission-9")?;
    assert_eq!(
        admit(db, "e", cursor, 9, "admission-9", ReceiveHoldClass::Policy)?,
        HoldDisposition::HeldLocal { evicted: vec![1] }
    );
    assert_eq!(
        db.inbox_retry_and_policy_counts_for_test("admission-1")?,
        (0, 0),
        "evicted policy hold drops retry and policy rows"
    );
    Ok(())
}

fn row_policy_retry_kept_on_live_redelivery(db: &AccountDb) -> TestResult {
    let source = "root-pol/device";
    db.seed_inbox_policy_for_test("shared", source)?;
    let wire = stage(db, "e", 0, 1, "shared")?;
    assert!(matches!(
        admit(db, "e", 0, 1, "shared", ReceiveHoldClass::Policy)?,
        HoldDisposition::HeldLocal { .. }
    ));
    db.defer_inbox_entry("shared", &wire, 1)?;
    db.retire_receive_incarnation_for_test("t", "e", "e2")?;
    stage(db, "e2", 0, 1, "shared")?;
    assert!(matches!(
        admit(db, "e2", 0, 1, "shared", ReceiveHoldClass::Policy)?,
        HoldDisposition::HeldLocal { .. }
    ));
    let mut cursor = 1u64;
    for sequence in 2..=7 {
        let key = format!("fill-{sequence}");
        db.seed_inbox_policy_for_test(&key, source)?;
        stage(db, "e2", cursor, sequence, &key)?;
        assert!(matches!(
            admit(db, "e2", cursor, sequence, &key, ReceiveHoldClass::Policy)?,
            HoldDisposition::HeldLocal { evicted } if evicted.is_empty()
        ));
        cursor = sequence;
    }
    db.seed_inbox_policy_for_test("fill-8", source)?;
    stage(db, "e2", cursor, 8, "fill-8")?;
    assert_eq!(
        admit(db, "e2", cursor, 8, "fill-8", ReceiveHoldClass::Policy)?,
        HoldDisposition::HeldLocal { evicted: vec![1] }
    );
    assert_eq!(
        db.inbox_retry_and_policy_counts_for_test("shared")?,
        (1, 1),
        "live redelivery keeps the retry and policy rows"
    );
    Ok(())
}

#[test]
fn hold_source_class_quotas() -> TestResult {
    row_unrouted_class_evicts(&open("hold-quotas")?.db)?;
    row_aggregate_over_evicts(&open("hold-aggregate-over")?.db)?;
    row_policy_retry_dropped(&open("hold-policy-retry-evict")?.db)?;
    row_policy_retry_kept_on_live_redelivery(&open("hold-policy-retry-keep")?.db)?;
    assert_eq!(HoldDisposition::Paused, HoldDisposition::Paused);
    let _ = ReceiveHoldResult::Paused;
    Ok(())
}
