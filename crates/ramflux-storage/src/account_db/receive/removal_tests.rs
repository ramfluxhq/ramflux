// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P08 first-leg cells: expiry/eviction and failure-policy admission crash cuts.
#![allow(clippy::expect_used, clippy::panic)]
use super::cover::{ReceiveCover, ReceiveCoverKind, ReceiveCoverResult};
use super::removal::{
    FaultKind, ReceiveFailure, ReceiveFailureKind as FailKind, ReceiveFailureReason,
    ReceiveFailureResult as FailOut, run as with_fault,
};
use super::stage::{ReceiveStage, ReceiveStageResult};
use super::stage_tests::{bytes, setup};
use super::*;
use crate::{InboxFailurePolicy, ProjectionStore, StorageError};
use rusqlite::params;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snap {
    cursor: u64,
    intents: Vec<u64>,
    work: Vec<u64>,
    receipts: Vec<(u64, String)>,
}

fn unverified(at: i64) -> InboxFailurePolicy<'static> {
    InboxFailurePolicy { verified_source: None, trusted: false, dependency: ("none", ""), at }
}

fn pin_source(
    owner: &str,
    name: &str,
) -> Result<ramflux_crypto::RootQualifiedDeviceRef, StorageError> {
    let seed = ramflux_crypto::blake3_256("ramflux.storage.test.pin.v1", owner.as_bytes());
    Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
        &ramflux_crypto::create_identity_root(owner, seed),
        name,
    )?)
}

fn expect(db: &AccountDb, cursor: u64) -> Result<ReceiveExpectation<'static>, StorageError> {
    expect_for(db, "e", cursor)
}

fn expect_for<'a>(
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

fn stage(db: &AccountDb, cursor: u64, sequence: u64, key: &str) -> Result<Vec<u8>, StorageError> {
    let wire = bytes(sequence);
    let result = db.receive_transaction(expect(db, cursor)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation: "e",
            sequence,
            entry_json: &wire,
            admission_key: key,
            retain_until: 100,
            first_seen: i64::try_from(sequence).unwrap_or(i64::MAX),
        })
    })?;
    assert!(matches!(result, ReceiveStageResult::Staged | ReceiveStageResult::Existing));
    Ok(wire)
}

fn cover_held(db: &AccountDb, cursor: u64, sequence: u64) -> Result<(), StorageError> {
    cover_held_for(db, "e", cursor, sequence)
}

fn cover_held_for(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    sequence: u64,
) -> Result<(), StorageError> {
    let out = db.receive_transaction(expect_for(db, incarnation, cursor)?, 1, |tx| {
        tx.cover(ReceiveCover {
            sequence,
            kind: ReceiveCoverKind::Held,
            gaps: &[],
            retain_until: 0,
        })
    })?;
    assert_eq!(out, ReceiveCoverResult::Covered);
    Ok(())
}

fn admit(db: &AccountDb, cursor: u64, input: ReceiveFailure<'_>) -> Result<FailOut, StorageError> {
    db.receive_transaction(expect(db, cursor)?, 1, |tx| tx.admit_failure(input))
}

fn expire_tx(db: &AccountDb, cursor: u64, at: i64) -> Result<Vec<u64>, StorageError> {
    db.receive_transaction(expect(db, cursor)?, 1, |tx| tx.expire_holds(at))
}

fn snap(db: &AccountDb) -> Result<Snap, StorageError> {
    let cursor = db
        .projection_checkpoint("gateway_receive_cursor:t")?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?;
    Ok(Snap {
        cursor,
        intents: seqs(
            db,
            "SELECT inbox_seq FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq",
        )?,
        work: seqs(
            db,
            "SELECT inbox_seq FROM gateway_receive_work WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq",
        )?,
        receipts: {
            let mut out = Vec::new();
            let mut query = db.connection.prepare(
                "SELECT inbox_seq,disposition FROM gateway_receive_receipt WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq",
            )?;
            for row in query.query_map([], |row| Ok((be(row.get(0)?), row.get(1)?)))? {
                out.push(row?);
            }
            out
        },
    })
}

fn seqs(db: &AccountDb, sql: &str) -> Result<Vec<u64>, StorageError> {
    let mut query = db.connection.prepare(sql)?;
    let rows = query.query_map([], |row| Ok(be(row.get(0)?)))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(StorageError::from)
}

fn be(bytes: Vec<u8>) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("be-u64"))
}

fn failure_count(db: &AccountDb, reason: &str) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='inbox.receive_failure'
           AND json_extract(CAST(body_json AS TEXT),'$.reason')=?1",
        params![reason],
        |row| row.get(0),
    )?)
}

fn retry_count(db: &AccountDb, key: &str) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM runtime_inbox_retry WHERE envelope_key=?1",
        params![key],
        |row| row.get(0),
    )?)
}

fn unrouted_for(db: &AccountDb, key: &str) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM runtime_unrouted WHERE envelope_id=?1",
        params![key],
        |row| row.get(0),
    )?)
}

fn policy_window(db: &AccountDb, key: &str) -> Result<(i64, i64, String, String), StorageError> {
    Ok(db.connection.query_row(
        "SELECT trusted,expires_at,failure_class,subject FROM runtime_inbox_policy WHERE envelope_key=?1",
        params![key],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?)
}

fn long_entry() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"envelope":{"created_at":1,"ttl":3600}})).expect("entry")
}

fn reopen(root: &std::path::Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &crate::AccountIndex::open(root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn assert_fault(result: Result<impl std::fmt::Debug, StorageError>) {
    match result {
        Err(StorageError::Integrity(
            "receive failure before-commit" | "receive settle before-commit",
        )) => {}
        other => panic!("expected before-commit, got {other:?}"),
    }
}

fn fill_unrouted_holds(db: &AccountDb, n: u64) -> Result<u64, StorageError> {
    let mut cursor = 0u64;
    for sequence in 1..=n {
        let key = format!("k{sequence}");
        let wire = stage(db, cursor, sequence, &key)?;
        cover_held(db, cursor, sequence)?;
        db.hold_unrouted(&key, sequence, &wire, i64::try_from(sequence).expect("at"))?;
        cursor = sequence;
    }
    Ok(cursor)
}

#[test]
fn held_local_expiry_and_eviction_crash() -> Result<(), StorageError> {
    eviction_cut()?;
    expire_cut()?;
    dead_letter_cut()?;
    contact_expiry_cut()?;
    retired_expiry_cut()?;
    router_retain_until_leaves_staged_and_held()?;
    retired_settle_keeps_live_retry_and_unrouted()?;
    Ok(())
}

fn eviction_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-evict")?;
    let cursor = fill_unrouted_holds(&db, 64)?;
    assert_eq!(cursor, 64);
    assert_eq!(db.unrouted_count()?, 64);
    let pre = snap(&db)?;
    assert_eq!(pre.cursor, 64);
    assert_eq!(pre.work.len(), 64);
    let extra = bytes(65);
    assert_fault(super::settle::run(super::settle::FaultKind::BeforeCommit, || {
        db.hold_unrouted("k65", 65, &extra, 65)
    }));
    assert_eq!(snap(&db)?, pre, "eviction pause keeps C/work/receipt");
    db.hold_unrouted("k65", 65, &extra, 65)?;
    let done = snap(&db)?;
    assert_eq!(done.cursor, 64, "eviction is WS below C");
    assert_eq!(done.work.len(), 63);
    assert!(!done.work.contains(&1), "oldest hold is settled");
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "held_evicted")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    assert_eq!(failure_count(&db, "held_evicted")?, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn expire_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-expire")?;
    let wire = stage(&db, 0, 1, "exp")?;
    cover_held(&db, 0, 1)?;
    db.hold_unrouted("exp", 1, &wire, 1)?;
    db.defer_inbox_entry("exp", &wire, 1)?;
    db.connection
        .execute("UPDATE runtime_inbox_policy SET expires_at=10 WHERE envelope_key='exp'", [])?;
    let pre = snap(&db)?;
    assert_eq!(pre.cursor, 1);
    assert_eq!(pre.work, vec![1]);
    assert_fault(super::settle::run(super::settle::FaultKind::BeforeCommit, || {
        db.expire_inbox_holds(20)
    }));
    assert_eq!(snap(&db)?, pre);
    db.expire_inbox_holds(20)?;
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "held_expired")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn dead_letter_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-dead")?;
    let wire = stage(&db, 0, 1, "dead")?;
    cover_held(&db, 0, 1)?;
    let pre = snap(&db)?;
    assert_fault(super::settle::run(super::settle::FaultKind::BeforeCommit, || {
        db.dead_letter_inbox(
            "dead",
            &wire,
            &serde_json::json!({"error_code":"authentication_failed"}),
            50,
        )
    }));
    assert_eq!(snap(&db)?, pre);
    db.dead_letter_inbox(
        "dead",
        &wire,
        &serde_json::json!({"error_code":"authentication_failed"}),
        50,
    )?;
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "policy_rejected")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn contact_expiry_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-contact")?;
    stage(&db, 0, 1, "contact")?;
    cover_held(&db, 0, 1)?;
    db.connection.execute(
        "INSERT INTO runtime_inbox_policy VALUES('contact','root/device',1,1,10,0,'receive_hold_contact','contact-root',0,0)",
        [],
    )?;
    let pre = snap(&db)?;
    assert_fault(with_fault(FaultKind::BeforeCommit, || expire_tx(&db, 1, 20)));
    assert_eq!(snap(&db)?, pre);
    assert_eq!(expire_tx(&db, 1, 20)?, vec![1]);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "held_expired")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn retired_expiry_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-retired")?;
    stage(&db, 0, 1, "ret")?;
    cover_held(&db, 0, 1)?;
    db.connection.execute(
        "INSERT INTO runtime_inbox_policy VALUES('ret','root/device',1,1,10,0,'none','',0,0)",
        [],
    )?;
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET incarnation_id='live', retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&["e"])?],
    )?;
    let pre = snap(&db)?;
    assert_eq!(pre.cursor, 1);
    assert_eq!(pre.work, vec![1]);
    assert_eq!(pre.intents, Vec::<u64>::new());
    assert_fault(with_fault(FaultKind::BeforeCommit, || expire_tx(&db, 1, 20)));
    assert_eq!(snap(&db)?, pre, "retired expiry pause keeps work and writes no intent");
    assert_eq!(expire_tx(&db, 1, 20)?, vec![1]);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1, "retired E never writes C");
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, Vec::<u64>::new(), "retired E never writes an ACK intent");
    assert_eq!(failure_count(&db, "held_expired")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn router_retain_until_leaves_staged_and_held() -> Result<(), StorageError> {
    let (root, db) = setup("p08-retain")?;
    stage(&db, 0, 1, "held-k")?;
    cover_held(&db, 0, 1)?;
    stage(&db, 1, 2, "staged-k")?;
    db.connection.execute(
        "UPDATE gateway_receive_receipt SET first_seen=0 WHERE incarnation_id='e' AND inbox_seq=?1",
        params![2u64.to_be_bytes().as_slice()],
    )?;
    let pre = snap(&db)?;
    assert_eq!(pre.work, vec![1, 2]);
    assert_eq!(pre.receipts, vec![(1, "held".into()), (2, "staged".into())]);
    assert_eq!(expire_tx(&db, 1, 604_800)?, Vec::<u64>::new());
    assert_eq!(snap(&db)?, pre, "router retain_until does not expire staged or held work");
    assert_eq!(failure_count(&db, "held_expired")?, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn retired_settle_keeps_live_retry_and_unrouted() -> Result<(), StorageError> {
    let (root, db) = setup("p08-live-e")?;
    let wire = stage(&db, 0, 1, "shared")?;
    cover_held(&db, 0, 1)?;
    db.hold_unrouted("shared", 1, &wire, 1)?;
    db.defer_inbox_entry("shared", &wire, 1)?;
    assert_eq!(retry_count(&db, "shared")?, 1);
    assert_eq!(unrouted_for(&db, "shared")?, 1);
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET incarnation_id='e2', retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&["e"])?],
    )?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "0")?;
    let live = bytes(1);
    let staged = db.receive_transaction(expect_for(&db, "e2", 0)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation: "e2",
            sequence: 1,
            entry_json: &live,
            admission_key: "shared",
            retain_until: 100,
            first_seen: 1,
        })
    })?;
    assert!(matches!(staged, ReceiveStageResult::Staged | ReceiveStageResult::Existing));
    cover_held_for(&db, "e2", 0, 1)?;
    db.receive_transaction(expect(&db, 1)?, 1, |tx| {
        tx.settle_failure(1, ReceiveFailureReason::HeldExpired, 20)
    })?;
    let old: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE admission_key='shared' AND incarnation_id='e'",
        [],
        |row| row.get(0),
    )?;
    let live_work: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE admission_key='shared' AND incarnation_id='e2'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(old, 0, "retired E work is settled");
    assert_eq!(live_work, 1, "live E work remains");
    assert_eq!(retry_count(&db, "shared")?, 1, "live redelivery keeps the retry row");
    assert_eq!(unrouted_for(&db, "shared")?, 1, "live redelivery keeps the unrouted row");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn held_purge_scope_and_expiry_boundary() -> Result<(), StorageError> {
    staged_survives_held_purge()?;
    default_expiry_boundary()?;
    Ok(())
}

fn staged_survives_held_purge() -> Result<(), StorageError> {
    let (root, db) = setup("p08-h1")?;
    let wire = stage(&db, 0, 1, "shared")?;
    cover_held(&db, 0, 1)?;
    db.hold_unrouted("shared", 1, &wire, 1)?;
    db.defer_inbox_entry("shared", &wire, 1)?;
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET incarnation_id='e2', retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&["e"])?],
    )?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "0")?;
    let live = bytes(1);
    let staged = db.receive_transaction(expect_for(&db, "e2", 0)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation: "e2",
            sequence: 1,
            entry_json: &live,
            admission_key: "shared",
            retain_until: 100,
            first_seen: 700_000,
        })
    })?;
    assert!(matches!(staged, ReceiveStageResult::Staged | ReceiveStageResult::Existing));
    db.trim_expired_unrouted(700_000)?;
    let live_work: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE admission_key='shared' AND incarnation_id='e2'",
        [],
        |row| row.get(0),
    )?;
    let live_receipt: String = db.connection.query_row(
        "SELECT disposition FROM gateway_receive_receipt WHERE target_delivery_id='t' AND incarnation_id='e2' AND inbox_seq=?1",
        params![1u64.to_be_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let live_intents: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e2'",
        [],
        |row| row.get(0),
    )?;
    let old_work: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE admission_key='shared' AND incarnation_id='e'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_work, 1, "staged work sharing the key survives the purge");
    assert_eq!(live_receipt, "staged", "staged receipt survives the purge");
    assert_eq!(live_intents, 0, "no ACK intent for work never processed");
    assert_eq!(old_work, 0, "old held work is settled");
    assert_eq!(
        unrouted_for(&db, "shared")?,
        1,
        "shared guard keeps the unrouted row while staged work shares the key"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn default_expiry_boundary() -> Result<(), StorageError> {
    let (root, db) = setup("p08-boundary")?;
    stage(&db, 0, 1, "edge")?;
    cover_held(&db, 0, 1)?;
    let bound = 1 + 604_800;
    assert_eq!(expire_tx(&db, 1, bound - 1)?, Vec::<u64>::new(), "one second before stays");
    assert_eq!(snap(&db)?.work, vec![1]);
    assert_eq!(expire_tx(&db, 1, bound)?, vec![1], "exactly at the bound expires");
    assert_eq!(snap(&db)?.work, Vec::<u64>::new());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn failure_policy_stage_crash() -> Result<(), StorageError> {
    retryable_cut()?;
    deterministic_cut()?;
    exhausted_cut()?;
    identity_missing_cut()?;
    trusted_vs_unverified_failure_policy()?;
    Ok(())
}

fn retryable_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-retry")?;
    let wire = stage(&db, 0, 1, "retry")?;
    let pre = snap(&db)?;
    assert_eq!(pre.work, vec![1]);
    assert_eq!(pre.receipts, vec![(1, "staged".into())]);
    let input = ReceiveFailure {
        sequence: 1,
        admission_key: "retry",
        entry: &wire,
        kind: FailKind::Retryable,
        error_code: "directory_miss",
        at: 1,
        policy: unverified(1),
    };
    assert_fault(with_fault(FaultKind::BeforeCommit, || admit(&db, 0, input)));
    assert_eq!(snap(&db)?, pre, "W0 survives a failed retryable admission");
    assert_eq!(retry_count(&db, "retry")?, 0);
    assert_eq!(admit(&db, 0, input)?, FailOut::Held);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, vec![1]);
    assert_eq!(done.receipts, vec![(1, "held".into())]);
    assert_eq!(done.intents, Vec::<u64>::new());
    assert_eq!(retry_count(&db, "retry")?, 1);
    assert_eq!(failure_count(&db, "policy_rejected")?, 0);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn deterministic_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-det")?;
    let wire = stage(&db, 0, 1, "det")?;
    let pre = snap(&db)?;
    let input = ReceiveFailure {
        sequence: 1,
        admission_key: "det",
        entry: &wire,
        kind: FailKind::Deterministic,
        error_code: "authentication_failed",
        at: 1,
        policy: unverified(1),
    };
    assert_fault(with_fault(FaultKind::BeforeCommit, || admit(&db, 0, input)));
    assert_eq!(snap(&db)?, pre);
    assert_eq!(admit(&db, 0, input)?, FailOut::Rejected);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "policy_rejected")?, 1);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn exhausted_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-exh")?;
    let wire = stage(&db, 0, 1, "exh")?;
    let pre = snap(&db)?;
    let input = ReceiveFailure {
        sequence: 1,
        admission_key: "exh",
        entry: &wire,
        kind: FailKind::Exhausted,
        error_code: "retry_exhausted",
        at: 1,
        policy: unverified(1),
    };
    assert_fault(with_fault(FaultKind::BeforeCommit, || admit(&db, 0, input)));
    assert_eq!(snap(&db)?, pre, "W0 survives a failed exhausted admission");
    assert_eq!(admit(&db, 0, input)?, FailOut::Rejected);
    let done = snap(&db)?;
    assert_eq!(done.cursor, 1);
    assert_eq!(done.work, Vec::<u64>::new());
    assert_eq!(done.intents, vec![1]);
    assert_eq!(failure_count(&db, "policy_rejected")?, 1);
    assert_eq!(retry_count(&db, "exh")?, 0);
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, done);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn identity_missing_cut() -> Result<(), StorageError> {
    let (root, db) = setup("p08-id")?;
    let wire = stage(&db, 0, 1, "id")?;
    let missing_seq = admit(
        &db,
        0,
        ReceiveFailure {
            sequence: 0,
            admission_key: "id",
            entry: &wire,
            kind: FailKind::Retryable,
            error_code: "directory_miss",
            at: 1,
            policy: unverified(1),
        },
    );
    assert!(matches!(
        missing_seq,
        Err(StorageError::Integrity("receive failure identity missing"))
    ));
    let missing_key = admit(
        &db,
        0,
        ReceiveFailure {
            sequence: 1,
            admission_key: "",
            entry: &wire,
            kind: FailKind::Retryable,
            error_code: "directory_miss",
            at: 1,
            policy: unverified(1),
        },
    );
    assert!(matches!(
        missing_key,
        Err(StorageError::Integrity("receive failure identity missing"))
    ));
    assert_eq!(snap(&db)?.work, vec![1]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn trusted_vs_unverified_failure_policy() -> Result<(), StorageError> {
    let (root, db) = setup("p08-policy")?;
    let packet = long_entry();
    stage(&db, 0, 1, "unv")?;
    assert_eq!(
        admit(
            &db,
            0,
            ReceiveFailure {
                sequence: 1,
                admission_key: "unv",
                entry: &packet,
                kind: FailKind::Retryable,
                error_code: "directory_miss",
                at: 1,
                policy: unverified(1),
            }
        )?,
        FailOut::Held
    );
    assert_eq!(policy_window(&db, "unv")?, (0, 31, "none".into(), String::new()));

    stage(&db, 1, 2, "tr")?;
    let source = pin_source("principal", "device")?;
    assert_eq!(
        admit(
            &db,
            1,
            ReceiveFailure {
                sequence: 2,
                admission_key: "tr",
                entry: &packet,
                kind: FailKind::Retryable,
                error_code: "directory_miss",
                at: 1,
                policy: InboxFailurePolicy {
                    verified_source: Some(&source),
                    trusted: true,
                    dependency: ("group", "g"),
                    at: 1,
                },
            }
        )?,
        FailOut::Held
    );
    assert_eq!(policy_window(&db, "tr")?, (1, 601, "group".into(), "g".into()));

    for index in 0..16 {
        let key = format!("stranger-{index}");
        assert!(db.set_verified_inbox_failure_policy(&key, &packet, unverified(100))?);
    }
    stage(&db, 2, 3, "cap")?;
    assert_eq!(
        admit(
            &db,
            2,
            ReceiveFailure {
                sequence: 3,
                admission_key: "cap",
                entry: &packet,
                kind: FailKind::Retryable,
                error_code: "directory_miss",
                at: 100,
                policy: unverified(100),
            }
        )?,
        FailOut::Rejected,
        "16-untrusted cap rejects a further unverified admission"
    );
    stage(&db, 3, 4, "cap-t")?;
    assert_eq!(
        admit(
            &db,
            3,
            ReceiveFailure {
                sequence: 4,
                admission_key: "cap-t",
                entry: &packet,
                kind: FailKind::Retryable,
                error_code: "directory_miss",
                at: 100,
                policy: InboxFailurePolicy {
                    verified_source: Some(&source),
                    trusted: true,
                    dependency: ("none", ""),
                    at: 100,
                },
            }
        )?,
        FailOut::Held,
        "trusted senders are outside the 16-untrusted cap"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn dead_letters_for(db: &AccountDb, key: &str) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM runtime_inbox_dead_letter WHERE envelope_key=?1",
        params![key],
        |row| row.get(0),
    )?)
}

#[test]
fn staged_only_key_survives_expiry_and_unrouted_trim() -> Result<(), StorageError> {
    let (root, db) = setup("p08-staged-only")?;
    let wire = stage(&db, 0, 1, "stg")?;
    db.hold_unrouted("stg", 1, &wire, 1)?;
    db.defer_inbox_entry("stg", &wire, 1)?;
    // Expiry at 700_000 is past the policy window and the 7-day unrouted cutoff.
    db.expire_inbox_holds(700_000)?;
    assert_eq!(unrouted_for(&db, "stg")?, 1, "staged-only key keeps its unrouted row");
    assert_eq!(dead_letters_for(&db, "stg")?, 0, "no retry_expired diagnostic for staged work");
    let staged_work: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE admission_key='stg'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(staged_work, 1, "staged work is not settled by hold expiry");
    let disposition: String = db.connection.query_row(
        "SELECT disposition FROM gateway_receive_receipt WHERE target_delivery_id='t' AND incarnation_id='e' AND inbox_seq=?1",
        params![1u64.to_be_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(disposition, "staged", "receipt stays staged");
    // Overflow: trim runs before each insert, so 65 newer non-staged rows push the 64-cap past
    // the oldest staged-only key (the eviction boundary falls on it at the last insert).
    for index in 0..65u64 {
        let wire = bytes(100 + index);
        db.hold_unrouted(
            &format!("ov{index}"),
            100 + index,
            &wire,
            1_000 + i64::try_from(index).expect("at"),
        )?;
    }
    assert_eq!(unrouted_for(&db, "stg")?, 1, "staged-only key survives overflow trim");
    assert_eq!(unrouted_for(&db, "ov0")?, 0, "oldest non-staged key is evicted instead");
    assert_eq!(unrouted_for(&db, "ov64")?, 1, "newest non-staged key is kept");
    assert_eq!(db.unrouted_count()?, 65, "64 non-staged rows plus the staged-only row");
    assert_eq!(dead_letters_for(&db, "ov0")?, 0, "no retry_expired written for evicted key");
    assert_eq!(dead_letters_for(&db, "stg")?, 0, "no retry_expired diagnostic for staged work");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn verified_attempt_limits_are_exact() -> Result<(), StorageError> {
    let (root, db) = setup("p08-attempt-limits")?;
    let packet = long_entry();
    let source = pin_source("principal", "device")?;
    assert!(db.set_verified_inbox_failure_policy(
        "tr",
        &packet,
        InboxFailurePolicy {
            verified_source: Some(&source),
            trusted: true,
            dependency: ("none", ""),
            at: 1,
        },
    )?);
    assert_eq!(policy_window(&db, "tr")?, (1, 601, "none".into(), String::new()));
    for attempt in 1..=8u32 {
        assert_eq!(db.defer_inbox_entry("tr", &packet, 1)?, attempt, "trusted attempt {attempt}");
    }
    assert_eq!(db.defer_inbox_entry("tr", &packet, 1)?, 0, "trusted 9th attempt refused");

    assert!(db.set_verified_inbox_failure_policy("un", &packet, unverified(1))?);
    assert_eq!(policy_window(&db, "un")?, (0, 31, "none".into(), String::new()));
    for attempt in 1..=3u32 {
        assert_eq!(
            db.defer_inbox_entry("un", &packet, 1)?,
            attempt,
            "unverified attempt {attempt}"
        );
    }
    assert_eq!(db.defer_inbox_entry("un", &packet, 1)?, 0, "unverified 4th attempt refused");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
