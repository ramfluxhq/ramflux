// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P20f r5A: `failure_policy_stage_crash` (M5) and `held_local_expiry_and_eviction_crash` (M6).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use super::apply_w1::{
    self, apply_page, queue_legacy_hold, queue_policy_kind, set_after_classify, set_before_commit,
};
use crate::bus::connection_manager::{ReceiveEntry, ReceiveTurn};
use crate::bus::contact_backpressure::Backpressure;
use crate::bus::runtime_tests;
use crate::bus::sync_driver::source::failure::{self as source_failure, SourceFailure};
use crate::bus::sync_driver::source::hold::SourceHold;
use crate::client::inbox_failure::verified_failure_policy;
use crate::prelude::*;
use ramflux_protocol::encode_base64url;
use ramflux_storage::{
    AccountDb, ReceiveFailure, ReceiveFailureKind, ReceiveFailureResult, StorageError,
};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

const START: i64 = 1_700_000_000;
const HOLD_MAX: i64 = 604_800;
const OPEN_INPUT: &str = "source effect requires staged receive work";
const FAILURE_CUT: &str = "source failure before-commit";
const W1_CUT: &str = "apply page w1 before-commit";
const EXHAUSTED: &str = "retry_exhausted";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Wal,
    RedbOnly,
}

const MODES: [Mode; 2] = [Mode::Wal, Mode::RedbOnly];

struct Harness {
    _root: tempfile::TempDir,
    account: crate::bus::state::LocalBusAccountState,
}

fn open() -> Result<Harness, SdkError> {
    let root = tempfile::tempdir().expect("tmp");
    let account =
        runtime_tests::account(root.path(), "acct", None, Arc::new(AtomicBool::new(false)))?;
    let target = account.target_delivery_id.clone();
    let db = account.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(&target, "e")?;
    Ok(Harness { _root: root, account })
}

fn turn(
    account: &crate::bus::state::LocalBusAccountState,
    generation: u64,
) -> Result<ReceiveTurn, SdkError> {
    apply_w1::capture_turn(account.client.account_db()?, generation, &account.target_delivery_id)
}

fn envelope(
    target: &str,
    payload: &str,
    principal: &str,
    device: &str,
    seq: u64,
) -> serde_json::Value {
    json!({
        "inbox_seq": seq,
        "target_delivery_id": target,
        "envelope": {
            "schema": "test",
            "version": 1,
            "domain": "test",
            "signing_key_id": "key",
            "signature_alg": "ed25519",
            "signature": "sig",
            "envelope_id": format!("env-{seq}"),
            "source_principal_id": principal,
            "source_device_id": device,
            "target_delivery_id": target,
            "delivery_class": "opaque_event",
            "priority": "normal",
            "ttl": 60,
            "created_at": 1,
            "encrypted_payload": payload,
            "payload_hash": format!("H{seq}")
        }
    })
}

fn dummy_seq(target: &str, payload: &str, principal: &str, device: &str, seq: u64) -> ReceiveEntry {
    ReceiveEntry {
        entry: serde_json::from_value(envelope(target, payload, principal, device, seq))
            .expect("entry"),
        retry_key: None,
        replay: false,
        turn: None,
    }
}

fn own_dummy_at(account: &crate::bus::state::LocalBusAccountState, seq: u64) -> ReceiveEntry {
    dummy_seq(
        &account.target_delivery_id,
        &encode_base64url(b"legacy-a2i-dummy"),
        &account.gateway_config.principal_id,
        &account.gateway_config.device_id,
        seq,
    )
}

fn live_dummy(account: &crate::bus::state::LocalBusAccountState) -> ReceiveEntry {
    let mut prepared = own_dummy_at(account, 1);
    prepared.entry.envelope.created_at = now_unix_timestamp();
    prepared.entry.envelope.ttl = 86_400;
    prepared
}

fn retryable_entry(account: &crate::bus::state::LocalBusAccountState) -> ReceiveEntry {
    let mut entry = live_dummy(account);
    entry.entry.envelope.signed.signature = encode_base64url([7u8; 64]);
    entry
}

async fn drive(
    account: &mut crate::bus::state::LocalBusAccountState,
    prepared: ReceiveEntry,
    generation: impl Fn() -> u64 + 'static,
) -> Result<crate::bus::connection_manager::ReceiveApplied, SdkError> {
    let prepared_turn = turn(account, 1)?;
    let pressure = Box::new(Backpressure::load(&account.client, now_unix_timestamp())?);
    apply_page(account, &prepared_turn, &generation, prepared, None, pressure).await
}

fn reopen(account: &mut crate::bus::state::LocalBusAccountState) -> Result<(), SdkError> {
    account.client.active_account_db = None;
    account.client.unlock_account("acct", b"actor-test-secret")?;
    Ok(())
}

fn recover(
    account: &mut crate::bus::state::LocalBusAccountState,
    mode: Mode,
) -> Result<(), SdkError> {
    if mode == Mode::RedbOnly {
        account.client.account_db()?.checkpoint_retired_secrets()?;
    }
    reopen(account)
}

fn from_disk(
    account: &crate::bus::state::LocalBusAccountState,
    sequence: u64,
) -> Result<ReceiveEntry, SdkError> {
    let json = account.client.account_db()?.staged_entry_json_for_test(sequence)?;
    Ok(ReceiveEntry {
        entry: serde_json::from_slice(&json)?,
        retry_key: None,
        replay: false,
        turn: None,
    })
}

fn db_of(account: &crate::bus::state::LocalBusAccountState) -> Result<&AccountDb, SdkError> {
    account.client.account_db()
}

fn snap(
    account: &crate::bus::state::LocalBusAccountState,
) -> Result<ramflux_storage::ReceiveLedgerSnap, SdkError> {
    Ok(db_of(account)?.receive_ledger_snap_for_test(&account.target_delivery_id)?)
}

fn cursor(account: &crate::bus::state::LocalBusAccountState) -> Result<u64, SdkError> {
    Ok(snap(account)?.cursor)
}

fn journal_topic(db: &AccountDb, topic: &str) -> Result<usize, SdkError> {
    Ok(db.journal_after(0, 1024)?.into_iter().filter(|event| event.topic == topic).count())
}

fn failure_events(db: &AccountDb, reason: &str) -> Result<usize, SdkError> {
    Ok(db
        .journal_after(0, 1024)?
        .into_iter()
        .filter(|event| {
            event.topic == "inbox.receive_failure"
                && event.body.get("reason").and_then(serde_json::Value::as_str) == Some(reason)
        })
        .count())
}

fn retry_count(db: &AccountDb, key: &str) -> Result<i64, SdkError> {
    Ok(db.inbox_retry_and_policy_counts_for_test(key)?.0)
}

fn dead_letters(db: &AccountDb) -> Result<usize, SdkError> {
    journal_topic(db, "message.undeliverable")
}

fn arm_w1_cut(_db: &AccountDb) {
    set_before_commit(W1_CUT);
}

fn assert_integrity(error: Option<&SdkError>, text: &str, label: &str) {
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(got))) if *got == text
        ),
        "{label}: {error:?}"
    );
}

fn admit_exhausted(
    account: &crate::bus::state::LocalBusAccountState,
    entry: &crate::GatewayInboxEntry,
    json: &[u8],
) -> Result<ReceiveFailureResult, SdkError> {
    let key = account.client.inbox_admission_key(entry)?;
    let at = now_unix_timestamp();
    let built =
        verified_failure_policy(&account.client, &account.gateway_config.device_id, entry, at)?;
    let prepared = turn(account, 1)?;
    let failure = SourceFailure { expected: prepared.expected(), generation: 1 };
    failure.admit(
        db_of(account)?,
        ReceiveFailure {
            sequence: entry.inbox_seq,
            admission_key: &key,
            entry: json,
            kind: ReceiveFailureKind::Exhausted,
            error_code: EXHAUSTED,
            at,
            policy: built.policy(),
        },
    )
}

async fn stage_w0(
    account: &mut crate::bus::state::LocalBusAccountState,
) -> Result<ReceiveEntry, SdkError> {
    source_failure::set_fault(source_failure::Fault::BeforeCommit);
    queue_policy_kind(ReceiveFailureKind::Retryable);
    let entry = retryable_entry(account);
    let cut = drive(account, entry.clone(), || 1).await;
    source_failure::set_fault(source_failure::Fault::None);
    assert_integrity(cut.as_ref().err(), FAILURE_CUT, "W0 stage cut");
    assert_eq!(
        db_of(account)?.receive_state_for_test(1)?,
        (Some("staged".into()), 1),
        "W0 survives the W1 cut"
    );
    Ok(entry)
}

fn assert_exhausted_committed(
    account: &crate::bus::state::LocalBusAccountState,
    key: &str,
) -> Result<(), SdkError> {
    let db = db_of(account)?;
    assert_eq!(db.receive_state_for_test(1)?, (None, 0), "exhausted settles W0");
    assert_eq!(cursor(account)?, 1);
    assert_eq!(snap(account)?.intents, vec![1]);
    assert_eq!(failure_events(db, "policy_rejected")?, 1);
    assert_eq!(retry_count(db, key)?, 0);
    assert_eq!(dead_letters(db)?, 1);
    Ok(())
}

async fn exhausted_retry_after_commit(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = stage_w0(&mut harness.account).await?;
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    let json = db_of(&harness.account)?.staged_entry_json_for_test(1)?;
    assert_eq!(
        admit_exhausted(&harness.account, &entry.entry, &json)?,
        ReceiveFailureResult::Rejected
    );
    assert_exhausted_committed(&harness.account, &key)?;
    recover(&mut harness.account, mode)?;
    assert_exhausted_committed(&harness.account, &key)?;
    let again = drive(&mut harness.account, entry, || 1).await?;
    assert!(again.0.is_none());
    assert_exhausted_committed(&harness.account, &key)?;
    Ok(())
}

async fn exhausted_split_write(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = stage_w0(&mut harness.account).await?;
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    let json = db_of(&harness.account)?.staged_entry_json_for_test(1)?;
    source_failure::set_fault(source_failure::Fault::BeforeCommit);
    let cut = admit_exhausted(&harness.account, &entry.entry, &json);
    source_failure::set_fault(source_failure::Fault::None);
    assert_integrity(cut.as_ref().err(), FAILURE_CUT, "exhausted split-write");
    assert_eq!(db_of(&harness.account)?.receive_state_for_test(1)?, (Some("staged".into()), 1));
    assert_eq!(failure_events(db_of(&harness.account)?, "policy_rejected")?, 0);
    assert_eq!(retry_count(db_of(&harness.account)?, &key)?, 0);
    assert_eq!(dead_letters(db_of(&harness.account)?)?, 0);
    recover(&mut harness.account, mode)?;
    assert_eq!(
        db_of(&harness.account)?.receive_state_for_test(1)?,
        (Some("staged".into()), 1),
        "split-write reopen shows neither journal nor dead-letter"
    );
    assert_eq!(failure_events(db_of(&harness.account)?, "policy_rejected")?, 0);
    assert_eq!(dead_letters(db_of(&harness.account)?)?, 0);
    Ok(())
}

async fn exhausted_router_row_removed(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = stage_w0(&mut harness.account).await?;
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    recover(&mut harness.account, mode)?;
    let recovered = from_disk(&harness.account, 1)?;
    assert_eq!(recovered.entry.envelope.envelope_id, entry.entry.envelope.envelope_id);
    let json = db_of(&harness.account)?.staged_entry_json_for_test(1)?;
    assert_eq!(
        admit_exhausted(&harness.account, &recovered.entry, &json)?,
        ReceiveFailureResult::Rejected
    );
    assert_exhausted_committed(&harness.account, &key)?;
    recover(&mut harness.account, mode)?;
    assert_exhausted_committed(&harness.account, &key)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn failure_policy_stage_crash() -> Result<(), SdkError> {
    for mode in MODES {
        exhausted_retry_after_commit(mode).await?;
        exhausted_split_write(mode).await?;
        exhausted_router_row_removed(mode).await?;
    }
    Ok(())
}

async fn hold_seq(
    account: &mut crate::bus::state::LocalBusAccountState,
    seq: u64,
) -> Result<(), SdkError> {
    queue_legacy_hold(std::iter::repeat_n(true, 4));
    let entry = own_dummy_at(account, seq);
    drive(account, entry, || 1).await?;
    Ok(())
}

async fn quarantine_purge(mode: Mode) -> Result<(), SdkError> {
    let _clock = crate::time::FixedClock::set(START);
    let mut harness = open()?;
    hold_seq(&mut harness.account, 1).await?;
    assert_eq!(db_of(&harness.account)?.receive_state_for_test(1)?, (Some("held".into()), 1));
    assert_eq!(db_of(&harness.account)?.unrouted_count()?, 1);
    let pre = snap(&harness.account)?;
    crate::time::FixedClock::advance_to(START + HOLD_MAX);
    let prepared = turn(&harness.account, 1)?;
    source_failure::set_fault(source_failure::Fault::BeforeCommit);
    let cut = SourceFailure { expected: prepared.expected(), generation: 1 }
        .expire_holds(db_of(&harness.account)?, START + HOLD_MAX);
    source_failure::set_fault(source_failure::Fault::None);
    assert_integrity(cut.as_ref().err(), FAILURE_CUT, "quarantine purge cut");
    assert_eq!(snap(&harness.account)?, pre, "purge cut writes nothing");
    recover(&mut harness.account, mode)?;
    assert_eq!(snap(&harness.account)?, pre);
    let prepared = turn(&harness.account, 1)?;
    let settled = SourceFailure { expected: prepared.expected(), generation: 1 }
        .expire_holds(db_of(&harness.account)?, START + HOLD_MAX)?;
    assert_eq!(settled, vec![1]);
    assert_eq!(failure_events(db_of(&harness.account)?, "held_expired")?, 1);
    assert_eq!(db_of(&harness.account)?.unrouted_count()?, 0, "quarantine row is gone");
    assert_eq!(snap(&harness.account)?.work, 0);
    recover(&mut harness.account, mode)?;
    assert_eq!(failure_events(db_of(&harness.account)?, "held_expired")?, 1);
    assert_eq!(db_of(&harness.account)?.unrouted_count()?, 0);
    Ok(())
}

async fn fill_holds(
    account: &mut crate::bus::state::LocalBusAccountState,
    through: u64,
) -> Result<(), SdkError> {
    for seq in 1..=through {
        hold_seq(account, seq).await?;
    }
    Ok(())
}

async fn cap_64_bound(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open()?;
    fill_holds(&mut harness.account, 64).await?;
    assert_eq!(snap(&harness.account)?.work, 64, "64 unrouted holds stay");
    assert_eq!(cursor(&harness.account)?, 64);
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 0);
    queue_legacy_hold(std::iter::repeat_n(true, 4));
    set_after_classify(arm_w1_cut);
    let extra = own_dummy_at(&harness.account, 65);
    let cut = drive(&mut harness.account, extra, || 1).await;
    assert_integrity(cut.as_ref().err(), W1_CUT, "65th eviction cut");
    assert_eq!(
        db_of(&harness.account)?.receive_state_for_test(65)?,
        (Some("staged".into()), 65),
        "W1 cut leaves the 65th staged and the 64 holds"
    );
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 0);
    recover(&mut harness.account, mode)?;
    hold_seq(&mut harness.account, 65).await?;
    let done = snap(&harness.account)?;
    assert_eq!(done.cursor, 65);
    assert_eq!(done.work, 64, "65 evicts exactly one");
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 1);
    assert!(!done.receipts.iter().any(|(seq, disp)| *seq == 1 && disp == "held"));
    assert!(done.intents.contains(&1));
    recover(&mut harness.account, mode)?;
    assert_eq!(snap(&harness.account)?, done);
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 1);
    Ok(())
}

async fn dead_letter_row(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = stage_w0(&mut harness.account).await?;
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    let json = db_of(&harness.account)?.staged_entry_json_for_test(1)?;
    db_of(&harness.account)?.dead_letter_inbox(
        &key,
        &json,
        &json!({"error_code":"authentication_failed"}),
        now_unix_timestamp(),
    )?;
    assert_eq!(failure_events(db_of(&harness.account)?, "policy_rejected")?, 1);
    assert_eq!(dead_letters(db_of(&harness.account)?)?, 1);
    assert_eq!(snap(&harness.account)?.work, 0);
    assert_eq!(snap(&harness.account)?.intents, vec![1]);
    recover(&mut harness.account, mode)?;
    assert_eq!(failure_events(db_of(&harness.account)?, "policy_rejected")?, 1);
    assert_eq!(dead_letters(db_of(&harness.account)?)?, 1);
    assert_eq!(snap(&harness.account)?.work, 0);
    Ok(())
}

fn contact_hold(account: &crate::bus::state::LocalBusAccountState) -> Result<(), SdkError> {
    let entry = own_dummy_at(account, 1);
    let key = account.client.inbox_admission_key(&entry.entry)?;
    let prepared = turn(account, 1)?;
    SourceHold { expected: prepared.expected(), generation: 1 }.contact_entry(
        db_of(account)?,
        &entry.entry,
        &key,
        "contact-root",
        now_unix_timestamp(),
    )?;
    Ok(())
}

async fn contact_expiry_cut(mode: Mode) -> Result<(), SdkError> {
    let _clock = crate::time::FixedClock::set(START);
    let mut harness = open()?;
    queue_legacy_hold(std::iter::repeat_n(true, 4));
    set_after_classify(arm_w1_cut);
    let entry = own_dummy_at(&harness.account, 1);
    let cut = drive(&mut harness.account, entry, || 1).await;
    assert_integrity(cut.as_ref().err(), W1_CUT, "contact W0 cut");
    contact_hold(&harness.account)?;
    assert_eq!(db_of(&harness.account)?.receive_state_for_test(1)?, (Some("held".into()), 1));
    let pre = snap(&harness.account)?;
    crate::time::FixedClock::advance_to(START + HOLD_MAX);
    let prepared = turn(&harness.account, 1)?;
    source_failure::set_fault(source_failure::Fault::BeforeCommit);
    let cut = SourceFailure { expected: prepared.expected(), generation: 1 }
        .expire_holds(db_of(&harness.account)?, START + HOLD_MAX);
    source_failure::set_fault(source_failure::Fault::None);
    assert_integrity(cut.as_ref().err(), FAILURE_CUT, "contact expiry cut");
    assert_eq!(snap(&harness.account)?, pre);
    recover(&mut harness.account, mode)?;
    let prepared = turn(&harness.account, 1)?;
    let settled = SourceFailure { expected: prepared.expected(), generation: 1 }
        .expire_holds(db_of(&harness.account)?, START + HOLD_MAX)?;
    assert_eq!(settled, vec![1]);
    assert_eq!(failure_events(db_of(&harness.account)?, "held_expired")?, 1);
    recover(&mut harness.account, mode)?;
    assert_eq!(failure_events(db_of(&harness.account)?, "held_expired")?, 1);
    assert_eq!(snap(&harness.account)?.work, 0);
    Ok(())
}

async fn raw_delete_refused(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open()?;
    hold_seq(&mut harness.account, 1).await?;
    assert_eq!(db_of(&harness.account)?.receive_state_for_test(1)?, (Some("held".into()), 1));
    db_of(&harness.account)?.erase_receive_work_for_test(1)?;
    let prepared = turn(&harness.account, 1)?;
    let refused = db_of(&harness.account)?
        .receive_transaction(prepared.expected(), 1, |tx| tx.require_open_input(1));
    let error = refused.as_ref().expect_err("raw DELETE must be refused");
    assert!(
        matches!(error, StorageError::Integrity(text) if *text == OPEN_INPUT),
        "exact StorageError: {error:?}"
    );
    assert_eq!(
        db_of(&harness.account)?.receive_state_for_test(1)?,
        (Some("held".into()), 0),
        "receipt stays held after an unfenced work DELETE"
    );
    recover(&mut harness.account, mode)?;
    assert_eq!(db_of(&harness.account)?.receive_state_for_test(1)?, (Some("held".into()), 0));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn held_local_expiry_and_eviction_crash() -> Result<(), SdkError> {
    for mode in MODES {
        quarantine_purge(mode).await?;
        cap_64_bound(mode).await?;
        dead_letter_row(mode).await?;
        contact_expiry_cut(mode).await?;
        raw_delete_refused(mode).await?;
    }
    Ok(())
}
