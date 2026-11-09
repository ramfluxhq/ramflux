// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P20f r5A r2: `failure_policy_stage_crash` (M5) and `held_local_expiry_and_eviction_crash` (M6).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used, clippy::too_many_lines)]

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
use ramflux_node_core::{InboxEntry, RouterCore, RouterRedbStore};
use ramflux_protocol::{Ack, Ext, SignatureAlg, SignedFields, encode_base64url};
use ramflux_storage::{
    AccountDb, ReceiveFailure, ReceiveFailureKind, ReceiveFailureResult, StorageError,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};

const START: i64 = 1_700_000_000;
const HOLD_MAX: i64 = 604_800;
const OPEN_INPUT: &str = "source effect requires staged receive work";
const FAILURE_CUT: &str = "source failure before-commit";
const W1_CUT: &str = "apply page w1 before-commit";
const UNTRUSTED_RETRY_LIMIT: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Wal,
    RedbOnly,
}

const MODES: [Mode; 2] = [Mode::Wal, Mode::RedbOnly];

struct Harness {
    _root: tempfile::TempDir,
    account: crate::bus::state::LocalBusAccountState,
    router_path: PathBuf,
    mode: Mode,
}

fn router_wal_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[allow(unsafe_code)]
fn write_router_wal_env(enabled: bool) {
    // SAFETY: callers hold `router_wal_lock` for the whole set/open/restore window.
    unsafe {
        std::env::set_var("RAMFLUX_ROUTER_WAL", if enabled { "1" } else { "0" });
    }
}

#[allow(unsafe_code)]
fn restore_router_wal_env(previous: Option<String>) {
    // SAFETY: callers hold `router_wal_lock` for the whole set/open/restore window.
    unsafe {
        match previous {
            Some(value) => std::env::set_var("RAMFLUX_ROUTER_WAL", value),
            None => std::env::remove_var("RAMFLUX_ROUTER_WAL"),
        }
    }
}

fn open_router(path: &Path, mode: Mode) -> Result<RouterRedbStore, SdkError> {
    let _guard = router_wal_lock().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = std::env::var("RAMFLUX_ROUTER_WAL").ok();
    write_router_wal_env(mode == Mode::Wal);
    let opened = RouterRedbStore::open(path);
    restore_router_wal_env(previous);
    opened.map_err(|error| SdkError::LocalBus(error.to_string()))
}

fn wal_dir(path: &Path) -> PathBuf {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("router.redb");
    path.with_file_name(format!("{name}.wal"))
}

fn assert_router_mode(path: &Path, mode: Mode) {
    let wal = wal_dir(path);
    match mode {
        Mode::Wal => assert!(wal.exists(), "WAL mode must create {wal:?}"),
        Mode::RedbOnly => assert!(!wal.exists(), "redb-only must not create {wal:?}"),
    }
}

fn router_inbox(entry: &crate::GatewayInboxEntry) -> InboxEntry {
    InboxEntry {
        inbox_seq: entry.inbox_seq,
        target_delivery_id: entry.target_delivery_id.clone(),
        envelope: entry.envelope.clone(),
    }
}

fn router_ack(envelope_id: &str) -> Ack {
    Ack {
        schema: "ramflux.ack.v1".into(),
        version: 1,
        domain: "ramflux.ack.v1".into(),
        ext: Ext::default(),
        signed: SignedFields {
            signing_key_id: "key".into(),
            signature_alg: SignatureAlg::Ed25519,
            signature: "sig".into(),
        },
        ack_id: format!("ack-{envelope_id}"),
        envelope_id: envelope_id.to_owned(),
        receiver_device_id: "device".into(),
        received_at: 1,
        cursor_after: None,
    }
}

fn plant_router_row(
    store: &RouterRedbStore,
    entry: &crate::GatewayInboxEntry,
) -> Result<(), SdkError> {
    store
        .record_inbox_entry(&router_inbox(entry))
        .map_err(|error| SdkError::LocalBus(error.to_string()))
}

fn pending_for(store: &RouterRedbStore, target: &str) -> Result<Vec<InboxEntry>, SdkError> {
    let Some(router) =
        store.load_router().map_err(|error| SdkError::LocalBus(error.to_string()))?
    else {
        return Ok(Vec::new());
    };
    Ok(router.resume(target, 0, 32))
}

fn ack_router_row(
    store: &RouterRedbStore,
    entry: &crate::GatewayInboxEntry,
) -> Result<(), SdkError> {
    let router = store
        .load_router()
        .map_err(|error| SdkError::LocalBus(error.to_string()))?
        .ok_or_else(|| SdkError::LocalBus("router row missing before ACK".into()))?;
    let id = entry.envelope.envelope_id.as_str();
    let cursor =
        router.apply_ack(&router_ack(id)).map_err(|error| SdkError::LocalBus(error.to_string()))?;
    store.record_ack_increment(&cursor, id).map_err(|error| SdkError::LocalBus(error.to_string()))
}

fn open(mode: Mode) -> Result<Harness, SdkError> {
    let root = tempfile::tempdir().expect("tmp");
    let account =
        runtime_tests::account(root.path(), "acct", None, Arc::new(AtomicBool::new(false)))?;
    let target = account.target_delivery_id.clone();
    let db = account.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(&target, "e")?;
    let router_path = root.path().join("router.redb");
    {
        let store = open_router(&router_path, mode)?;
        store
            .bootstrap_router(&RouterCore::new())
            .map_err(|error| SdkError::LocalBus(error.to_string()))?;
        let plant =
            dummy_seq(&target, &encode_base64url(b"router-mode-plant"), "router", "dev", 99);
        plant_router_row(&store, &plant.entry)?;
        assert_router_mode(&router_path, mode);
        assert_eq!(
            pending_for(&store, &target)?.len(),
            1,
            "mode plant must be a real router inbox row"
        );
    }
    Ok(Harness { _root: root, account, router_path, mode })
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

fn recover(harness: &mut Harness) -> Result<(), SdkError> {
    reopen(&mut harness.account)?;
    let _store = open_router(&harness.router_path, harness.mode)?;
    assert_router_mode(&harness.router_path, harness.mode);
    Ok(())
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

fn admit_retryable(
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
            kind: ReceiveFailureKind::Retryable,
            error_code: "inbound_pending",
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

fn assert_held_retry(
    account: &crate::bus::state::LocalBusAccountState,
    key: &str,
    attempt: u32,
) -> Result<(), SdkError> {
    let db = db_of(account)?;
    assert_eq!(
        db.receive_state_for_test(1)?,
        (Some("held".into()), 1),
        "attempt {attempt} still retries"
    );
    assert_eq!(retry_count(db, key)?, 1, "attempt {attempt} keeps the retry row");
    assert_eq!(failure_events(db, "policy_rejected")?, 0, "attempt {attempt} is not terminal");
    assert_eq!(dead_letters(db)?, 0, "Retryable exhaustion never writes message.undeliverable");
    Ok(())
}

fn assert_exhausted_committed(
    account: &crate::bus::state::LocalBusAccountState,
    key: &str,
) -> Result<(), SdkError> {
    let db = db_of(account)?;
    assert_eq!(db.receive_state_for_test(1)?, (None, 0), "limit settles W0");
    assert_eq!(cursor(account)?, 1);
    assert_eq!(snap(account)?.intents, vec![1]);
    assert_eq!(failure_events(db, "policy_rejected")?, 1);
    assert_eq!(retry_count(db, key)?, 0);
    assert_eq!(dead_letters(db)?, 0, "Retryable reject does not insert_inbox_dead_letter");
    Ok(())
}

fn drive_untrusted_limit(
    account: &crate::bus::state::LocalBusAccountState,
    entry: &crate::GatewayInboxEntry,
    json: &[u8],
    key: &str,
) -> Result<(), SdkError> {
    for attempt in 1..=UNTRUSTED_RETRY_LIMIT {
        assert_eq!(
            admit_retryable(account, entry, json)?,
            ReceiveFailureResult::Held,
            "attempt {attempt} of {UNTRUSTED_RETRY_LIMIT} still retries"
        );
        assert_held_retry(account, key, attempt)?;
    }
    assert_eq!(
        admit_retryable(account, entry, json)?,
        ReceiveFailureResult::Rejected,
        "attempt {} dead-letters",
        UNTRUSTED_RETRY_LIMIT + 1
    );
    assert_exhausted_committed(account, key)
}

async fn exhausted_retry_after_commit(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open(mode)?;
    let entry = stage_w0(&mut harness.account).await?;
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    let json = db_of(&harness.account)?.staged_entry_json_for_test(1)?;
    drive_untrusted_limit(&harness.account, &entry.entry, &json, &key)?;
    recover(&mut harness)?;
    assert_exhausted_committed(&harness.account, &key)?;
    let again = drive(&mut harness.account, entry, || 1).await?;
    assert!(again.0.is_none());
    assert_exhausted_committed(&harness.account, &key)?;
    Ok(())
}

async fn exhausted_split_write(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open(mode)?;
    let entry = stage_w0(&mut harness.account).await?;
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    let json = db_of(&harness.account)?.staged_entry_json_for_test(1)?;
    for attempt in 1..=UNTRUSTED_RETRY_LIMIT {
        assert_eq!(
            admit_retryable(&harness.account, &entry.entry, &json)?,
            ReceiveFailureResult::Held
        );
        assert_held_retry(&harness.account, &key, attempt)?;
    }
    source_failure::set_fault(source_failure::Fault::BeforeCommit);
    let cut = admit_retryable(&harness.account, &entry.entry, &json);
    source_failure::set_fault(source_failure::Fault::None);
    assert_integrity(cut.as_ref().err(), FAILURE_CUT, "exhausted split-write");
    assert_eq!(
        db_of(&harness.account)?.receive_state_for_test(1)?,
        (Some("held".into()), 1),
        "limit-1 hold survives the rejected split-write"
    );
    assert_eq!(failure_events(db_of(&harness.account)?, "policy_rejected")?, 0);
    assert_eq!(retry_count(db_of(&harness.account)?, &key)?, 1);
    assert_eq!(dead_letters(db_of(&harness.account)?)?, 0);
    recover(&mut harness)?;
    assert_eq!(
        db_of(&harness.account)?.receive_state_for_test(1)?,
        (Some("held".into()), 1),
        "split-write reopen shows neither journal nor dead-letter"
    );
    assert_eq!(failure_events(db_of(&harness.account)?, "policy_rejected")?, 0);
    assert_eq!(dead_letters(db_of(&harness.account)?)?, 0);
    Ok(())
}

async fn exhausted_router_row_removed(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open(mode)?;
    let entry = stage_w0(&mut harness.account).await?;
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    let target = harness.account.target_delivery_id.clone();
    {
        let store = open_router(&harness.router_path, mode)?;
        plant_router_row(&store, &entry.entry)?;
        assert!(
            pending_for(&store, &target)?
                .iter()
                .any(|row| row.envelope.envelope_id == entry.entry.envelope.envelope_id),
            "staged envelope must be a live router row"
        );
        ack_router_row(&store, &entry.entry)?;
        assert!(
            pending_for(&store, &target)?
                .iter()
                .all(|row| row.envelope.envelope_id != entry.entry.envelope.envelope_id),
            "ACK must remove the real router row"
        );
    }
    recover(&mut harness)?;
    let recovered = from_disk(&harness.account, 1)?;
    assert_eq!(recovered.entry.envelope.envelope_id, entry.entry.envelope.envelope_id);
    let json = db_of(&harness.account)?.staged_entry_json_for_test(1)?;
    drive_untrusted_limit(&harness.account, &recovered.entry, &json, &key)?;
    recover(&mut harness)?;
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
    source: Option<&str>,
) -> Result<(), SdkError> {
    queue_legacy_hold(std::iter::repeat_n(true, 4));
    let entry = own_dummy_at(account, seq);
    if let Some(source) = source {
        let key = account.client.inbox_admission_key(&entry.entry)?;
        db_of(account)?.seed_inbox_policy_for_test(&key, source)?;
    }
    drive(account, entry, || 1).await?;
    Ok(())
}

fn refuse_open_input(
    account: &crate::bus::state::LocalBusAccountState,
    sequence: u64,
) -> Result<(), SdkError> {
    let prepared = turn(account, 1)?;
    let refused = db_of(account)?
        .receive_transaction(prepared.expected(), 1, |tx| tx.require_open_input(sequence));
    let error = refused.as_ref().expect_err("fenced purge must refuse a later source effect");
    assert!(
        matches!(error, StorageError::Integrity(text) if *text == OPEN_INPUT),
        "exact StorageError: {error:?}"
    );
    Ok(())
}

fn probe_unrouted(
    account: &crate::bus::state::LocalBusAccountState,
    id: &str,
    seq: u64,
    at: i64,
) -> Result<(), SdkError> {
    let body = serde_json::to_vec(&json!({"probe": id, "inbox_seq": seq}))?;
    db_of(account)?.hold_unrouted(id, seq, &body, at)?;
    Ok(())
}

async fn quarantine_purge(mode: Mode) -> Result<(), SdkError> {
    let _clock = crate::time::FixedClock::set(START);
    let mut harness = open(mode)?;
    hold_seq(&mut harness.account, 1, None).await?;
    assert_eq!(db_of(&harness.account)?.receive_state_for_test(1)?, (Some("held".into()), 1));
    assert_eq!(db_of(&harness.account)?.unrouted_count()?, 1);
    crate::time::FixedClock::advance_to(START + HOLD_MAX + 1);
    probe_unrouted(&harness.account, "probe-expired", 99, START + HOLD_MAX + 1)?;
    assert_eq!(failure_events(db_of(&harness.account)?, "held_expired")?, 1);
    assert_eq!(db_of(&harness.account)?.receive_state_for_test(1)?, (None, 0));
    assert_eq!(snap(&harness.account)?.work, 0);
    refuse_open_input(&harness.account, 1)?;
    recover(&mut harness)?;
    assert_eq!(failure_events(db_of(&harness.account)?, "held_expired")?, 1);
    assert_eq!(db_of(&harness.account)?.receive_state_for_test(1)?, (None, 0));
    refuse_open_input(&harness.account, 1)?;
    Ok(())
}

async fn quarantine_overflow(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open(mode)?;
    for seq in 1..=64 {
        hold_seq(&mut harness.account, seq, None).await?;
    }
    assert_eq!(snap(&harness.account)?.work, 64);
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 0);
    probe_unrouted(&harness.account, "probe-overflow", 99, now_unix_timestamp())?;
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 1);
    assert_eq!(db_of(&harness.account)?.receive_state_for_test(1)?.0, None);
    refuse_open_input(&harness.account, 1)?;
    recover(&mut harness)?;
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 1);
    refuse_open_input(&harness.account, 1)?;
    Ok(())
}

fn held_receipts(done: &ramflux_storage::ReceiveLedgerSnap) -> Vec<u64> {
    done.receipts
        .iter()
        .filter(|(_, disposition)| disposition == "held")
        .map(|(seq, _)| *seq)
        .collect()
}

async fn cap_64_bound(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open(mode)?;
    for seq in 1..=32 {
        hold_seq(&mut harness.account, seq, Some("src-a")).await?;
    }
    for seq in 33..=64 {
        hold_seq(&mut harness.account, seq, Some("src-b")).await?;
    }
    let filled = snap(&harness.account)?;
    assert_eq!(filled.work, 64, "64 unrouted holds stay");
    assert_eq!(cursor(&harness.account)?, 64);
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 0);
    assert_eq!(held_receipts(&filled), (1..=64).collect::<Vec<_>>());
    queue_legacy_hold(std::iter::repeat_n(true, 4));
    set_after_classify(arm_w1_cut);
    let extra = own_dummy_at(&harness.account, 65);
    let extra_key = harness.account.client.inbox_admission_key(&extra.entry)?;
    db_of(&harness.account)?.seed_inbox_policy_for_test(&extra_key, "src-c")?;
    let cut = drive(&mut harness.account, extra, || 1).await;
    assert_integrity(cut.as_ref().err(), W1_CUT, "65th eviction cut");
    assert_eq!(
        db_of(&harness.account)?.receive_state_for_test(65)?,
        (Some("staged".into()), 65),
        "W1 cut leaves the 65th staged and the 64 holds"
    );
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 0);
    recover(&mut harness)?;
    hold_seq(&mut harness.account, 65, None).await?;
    let done = snap(&harness.account)?;
    assert_eq!(done.cursor, 65);
    assert_eq!(done.work, 64, "65 evicts exactly one");
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 1);
    assert_eq!(
        held_receipts(&done),
        (2..=65).collect::<Vec<_>>(),
        "seqs 2..=64 survive; 65 is held"
    );
    assert!(done.intents.contains(&1));
    recover(&mut harness)?;
    assert_eq!(snap(&harness.account)?, done);
    assert_eq!(failure_events(db_of(&harness.account)?, "held_evicted")?, 1);
    Ok(())
}

async fn dead_letter_row(mode: Mode) -> Result<(), SdkError> {
    let mut harness = open(mode)?;
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
    recover(&mut harness)?;
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
    let mut harness = open(mode)?;
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
    recover(&mut harness)?;
    let prepared = turn(&harness.account, 1)?;
    let settled = SourceFailure { expected: prepared.expected(), generation: 1 }
        .expire_holds(db_of(&harness.account)?, START + HOLD_MAX)?;
    assert_eq!(settled, vec![1]);
    assert_eq!(failure_events(db_of(&harness.account)?, "held_expired")?, 1);
    recover(&mut harness)?;
    assert_eq!(failure_events(db_of(&harness.account)?, "held_expired")?, 1);
    assert_eq!(snap(&harness.account)?.work, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn held_local_expiry_and_eviction_crash() -> Result<(), SdkError> {
    for mode in MODES {
        quarantine_purge(mode).await?;
        quarantine_overflow(mode).await?;
        cap_64_bound(mode).await?;
        dead_letter_row(mode).await?;
        contact_expiry_cut(mode).await?;
    }
    Ok(())
}
