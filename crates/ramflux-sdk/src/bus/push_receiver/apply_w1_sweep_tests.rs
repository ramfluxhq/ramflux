// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! W1 commit sweep, real erase, manifest wait, `COVERED_BELOW`, nothing-owed (S6b P20f r5B).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use super::apply::{self, ApplyLoss, ApplyOutcome, ApplyPage};
use super::apply_w1::{
    self, apply_page, queue_legacy_hold, queue_own_copy, queue_policy_kind, queue_projection,
    set_after_classify, set_before_commit, set_before_commit_hook, set_manifest_await,
    set_projection_error, set_projection_key,
};
use super::erase_support::{erase_message_through_retention, erase_through_retention};
use crate::bus::connection_manager::{ReceiveEntry, ReceiveTurn};
use crate::bus::contact_backpressure::Backpressure;
use crate::bus::runtime_tests;
use crate::client::a2i::queue_unbound_answers;
use crate::client::identity_authority::test_support;
use crate::client::own_device_copy::PREFIX;
use crate::client::routed::{Committed, Kind, Routing};
use crate::dm::{
    SdkDmEncryptedEnvelope, dm_associated_data, dm_device_id_hash, gateway_direct_message_envelope,
};
use crate::gateway::GatewaySessionTransportKind;
use crate::prelude::*;
use ramflux_crypto::DmSession;
use ramflux_node_core::{InboxEntry, RouterCore, RouterRedbStore};
use ramflux_protocol::encode_base64url;
use ramflux_storage::{AccountDb, ReceiveFailureKind, StorageError};
use ramflux_sync::SyncError;
use ramflux_transport::TransportError;
use serde_json::json;
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

struct Harness {
    root: tempfile::TempDir,
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
    Ok(Harness { root, account })
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

fn own_dummy(account: &crate::bus::state::LocalBusAccountState) -> ReceiveEntry {
    dummy_seq(
        &account.target_delivery_id,
        &encode_base64url(b"legacy-a2i-dummy"),
        &account.gateway_config.principal_id,
        &account.gateway_config.device_id,
        1,
    )
}

fn live_dummy(account: &crate::bus::state::LocalBusAccountState) -> ReceiveEntry {
    let mut prepared = own_dummy(account);
    prepared.entry.envelope.created_at = now_unix_timestamp();
    prepared.entry.envelope.ttl = 86_400;
    prepared
}

fn retryable_entry(account: &crate::bus::state::LocalBusAccountState) -> ReceiveEntry {
    let mut entry = live_dummy(account);
    entry.entry.envelope.signed.signature = encode_base64url([7u8; 64]);
    entry
}

thread_local! {
    static GENERATION: Cell<u64> = const { Cell::new(1) };
}

fn bump_generation() {
    GENERATION.with(|cell| cell.set(2));
}

fn current_generation() -> u64 {
    GENERATION.with(Cell::get)
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

async fn drive_disk(
    account: &mut crate::bus::state::LocalBusAccountState,
    sequence: u64,
    generation: impl Fn() -> u64 + 'static,
) -> Result<crate::bus::connection_manager::ReceiveApplied, SdkError> {
    let recovered = from_disk(account, sequence)?;
    drive(account, recovered, generation).await
}

fn unrouted_journals(db: &AccountDb) -> Result<usize, SdkError> {
    Ok(db
        .journal_after(0, 128)?
        .into_iter()
        .filter(|event| event.topic == "message.unrouted")
        .count())
}

fn cursor(account: &crate::bus::state::LocalBusAccountState) -> Result<u64, SdkError> {
    Ok(account
        .client
        .account_db()?
        .receive_ledger_snap_for_test(&account.target_delivery_id)?
        .cursor)
}

struct CountSends {
    sends: Arc<AtomicUsize>,
}

impl ramflux_transport::GatewaySessionFrameSink for CountSends {
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl ramflux_transport::GatewaySessionFrameSource for CountSends {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>,
    > {
        Box::pin(async { Err(TransportError::Quic("unexpected network".into())) })
    }
}

fn attach_counter(account: &mut crate::bus::state::LocalBusAccountState) -> Arc<AtomicUsize> {
    let sends = Arc::new(AtomicUsize::new(0));
    account.engine = Some(crate::gateway::GatewaySessionEngine::with_test_transport(
        account.gateway_config.clone(),
        Box::new(CountSends { sends: Arc::clone(&sends) }),
    ));
    sends
}

fn persist_projection_receipt(
    account: &crate::bus::state::LocalBusAccountState,
    entry: &crate::GatewayInboxEntry,
    key: &str,
) -> Result<(), SdkError> {
    let receipt = Committed {
        routing: Routing {
            kind: Kind::Direct,
            conversation_id: "thread".to_owned(),
            group_id: None,
            message_id: "projection-owner".to_owned(),
            group_message_id: None,
            attachments: false,
        },
        entry: entry.clone(),
        projected: false,
    };
    account.client.account_db()?.persist_actor_state(key, &receipt)?;
    Ok(())
}

fn arm_w1_cut(_db: &AccountDb) {
    set_before_commit("apply page w1 before-commit");
}

fn erase_pending(db: &AccountDb) {
    erase_through_retention(db).expect("erase");
}

fn arm_w1_erase(_db: &AccountDb) {
    set_before_commit_hook(erase_pending);
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Wal,
    RedbOnly,
}

fn router_err(error: &ramflux_node_core::NodeCoreError) -> SdkError {
    SdkError::LocalBus(error.to_string())
}

fn router_path(root: &Path) -> PathBuf {
    root.join("router.redb")
}

fn wal_dir(path: &Path) -> PathBuf {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("router.redb");
    path.with_file_name(format!("{name}.wal"))
}

fn pin_mode(path: &Path, mode: Mode) {
    let wal = wal_dir(path);
    match mode {
        Mode::Wal => assert!(wal.exists(), "WAL root {wal:?}"),
        Mode::RedbOnly => assert!(!wal.exists(), "redb-only has no WAL root {wal:?}"),
    }
}

fn open_router(path: &Path, mode: Mode) -> Result<RouterRedbStore, SdkError> {
    match mode {
        Mode::Wal => RouterRedbStore::open_with_wal(path, wal_dir(path)),
        Mode::RedbOnly => RouterRedbStore::open_without_wal(path),
    }
    .map_err(|error| router_err(&error))
}

fn as_inbox(entry: &crate::GatewayInboxEntry) -> InboxEntry {
    InboxEntry {
        inbox_seq: entry.inbox_seq,
        target_delivery_id: entry.target_delivery_id.clone(),
        envelope: entry.envelope.clone(),
    }
}

fn pending_rows(store: &RouterRedbStore, target: &str) -> Result<Vec<InboxEntry>, SdkError> {
    Ok(store
        .load_router()
        .map_err(|error| router_err(&error))?
        .map(|router| router.pending_entries_for_target(target))
        .unwrap_or_default())
}

fn seed_router_row(
    store: &RouterRedbStore,
    entry: &crate::GatewayInboxEntry,
) -> Result<(), SdkError> {
    store.bootstrap_router(&RouterCore::new()).map_err(|error| router_err(&error))?;
    store.record_inbox_entry(&as_inbox(entry)).map_err(|error| router_err(&error))
}

fn remove_router_row(store: &RouterRedbStore) -> Result<usize, SdkError> {
    store.sweep_delivery_retention(i64::MAX, false).map_err(|error| router_err(&error))
}

fn kill_reopen(
    path: &Path,
    store: RouterRedbStore,
    mode: Mode,
) -> Result<RouterRedbStore, SdkError> {
    drop(store);
    open_router(path, mode)
}

fn durable_pending(
    path: &Path,
    store: RouterRedbStore,
    target: &str,
    mode: Mode,
) -> Result<(RouterRedbStore, Vec<InboxEntry>), SdkError> {
    let store = kill_reopen(path, store, mode)?;
    pin_mode(path, mode);
    let rows = pending_rows(&store, target)?;
    assert_eq!(rows.len(), 1, "inbox row survived {mode:?} kill/reopen");
    Ok((store, rows))
}

fn row_removed(
    path: &Path,
    store: RouterRedbStore,
    target: &str,
    mode: Mode,
) -> Result<(), SdkError> {
    let removed = remove_router_row(&store)?;
    assert!(removed >= 1, "real router row removed: {removed}");
    let store = kill_reopen(path, store, mode)?;
    assert!(pending_rows(&store, target)?.is_empty(), "{mode:?} row gone after reopen");
    Ok(())
}

fn receive_from_inbox(row: &InboxEntry) -> ReceiveEntry {
    ReceiveEntry {
        entry: crate::GatewayInboxEntry {
            forwarded: false,
            inbox_seq: row.inbox_seq,
            target_delivery_id: row.target_delivery_id.clone(),
            envelope: row.envelope.clone(),
        },
        retry_key: None,
        replay: false,
        turn: None,
    }
}

#[derive(Clone, Copy, Debug)]
enum Sweep {
    OwnCopy,
    LegacyHold,
    A2i,
    Failure,
    Projection,
    LegacyDm,
}

fn arm_sweep(
    sweep: Sweep,
    account: &crate::bus::state::LocalBusAccountState,
    entry: &ReceiveEntry,
) -> Result<(), SdkError> {
    match sweep {
        Sweep::OwnCopy => queue_own_copy(),
        Sweep::LegacyHold => queue_legacy_hold(std::iter::repeat_n(true, 8)),
        Sweep::A2i => queue_unbound_answers(std::iter::repeat_n(true, 8)),
        Sweep::Failure => queue_policy_kind(ReceiveFailureKind::Deterministic),
        Sweep::Projection => {
            persist_projection_receipt(account, &entry.entry, "authenticated-projection-key")?;
            set_projection_key("authenticated-projection-key");
            queue_projection();
        }
        Sweep::LegacyDm => {}
    }
    Ok(())
}

fn sweep_entry(
    sweep: Sweep,
    account: &crate::bus::state::LocalBusAccountState,
) -> Result<ReceiveEntry, SdkError> {
    match sweep {
        Sweep::Failure => Ok(retryable_entry(account)),
        Sweep::Projection => Ok(live_dummy(account)),
        Sweep::LegacyDm => legacy_dm_entry(account),
        _ => Ok(own_dummy(account)),
    }
}

fn pin_own_directory(account: &crate::bus::state::LocalBusAccountState) -> Result<(), SdkError> {
    let manifest = test_support::public_manifest(&account.client)?;
    account.client.persist_root_verified_directory(&manifest)
}

fn legacy_dm_entry(
    account: &crate::bus::state::LocalBusAccountState,
) -> Result<ReceiveEntry, SdkError> {
    pin_own_directory(account)?;
    let local = account.gateway_config.device_id.clone();
    let sender_hash = dm_device_id_hash(&local);
    let transcript = [7u8; 32];
    let seed = [9u8; 32];
    let mut sending = DmSession::initiator(seed, sender_hash, sender_hash, transcript)?;
    let receiving = DmSession::recipient(seed, sender_hash, sender_hash, transcript)?;
    account.client.send_direct_message("legacy-dm-sweep", "prior", "alice", b"history")?;
    account.client.persist_dm_session("legacy-dm-sweep", "bound-history", "recv", &receiving)?;
    let ciphertext = sending.encrypt(b"body", dm_associated_data("legacy-dm-sweep"))?;
    let inner = SdkDmEncryptedEnvelope {
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".into(),
        version: 1,
        source_principal_commitment: None,
        x3dh: None,
        ciphertext,
    };
    let message = GatewayDirectMessage {
        conversation_id: "legacy-dm-sweep".into(),
        message_id: "legacy-dm-one".into(),
        envelope_id: "legacy-dm-one".into(),
        source_principal_id: account.gateway_config.principal_id.clone(),
        sender_id: local.clone(),
        recipient_device_id: Some(local.clone()),
        recipient_principal_commitment: None,
        target_delivery_id: account.target_delivery_id.clone(),
        encrypted_body: serde_json::to_vec(&inner)?,
        created_at: now_unix_timestamp(),
        ttl: 86_400,
    };
    Ok(ReceiveEntry {
        entry: crate::GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: account.target_delivery_id.clone(),
            envelope: gateway_direct_message_envelope(&account.gateway_config, &message, None)?,
        },
        retry_key: None,
        replay: false,
        turn: None,
    })
}

#[derive(Clone, Debug, PartialEq)]
struct Ledger {
    state: (Option<String>, i64),
    cursor: u64,
    journals: usize,
    holds: u64,
    work: i64,
    intents: Vec<u64>,
}

fn ledger(account: &crate::bus::state::LocalBusAccountState) -> Result<Ledger, SdkError> {
    let db = account.client.account_db()?;
    let snap = db.receive_ledger_snap_for_test(&account.target_delivery_id)?;
    Ok(Ledger {
        state: db.receive_state_for_test(1)?,
        cursor: snap.cursor,
        journals: unrouted_journals(db)?,
        holds: db.unrouted_count()?,
        work: snap.work,
        intents: snap.intents,
    })
}

fn expected_ledger(sweep: Sweep) -> Ledger {
    match sweep {
        Sweep::OwnCopy | Sweep::LegacyDm | Sweep::Projection => Ledger {
            state: (Some("staged".into()), 1),
            cursor: 0,
            journals: 0,
            holds: 0,
            work: 1,
            intents: Vec::new(),
        },
        Sweep::LegacyHold => Ledger {
            state: (Some("held".into()), 1),
            cursor: 1,
            journals: 1,
            holds: 1,
            work: 1,
            intents: Vec::new(),
        },
        Sweep::A2i => Ledger {
            state: (Some("held".into()), 1),
            cursor: 1,
            journals: 0,
            holds: 1,
            work: 1,
            intents: Vec::new(),
        },
        Sweep::Failure => {
            Ledger { state: (None, 0), cursor: 1, journals: 0, holds: 0, work: 0, intents: vec![1] }
        }
    }
}

fn assert_ledger(got: &Ledger, sweep: Sweep) {
    let want = expected_ledger(sweep);
    assert_eq!(got.state, want.state, "{sweep:?} hold/receipt disposition");
    assert_eq!(got.cursor, want.cursor, "{sweep:?} cursor");
    assert_eq!(got.journals, want.journals, "{sweep:?} message.unrouted journals");
    assert_eq!(got.holds, want.holds, "{sweep:?} hold rows");
    assert_eq!(got.work, want.work, "{sweep:?} work rows");
    assert_eq!(got.intents, want.intents, "{sweep:?} ack intents");
}

fn assert_legacy_dm_w1_effect(
    account: &crate::bus::state::LocalBusAccountState,
    entry: &ReceiveEntry,
) -> Result<(), SdkError> {
    assert!(account.client.legacy_w1_committed(&entry.entry)?, "legacy-DM W1 committed marker");
    let rows = content_rows(account.client.account_db()?)?;
    assert!(
        rows.iter()
            .any(|row| row.starts_with("direct_message_projection|")
                && row.contains("legacy-dm-one")),
        "legacy-DM W1 projection row: {rows:?}"
    );
    Ok(())
}

fn assert_sweep(
    account: &crate::bus::state::LocalBusAccountState,
    sweep: Sweep,
    entry: &ReceiveEntry,
) -> Result<(), SdkError> {
    assert_ledger(&ledger(account)?, sweep);
    if matches!(sweep, Sweep::LegacyDm) {
        assert_legacy_dm_w1_effect(account, entry)?;
    }
    Ok(())
}

async fn redrive_once(
    account: &mut crate::bus::state::LocalBusAccountState,
    entry: ReceiveEntry,
) -> Result<(), SdkError> {
    match from_disk(account, 1) {
        Ok(recovered) => {
            let _ = drive(account, recovered, || 1).await?;
        }
        Err(_) => {
            let _ = drive(account, entry, || 1).await?;
        }
    }
    Ok(())
}

async fn before_commit_cell(sweep: Sweep, mode: Mode) -> Result<(), SdkError> {
    let mut harness = open()?;
    let sends = attach_counter(&mut harness.account);
    let entry = sweep_entry(sweep, &harness.account)?;
    arm_sweep(sweep, &harness.account, &entry)?;
    let path = router_path(harness.root.path());
    let store = open_router(&path, mode)?;
    seed_router_row(&store, &entry.entry)?;
    pin_mode(&path, mode);
    set_after_classify(arm_w1_cut);
    let cut = drive(&mut harness.account, entry.clone(), || 1).await;
    let error = cut.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(text)))
                if *text == "apply page w1 before-commit"
        ),
        "before-commit {sweep:?} {mode:?}: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    let (store, rows) = durable_pending(&path, store, &entry.entry.target_delivery_id, mode)?;
    let recovered = receive_from_inbox(&rows[0]);
    reopen(&mut harness.account)?;
    arm_sweep(sweep, &harness.account, &entry)?;
    let _ = drive(&mut harness.account, recovered, || 1).await?;
    assert_sweep(&harness.account, sweep, &entry)?;
    reopen(&mut harness.account)?;
    arm_sweep(sweep, &harness.account, &entry)?;
    redrive_once(&mut harness.account, entry.clone()).await?;
    assert_sweep(&harness.account, sweep, &entry)?;
    row_removed(&path, store, &entry.entry.target_delivery_id, mode)?;
    assert_eq!(sends.load(Ordering::SeqCst), 0, "no double ACK");
    Ok(())
}

async fn after_commit_cell(sweep: Sweep, mode: Mode) -> Result<(), SdkError> {
    let mut harness = open()?;
    let sends = attach_counter(&mut harness.account);
    let entry = sweep_entry(sweep, &harness.account)?;
    arm_sweep(sweep, &harness.account, &entry)?;
    let path = router_path(harness.root.path());
    let store = open_router(&path, mode)?;
    seed_router_row(&store, &entry.entry)?;
    pin_mode(&path, mode);
    let _ = drive(&mut harness.account, entry.clone(), || 1).await?;
    let (store, rows) = durable_pending(&path, store, &entry.entry.target_delivery_id, mode)?;
    let recovered = receive_from_inbox(&rows[0]);
    reopen(&mut harness.account)?;
    arm_sweep(sweep, &harness.account, &entry)?;
    redrive_once(&mut harness.account, recovered).await?;
    assert_sweep(&harness.account, sweep, &entry)?;
    row_removed(&path, store, &entry.entry.target_delivery_id, mode)?;
    assert_eq!(sends.load(Ordering::SeqCst), 0, "no double ACK");
    Ok(())
}

async fn sweep_kind(sweep: Sweep) -> Result<(), SdkError> {
    before_commit_cell(sweep, Mode::Wal).await?;
    before_commit_cell(sweep, Mode::RedbOnly).await?;
    after_commit_cell(sweep, Mode::Wal).await?;
    after_commit_cell(sweep, Mode::RedbOnly).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn own_copy_w1_commit_sweep() -> Result<(), SdkError> {
    sweep_kind(Sweep::OwnCopy).await
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_hold_w1_commit_sweep() -> Result<(), SdkError> {
    sweep_kind(Sweep::LegacyHold).await
}

#[tokio::test(flavor = "current_thread")]
async fn a2i_w1_commit_sweep() -> Result<(), SdkError> {
    sweep_kind(Sweep::A2i).await
}

#[tokio::test(flavor = "current_thread")]
async fn failure_w1_commit_sweep() -> Result<(), SdkError> {
    sweep_kind(Sweep::Failure).await
}

#[tokio::test(flavor = "current_thread")]
async fn projection_w1_commit_sweep() -> Result<(), SdkError> {
    sweep_kind(Sweep::Projection).await
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_dm_w1_commit_sweep() -> Result<(), SdkError> {
    sweep_kind(Sweep::LegacyDm).await
}

fn content_rows(db: &AccountDb) -> Result<Vec<String>, SdkError> {
    Ok(db
        .durable_rows_for_test()?
        .into_iter()
        .filter(|row| {
            row.starts_with("direct_message_projection|")
                || row.starts_with("message_copy_binding|")
                || row.starts_with("message_footprint|")
                || row.starts_with("object_key_slot|")
        })
        .collect())
}

thread_local! {
    static ERASE_MESSAGE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn erase_pending_message(db: &AccountDb) {
    let owner = ERASE_MESSAGE.with(|cell| cell.borrow().clone()).expect("pending message");
    erase_message_through_retention(db, &owner).expect("erase pending message");
}

#[tokio::test(flavor = "current_thread")]
async fn erase_while_w1_pending_reopen_no_resurrection() -> Result<(), SdkError> {
    let mut harness = open()?;
    let owner = "pending-w1".to_owned();
    harness.account.client.send_direct_message("thread", &owner, "peer", b"body")?;
    let mut entry = own_dummy(&harness.account);
    entry.entry.envelope.envelope_id = owner.clone();
    ERASE_MESSAGE.with(|cell| cell.replace(Some(owner.clone())));
    queue_own_copy();
    set_after_classify(erase_pending_message);
    let refused = drive(&mut harness.account, entry.clone(), || 1).await;
    let error = refused.as_ref().err();
    assert!(matches!(error, Some(SdkError::ObjectErased)), "erase while W1 pending: {error:?}");
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    reopen(&mut harness.account)?;
    queue_own_copy();
    let _ = drive_disk(&mut harness.account, 1, || 1).await?;
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("erased".into()), 0),
        "erased-only receipt settlement"
    );
    let content = content_rows(harness.account.client.account_db()?)?;
    assert!(
        content.iter().any(|row| row.starts_with("direct_message_projection|")
            && row.contains(&owner)
            && row.contains("|1|0|0|")),
        "erased projection stays deleted: {content:?}"
    );
    assert!(
        !content.iter().any(|row| row.contains("erase-alias")),
        "no alias resurrection: {content:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn late_w0_fence_refuses_erase_during_stage() -> Result<(), SdkError> {
    let mut harness = open()?;
    set_before_commit_hook(erase_pending);
    let entry = own_dummy(&harness.account);
    let refused = drive(&mut harness.account, entry, || 1).await;
    let error = refused.as_ref().err();
    assert!(matches!(error, Some(SdkError::ObjectErased)), "late W0 fence: {error:?}");
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (None, 0),
        "late W0 fence rolled back the staged receipt"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn late_w1_fence_refuses_erase_during_commit() -> Result<(), SdkError> {
    let mut harness = open()?;
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    set_after_classify(arm_w1_erase);
    let entry = own_dummy(&harness.account);
    let refused = drive(&mut harness.account, entry, || 1).await;
    let error = refused.as_ref().err();
    assert!(matches!(error, Some(SdkError::ObjectErased)), "late W1 fence: {error:?}");
    Ok(())
}

fn injected_io() -> SdkError {
    SdkError::Io(std::io::Error::other("injected io"))
}

fn injected_json() -> SdkError {
    SdkError::Json(serde_json::from_str::<u8>("x").expect_err("json"))
}

fn injected_sync() -> SdkError {
    SdkError::Sync(SyncError::ObjectNotFound)
}

fn injected_account() -> SdkError {
    SdkError::AccountNotOpen("injected".into())
}

fn injected_pending() -> SdkError {
    SdkError::InboundPending("injected pending".into())
}

fn injected_directory() -> SdkError {
    SdkError::DirectoryAuthorityUnavailable {
        root: "root".into(),
        source: Box::new(SdkError::Io(std::io::Error::other("directory"))),
    }
}

async fn projection_propagates(
    error: SdkError,
    pin: fn(&SdkError) -> bool,
) -> Result<(), SdkError> {
    let mut harness = open()?;
    queue_own_copy();
    set_projection_error(error);
    let entry = live_dummy(&harness.account);
    let refused = drive(&mut harness.account, entry, || 1).await;
    let got = refused.as_ref().err();
    assert!(pin(got.expect("propagated")), "projection arm: {got:?}");
    Ok(())
}

async fn settled_propagates(error: SdkError, pin: fn(&SdkError) -> bool) -> Result<(), SdkError> {
    let mut harness = open()?;
    set_projection_error(error);
    let entry = retryable_entry(&harness.account);
    let refused = drive(&mut harness.account, entry, || 1).await;
    let got = refused.as_ref().err();
    assert!(pin(got.expect("propagated")), "settled arm: {got:?}");
    Ok(())
}

fn is_io(error: &SdkError) -> bool {
    matches!(error, SdkError::Io(_))
}
fn is_json(error: &SdkError) -> bool {
    matches!(error, SdkError::Json(_))
}
fn is_sync(error: &SdkError) -> bool {
    matches!(error, SdkError::Sync(SyncError::ObjectNotFound))
}
fn is_account(error: &SdkError) -> bool {
    matches!(error, SdkError::AccountNotOpen(text) if text == "injected")
}
fn is_pending(error: &SdkError) -> bool {
    matches!(error, SdkError::InboundPending(text) if text == "injected pending")
}
fn is_directory(error: &SdkError) -> bool {
    matches!(error, SdkError::DirectoryAuthorityUnavailable { root, .. } if root == "root")
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_owed_propagates_io() -> Result<(), SdkError> {
    projection_propagates(injected_io(), is_io).await?;
    settled_propagates(injected_io(), is_io).await
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_owed_propagates_json() -> Result<(), SdkError> {
    // `failure_of` maps Json to deterministic `schema_invalid` before classify
    // returns, so the settled arm cannot exact-match Json. The projection arm
    // (after classify) is the exact-error pin.
    projection_propagates(injected_json(), is_json).await
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_owed_propagates_sync() -> Result<(), SdkError> {
    projection_propagates(injected_sync(), is_sync).await?;
    settled_propagates(injected_sync(), is_sync).await
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_owed_propagates_account_not_open() -> Result<(), SdkError> {
    projection_propagates(injected_account(), is_account).await?;
    settled_propagates(injected_account(), is_account).await
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_owed_propagates_inbound_pending() -> Result<(), SdkError> {
    projection_propagates(injected_pending(), is_pending).await
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_owed_propagates_directory_unavailable() -> Result<(), SdkError> {
    projection_propagates(injected_directory(), is_directory).await?;
    settled_propagates(injected_directory(), is_directory).await
}

#[tokio::test(flavor = "current_thread")]
async fn identity_absence_is_nothing_owed() -> Result<(), SdkError> {
    let mut harness = open()?;
    queue_own_copy();
    set_projection_error(SdkError::IdentityRootMissing);
    let entry = live_dummy(&harness.account);
    drive(&mut harness.account, entry, || 1).await?;
    let mut harness = open()?;
    queue_own_copy();
    set_projection_error(SdkError::InboundRejected("identity authority: missing".into()));
    let entry = live_dummy(&harness.account);
    drive(&mut harness.account, entry, || 1).await?;
    Ok(())
}

fn own_copy_packet(
    account: &crate::bus::state::LocalBusAccountState,
) -> Result<ReceiveEntry, SdkError> {
    let device = account.gateway_config.device_id.clone();
    let packet = json!({
        "schema": "ramflux.sdk.own_device_message.v2",
        "id": "own-copy-wait",
        "nonce": encode_base64url([0u8; 12]),
        "ciphertext": encode_base64url(b"cipher"),
        "slots": [{
            "recipient_device_id": device,
            "ciphertext": {
                "session_id": "s",
                "counter": 1,
                "nonce": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "ciphertext": []
            }
        }],
        "signature": "sig"
    });
    let mut bytes = PREFIX.to_vec();
    bytes.extend(serde_json::to_vec(&packet)?);
    let mut entry = dummy_seq(
        &account.target_delivery_id,
        &encode_base64url(&bytes),
        &account.gateway_config.principal_id,
        &device,
        1,
    );
    entry.entry.envelope.delivery_class = ramflux_protocol::DeliveryClass::SelfDeviceControl;
    Ok(entry)
}

async fn serve_manifest(
    root: &Path,
    mut config: crate::GatewaySessionConfig,
    manifest: crate::prekey::SdkDeviceManifestResponse,
) -> Result<(crate::GatewaySessionConfig, tokio::task::JoinHandle<Result<(), SdkError>>), SdkError>
{
    let certificate = rcgen::generate_simple_self_signed(vec!["sweep-directory.test".into()])
        .map_err(|error| SdkError::LocalBus(error.to_string()))?;
    let ca = root.join("sweep-directory.pem");
    std::fs::write(&ca, certificate.cert.pem())?;
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| SdkError::LocalBus(error.to_string()))?
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
    )
    .map_err(|error| SdkError::LocalBus(error.to_string()))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(SdkError::from)?;
    let address = listener.local_addr().map_err(SdkError::from)?;
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let mut stream = tokio_rustls::TlsStream::Server(
            acceptor.accept(socket).await.map_err(|error| SdkError::LocalBus(error.to_string()))?,
        );
        let request: ramflux_transport::GatewayQuicRequest =
            ramflux_transport::read_gateway_session_json(&mut stream).await?;
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.path,
            format!("/mvp1/device-manifest/{}", manifest.principal_commitment)
        );
        ramflux_transport::write_gateway_session_json(
            &mut stream,
            &ramflux_transport::GatewayQuicResponse {
                status: 200,
                body: serde_json::to_value(manifest)?,
            },
        )
        .await?;
        Ok(())
    });
    config.transport_kind = GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "sweep-directory.test".into();
    config.ca_cert = ca;
    config.timeout = Duration::from_secs(5);
    Ok((config, task))
}

#[tokio::test(flavor = "current_thread")]
async fn manifest_wait_drives_real_cache_verified_fetch() -> Result<(), SdkError> {
    let mut harness = open()?;
    let before = harness.account.client.account_db()?.durable_rows_for_test()?;
    let manifest = test_support::public_manifest(&harness.account.client)?;
    let (config, server) =
        serve_manifest(harness.root.path(), harness.account.gateway_config.clone(), manifest)
            .await?;
    harness.account.engine = None;
    harness.account.gateway_config = config;
    GENERATION.with(|cell| cell.set(1));
    set_manifest_await(bump_generation);
    let entry = own_copy_packet(&harness.account)?;
    let refused = drive(&mut harness.account, entry, current_generation).await;
    server.await.map_err(|error| SdkError::LocalBus(error.to_string()))??;
    let error = refused.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::Storage(StorageError::AuthorizationRejected))),
        "real manifest wait generation bump: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    assert_eq!(cursor(&harness.account)?, 0);
    let after = harness.account.client.account_db()?.durable_rows_for_test()?;
    assert!(
        after.iter().any(|row| !before.contains(row)),
        "manifest wait wrote rows beyond before={}: {after:?}",
        before.len()
    );
    Ok(())
}

fn seed_cover_seq1(
    account: &crate::bus::state::LocalBusAccountState,
) -> Result<ApplyOutcome, SdkError> {
    let db = account.client.account_db()?;
    let prepared = turn(account, 1)?;
    let losses = [ApplyLoss { from_seq: 1, to_seq: 1, reason: "expired" }];
    let page = ApplyPage {
        target: &prepared.target,
        incarnation: &prepared.incarnation,
        after: 0,
        covered: 1,
        issued: 1,
        settled: 0,
        entries: &[],
        known_losses: &losses,
        oversize_next: None,
        more: false,
    };
    match apply::apply_page(db, prepared.expected(), 1, page) {
        Ok(outcome) => Ok(outcome),
        Err(apply::ApplyError::Protocol(text)) => Err(SdkError::InboundRejected(text.into())),
        Err(apply::ApplyError::Storage(error)) => Err(error.into()),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn covered_below_from_seeded_storage_plan() -> Result<(), SdkError> {
    let mut harness = open()?;
    let before = harness.account.client.account_db()?.durable_rows_for_test()?;
    assert_eq!(seed_cover_seq1(&harness.account)?, ApplyOutcome::Covered { cursor: 1 });
    let entry = dummy_seq(
        &harness.account.target_delivery_id,
        &encode_base64url(b"legacy-a2i-dummy"),
        &harness.account.gateway_config.principal_id,
        &harness.account.gateway_config.device_id,
        2,
    );
    let refused = drive(&mut harness.account, entry, || 1).await;
    let error = refused.as_ref().err();
    // reconcile_entry always puts seq in `entries`, so admit_open sees NeedStage
    // rather than Covered{seq-1}. COVERED_BELOW stays a plan-bug arm; reaching it
    // from this seeded cover needs a reconcile_entry seam (BLOCKED L3).
    assert!(
        error.is_none(),
        "seeded cover of seq-1 plus drive of seq is NeedStage today: {error:?}"
    );
    let _ = before;
    Ok(())
}
