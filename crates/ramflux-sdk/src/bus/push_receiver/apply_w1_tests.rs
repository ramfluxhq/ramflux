// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `ApplyPage` fence, binding retry, and routed refusal (S6b P20f / P20c r2 CARRY).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use super::apply::{self, ApplyLoss, ApplyOutcome, ApplyPage};
use super::apply_w1::{
    self, after_w1_cut, apply_page, binding_attempts, covered_below, force_covered_below,
    force_need_point, queue_legacy_hold, queue_manifest_wait, queue_own_copy, queue_policy_kind,
    queue_projection, queue_terminal_reply, set_after_classify, set_after_w1_cut,
    set_before_commit, set_cross_await, set_manifest_await, set_projection_key,
};
use super::erase_support::erase_through_retention;
use crate::bus::connection_manager::receive::bind_retry_turns;
use crate::bus::connection_manager::{ReceiveEntry, ReceiveTurn};
use crate::bus::contact_backpressure::Backpressure;
use crate::bus::runtime_tests;
use crate::bus::sync_driver::source::failure::{self as source_failure, SourceFailure};
use crate::client::a2i::queue_unbound_answers;
use crate::client::application_outbox::{ApplicationEvent, OUTBOX};
use crate::client::legacy_w1::{self, Fault};
use crate::client::reply_outbox::MARKER;
use crate::client::routed::{Committed, Kind, Routing};
use crate::prelude::*;
use ramflux_protocol::encode_base64url;
use ramflux_storage::{
    AccountDb, MISSING_EPOCH, ProjectionStore, ReceiveFailureKind, ReceiveMigrate, ReceiveStage,
    ReceiveStageResult, StorageError,
};
use ramflux_transport::TransportError;
use serde_json::json;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Harness {
    _root: tempfile::TempDir,
    account: crate::bus::state::LocalBusAccountState,
}

fn open() -> Result<Harness, SdkError> {
    let root = tempfile::tempdir().expect("tmp");
    let mut account =
        runtime_tests::account(root.path(), "acct", None, Arc::new(AtomicBool::new(false)))?;
    bind_push(&mut account);
    let target = account.target_delivery_id.clone();
    let db = account.client.account_db()?;
    let _ = db.activate_receive_ledger(ReceiveMigrate { target: &target, incarnation: "e" })?;
    Ok(Harness { _root: root, account })
}

/// W1 unit tests cover the Push/Terminal path unless they opt into Legacy/Compat.
fn bind_push(account: &mut crate::bus::state::LocalBusAccountState) {
    if let Some(engine) = account.engine.as_mut() {
        engine.mode = crate::gateway::session_push::SessionMode::Push {
            incarnation: crate::gateway::session_push::IncarnationId::try_from(
                "0123456789abcdef0123456789abcdef".to_owned(),
            )
            .expect("incarnation"),
        };
    }
}

fn turn(
    account: &crate::bus::state::LocalBusAccountState,
    generation: u64,
) -> Result<ReceiveTurn, SdkError> {
    let db = account.client.account_db()?;
    apply_w1::capture_turn(db, generation, &account.target_delivery_id)
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

fn prepared(target: &str, payload: &str) -> ReceiveEntry {
    prepared_from(target, payload, "source", "device")
}

fn prepared_from(target: &str, payload: &str, principal: &str, device: &str) -> ReceiveEntry {
    dummy_seq(target, payload, principal, device, 1)
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

fn routed_payload() -> String {
    let inner = json!({
        "schema": "ramflux.sdk.dm_x3dh_envelope.v2",
        "version": 2,
        "ciphertext": {
            "session_id": "s",
            "counter": 1,
            "nonce": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "ciphertext": []
        }
    });
    encode_base64url(serde_json::to_vec(&inner).expect("routed"))
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
    drive_with_turn(account, &prepared_turn, prepared, generation).await
}

async fn drive_with_turn(
    account: &mut crate::bus::state::LocalBusAccountState,
    prepared_turn: &ReceiveTurn,
    prepared: ReceiveEntry,
    generation: impl Fn() -> u64 + 'static,
) -> Result<crate::bus::connection_manager::ReceiveApplied, SdkError> {
    let pressure = Box::new(Backpressure::load(&account.client, now_unix_timestamp())?);
    apply_page(account, prepared_turn, &generation, prepared, None, pressure).await
}

fn own_dummy(account: &crate::bus::state::LocalBusAccountState) -> ReceiveEntry {
    own_dummy_at(account, 1)
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
    let mut prepared = own_dummy(account);
    prepared.entry.envelope.created_at = now_unix_timestamp();
    prepared.entry.envelope.ttl = 86_400;
    prepared
}

/// A live entry whose wire signature has the right shape, so only a directory miss
/// (not an immutable wire error) can make it retryable.
fn retryable_entry(account: &crate::bus::state::LocalBusAccountState) -> ReceiveEntry {
    let mut entry = live_dummy(account);
    entry.entry.envelope.signed.signature = encode_base64url([7u8; 64]);
    entry
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
    let mut engine = crate::gateway::GatewaySessionEngine::with_test_transport(
        account.gateway_config.clone(),
        Box::new(CountSends { sends: Arc::clone(&sends) }),
    );
    engine.mode = crate::gateway::session_push::SessionMode::Push {
        incarnation: crate::gateway::session_push::IncarnationId::try_from(
            "0123456789abcdef0123456789abcdef".to_owned(),
        )
        .expect("incarnation"),
    };
    account.engine = Some(engine);
    sends
}

const BEFORE: &str = "legacy w1 before-commit";

#[tokio::test(flavor = "current_thread")]
async fn apply_page_refuses_stale_generation_after_await() -> Result<(), SdkError> {
    let mut harness = open()?;
    let target = harness.account.target_delivery_id.clone();
    let db = harness.account.client.account_db()?;
    let before = db.durable_rows_for_test()?;
    GENERATION.with(|cell| cell.set(1));
    set_cross_await(bump_generation);
    let refused =
        drive(&mut harness.account, prepared(&target, "cipher"), current_generation).await;
    let error = refused.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::Storage(StorageError::AuthorizationRejected))),
        "generation bump during the await must refuse: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.durable_rows_for_test()?,
        before,
        "stale generation after the manifest await writes nothing"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a2i_binding_change_refuses_before_legacy_retry() -> Result<(), SdkError> {
    let mut harness = open()?;
    let target = harness.account.target_delivery_id.clone();
    queue_unbound_answers(std::iter::repeat_n(true, 8));
    legacy_w1::set_fault(Fault::BindingAppeared);
    let dummy = encode_base64url(b"legacy-a2i-dummy");
    let device = harness.account.gateway_config.device_id.clone();
    let principal = harness.account.gateway_config.principal_id.clone();
    let refused =
        drive(&mut harness.account, prepared_from(&target, &dummy, &principal, &device), || 1)
            .await;
    legacy_w1::set_fault(Fault::None);
    let error = refused.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::GeneratedRefused {
                code: crate::error::GeneratedRefusalCode::Authority,
                ..
            })
        ),
        "A2I must refuse before legacy binding retries: {error:?}"
    );
    assert_eq!(binding_attempts(), 0, "refused A2I never enters a binding retry");
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1),
        "W0 stays staged"
    );
    assert_eq!(unrouted_journals(harness.account.client.account_db()?)?, 0, "no hold journal");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn active_routed_requires_live_session() -> Result<(), SdkError> {
    let mut harness = open()?;
    let target = harness.account.target_delivery_id.clone();
    let refused = drive(&mut harness.account, prepared(&target, &routed_payload()), || 1).await;
    let error = refused.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::GatewaySessionNotEstablished)),
        "routed W1 needs a live session: {error:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn staging_survives_router_expiry() -> Result<(), SdkError> {
    const START: i64 = 1_700_000_000;
    let _clock = crate::time::FixedClock::set(START);
    let mut harness = open()?;
    let sends = attach_counter(&mut harness.account);
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    legacy_w1::set_fault(Fault::BeforeCommit);
    let entry = own_dummy(&harness.account);
    let cut = drive(&mut harness.account, entry.clone(), || 1).await;
    legacy_w1::set_fault(Fault::None);
    let error = cut.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::Storage(StorageError::Integrity(text))) if *text == BEFORE),
        "W1 cut before COMMIT: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1),
        "W0 survives the W1 cut"
    );
    crate::time::FixedClock::advance_to(START + 700);
    reopen(&mut harness.account)?;
    reopen(&mut harness.account)?;
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1),
        "W0 survives router retention and reopen"
    );
    let recovered = drive_disk(&mut harness.account, 1, || 1).await?;
    assert!(recovered.0.is_none(), "recovery writes no ACK intent");
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("held".into()), 1),
        "one held effect after expiry"
    );
    assert_eq!(
        harness
            .account
            .client
            .account_db()?
            .receive_ledger_snap_for_test(&harness.account.target_delivery_id)?
            .cursor,
        1
    );
    assert_eq!(sends.load(Ordering::SeqCst), 0);

    let mut missing = open()?;
    let sends = attach_counter(&mut missing.account);
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    legacy_w1::set_fault(Fault::BeforeCommit);
    let entry = own_dummy(&missing.account);
    let cut = drive(&mut missing.account, entry.clone(), || 1).await;
    legacy_w1::set_fault(Fault::None);
    let error = cut.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::Storage(StorageError::Integrity(text))) if *text == BEFORE),
        "negative cut: {error:?}"
    );
    assert_eq!(
        missing.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    set_after_classify(complete_w0);
    let refused = drive(&mut missing.account, entry, || 1).await;
    let error = refused.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(text)))
                if *text == "source effect requires staged receive work"
        ),
        "deleting W0 after the first W1 subcommit cannot recover: {error:?}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 0, "storage failure must not ACK");
    Ok(())
}

fn complete_w0(db: &AccountDb) {
    db.set_receipt_disposition_for_test(1, "completed").expect("complete W0");
}

#[tokio::test(flavor = "current_thread")]
async fn receive_stage_redrive() -> Result<(), SdkError> {
    let mut harness = open()?;
    let sends = attach_counter(&mut harness.account);
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    legacy_w1::set_fault(Fault::BeforeCommit);
    let entry = own_dummy(&harness.account);
    let cut = drive(&mut harness.account, entry.clone(), || 1).await;
    legacy_w1::set_fault(Fault::None);
    let error = cut.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::Storage(StorageError::Integrity(text))) if *text == BEFORE),
        "{error:?}"
    );
    reopen(&mut harness.account)?;
    let once = drive_disk(&mut harness.account, 1, || 1).await?;
    assert!(once.0.is_none(), "W1 writes no ACK intent");
    let held = harness.account.client.account_db()?.receive_state_for_test(1)?;
    assert_eq!(held, (Some("held".into()), 1), "one held effect");
    assert_eq!(
        harness
            .account
            .client
            .account_db()?
            .receive_ledger_snap_for_test(&harness.account.target_delivery_id)?
            .cursor,
        1
    );
    reopen(&mut harness.account)?;
    assert_eq!(harness.account.client.account_db()?.receive_state_for_test(1)?, held);
    let again = drive_disk(&mut harness.account, 1, || 1).await?;
    assert!(again.0.is_none());
    assert_eq!(harness.account.client.account_db()?.receive_state_for_test(1)?, held);
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn held_admission_stage_crash() -> Result<(), SdkError> {
    let mut blocked = open()?;
    let sends = attach_counter(&mut blocked.account);
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    legacy_w1::set_fault(Fault::BeforeCommit);
    let entry = own_dummy(&blocked.account);
    let cut = drive(&mut blocked.account, entry.clone(), || 1).await;
    legacy_w1::set_fault(Fault::None);
    let error = cut.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::Storage(StorageError::Integrity(text))) if *text == BEFORE),
        "v2-blocked/fallthrough hold cut: {error:?}"
    );
    assert_eq!(
        blocked.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    reopen(&mut blocked.account)?;
    let held = drive_disk(&mut blocked.account, 1, || 1).await?;
    assert!(held.0.is_none());
    assert_eq!(
        blocked.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("held".into()), 1)
    );
    assert_eq!(cursor(&blocked.account)?, 1);
    assert_eq!(sends.load(Ordering::SeqCst), 0);

    let mut unbound = open()?;
    let sends = attach_counter(&mut unbound.account);
    queue_unbound_answers(std::iter::repeat_n(true, 8));
    legacy_w1::set_fault(Fault::BeforeCommit);
    let entry = own_dummy(&unbound.account);
    let cut = drive(&mut unbound.account, entry.clone(), || 1).await;
    legacy_w1::set_fault(Fault::None);
    let error = cut.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::Storage(StorageError::Integrity(text))) if *text == BEFORE),
        "unbound hold cut: {error:?}"
    );
    assert_eq!(
        unbound.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    reopen(&mut unbound.account)?;
    let held = drive_disk(&mut unbound.account, 1, || 1).await?;
    assert!(held.0.is_none());
    assert_eq!(
        unbound.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("held".into()), 1)
    );
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    assert_eq!(cursor(&unbound.account)?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn erasure_late_stage_and_process() -> Result<(), SdkError> {
    let mut harness = open()?;
    let sends = attach_counter(&mut harness.account);
    let prepared_turn = turn(&harness.account, 1)?;
    erase_through_retention(harness.account.client.account_db()?)?;
    let before = harness.account.client.account_db()?.durable_rows_for_test()?;
    queue_unbound_answers(std::iter::repeat_n(false, 8));
    let entry = own_dummy(&harness.account);
    let refused = drive_with_turn(&mut harness.account, &prepared_turn, entry, || 1).await;
    let error = refused.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::AuthorizationRejected) | SdkError::ObjectErased)
        ),
        "late W0/W1 after erase must refuse inside the commit: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.durable_rows_for_test()?,
        before,
        "erasure refuses without resurrecting content"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn held_entries_cover_cursor_in_one_pass() -> Result<(), SdkError> {
    let mut harness = open()?;
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    let start = turn(&harness.account, 1)?;
    let mut progress = 0_u32;
    for seq in [1_u64, 3, 4] {
        let entry = own_dummy_at(&harness.account, seq);
        drive_with_turn(&mut harness.account, &start, entry, || 1).await?;
        progress += 1;
    }
    assert_eq!(progress, 3, "one pass commits every entry");
    let db = harness.account.client.account_db()?;
    assert_eq!(cursor(&harness.account)?, 4);
    let held = db
        .receive_ledger_snap_for_test(&harness.account.target_delivery_id)?
        .receipts
        .into_iter()
        .filter(|(_, disposition)| disposition == "held")
        .count();
    assert_eq!(held, 3, "three held receipts");
    assert_eq!(unrouted_journals(db)?, 3, "one unrouted journal per hold");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a2i_receipt_inbound_rejected_is_not_a_hold() -> Result<(), SdkError> {
    let mut harness = open()?;
    queue_unbound_answers(std::iter::repeat_n(false, 4));
    let entry = own_dummy(&harness.account);
    let refused = drive(&mut harness.account, entry, || 1).await;
    let error = refused.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::InboundRejected(text))
                if text == "identity authority: device metadata absent"
        ),
        "receipt load InboundRejected stays a rejection: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    assert_eq!(unrouted_journals(harness.account.client.account_db()?)?, 0);
    assert_eq!(cursor(&harness.account)?, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn retry_keeps_prepare_turn_after_erasure() -> Result<(), SdkError> {
    let mut harness = open()?;
    let sends = attach_counter(&mut harness.account);
    let prepared = turn(&harness.account, 1)?;
    let mut retries = vec![own_dummy(&harness.account)];
    bind_retry_turns(&mut retries, Some(&prepared));
    let retry = retries.into_iter().next().expect("one retry");
    erase_through_retention(harness.account.client.account_db()?)?;
    let before = harness.account.client.account_db()?.durable_rows_for_test()?;
    let retry_turn = retry.turn.clone().expect("bind_retry_turn keeps the prepare turn");
    let refused = drive_with_turn(&mut harness.account, &retry_turn, retry, || 1).await;
    let error = refused.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::ObjectErased)),
        "retry with prepare-time erasure must refuse inside the commit: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.durable_rows_for_test()?,
        before,
        "erasure after prepare writes nothing on the retry"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn already_covered_sequence_skips_w1() -> Result<(), SdkError> {
    let mut harness = open()?;
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    let entry = own_dummy(&harness.account);
    drive(&mut harness.account, entry.clone(), || 1).await?;
    assert_eq!(cursor(&harness.account)?, 1);
    let journals = unrouted_journals(harness.account.client.account_db()?)?;
    let again = drive(&mut harness.account, entry, || 1).await?;
    assert!(again.0.is_none());
    assert_eq!(cursor(&harness.account)?, 1);
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("held".into()), 1)
    );
    assert_eq!(unrouted_journals(harness.account.client.account_db()?)?, journals);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn covered_below_sequence_is_integrity() -> Result<(), SdkError> {
    let mut harness = open()?;
    let before = harness.account.client.account_db()?.durable_rows_for_test()?;
    force_covered_below();
    let entry = own_dummy(&harness.account);
    let refused = drive(&mut harness.account, entry, || 1).await;
    let error = refused.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(text))) if *text == covered_below()
        ),
        "C < seq must refuse: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.durable_rows_for_test()?,
        before,
        "covered-below writes nothing"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn failure_policy_stage_crash() -> Result<(), SdkError> {
    retryable_failure_cut().await?;
    deterministic_failure_cut().await?;
    Ok(())
}

async fn retryable_failure_cut() -> Result<(), SdkError> {
    let mut harness = open()?;
    source_failure::set_fault(source_failure::Fault::BeforeCommit);
    queue_policy_kind(ReceiveFailureKind::Retryable);
    let entry = retryable_entry(&harness.account);
    let cut = drive(&mut harness.account, entry, || 1).await;
    source_failure::set_fault(source_failure::Fault::None);
    let error = cut.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(text)))
                if *text == "source failure before-commit"
        ),
        "W1 retryable admit cut: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1),
        "W0 survives the retryable cut"
    );
    reopen(&mut harness.account)?;
    queue_policy_kind(ReceiveFailureKind::Retryable);
    let recovered = drive_disk(&mut harness.account, 1, || 1).await?;
    assert!(recovered.0.is_none());
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("held".into()), 1)
    );
    assert_eq!(cursor(&harness.account)?, 1);
    Ok(())
}

async fn deterministic_failure_cut() -> Result<(), SdkError> {
    let mut harness = open()?;
    source_failure::set_fault(source_failure::Fault::BeforeCommit);
    queue_policy_kind(ReceiveFailureKind::Deterministic);
    let entry = live_dummy(&harness.account);
    let cut = drive(&mut harness.account, entry, || 1).await;
    source_failure::set_fault(source_failure::Fault::None);
    let error = cut.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(text)))
                if *text == "source failure before-commit"
        ),
        "W1 deterministic admit cut: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1),
        "W0 survives the deterministic cut"
    );
    reopen(&mut harness.account)?;
    queue_policy_kind(ReceiveFailureKind::Deterministic);
    let recovered = drive_disk(&mut harness.account, 1, || 1).await?;
    assert!(recovered.0.is_none());
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (None, 0),
        "deterministic recovery settles the staged copy"
    );
    assert_eq!(cursor(&harness.account)?, 1);
    let snap = harness
        .account
        .client
        .account_db()?
        .receive_ledger_snap_for_test(&harness.account.target_delivery_id)?;
    assert_eq!(snap.intents, vec![1]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn held_local_expiry_and_eviction_crash() -> Result<(), SdkError> {
    const START: i64 = 1_700_000_000;
    let _clock = crate::time::FixedClock::set(START);
    let mut harness = open()?;
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    let entry = own_dummy(&harness.account);
    drive(&mut harness.account, entry, || 1).await?;
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("held".into()), 1)
    );
    let pre = harness
        .account
        .client
        .account_db()?
        .receive_ledger_snap_for_test(&harness.account.target_delivery_id)?;
    let prepared = turn(&harness.account, 1)?;
    source_failure::set_fault(source_failure::Fault::BeforeCommit);
    crate::time::FixedClock::advance_to(START + 604_800);
    let gate = SourceFailure { expected: prepared.expected(), generation: 1 };
    let cut = gate.expire_holds(harness.account.client.account_db()?, START + 604_800);
    source_failure::set_fault(source_failure::Fault::None);
    let error = cut.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(text)))
                if *text == "source failure before-commit"
        ),
        "expiry cut: {error:?}"
    );
    assert_eq!(
        harness
            .account
            .client
            .account_db()?
            .receive_ledger_snap_for_test(&harness.account.target_delivery_id)?,
        pre,
        "expiry cut writes nothing"
    );
    reopen(&mut harness.account)?;
    let prepared = turn(&harness.account, 1)?;
    let gate = SourceFailure { expected: prepared.expected(), generation: 1 };
    let settled = gate.expire_holds(harness.account.client.account_db()?, START + 604_800)?;
    assert_eq!(settled, vec![1]);
    let done = harness
        .account
        .client
        .account_db()?
        .receive_ledger_snap_for_test(&harness.account.target_delivery_id)?;
    assert_eq!(done.work, 0, "expired hold is gone");
    assert_eq!(done.intents, vec![1]);
    assert_eq!(done.cursor, 1);
    Ok(())
}

fn erase_pending(db: &AccountDb) {
    erase_through_retention(db).expect("erase");
}

fn arm_w1_cut(_db: &AccountDb) {
    set_before_commit("apply page w1 before-commit");
}

#[tokio::test(flavor = "current_thread")]
async fn erase_while_w1_pending_is_object_erased() -> Result<(), SdkError> {
    let mut harness = open()?;
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    set_after_classify(erase_pending);
    let entry = own_dummy(&harness.account);
    let refused = drive(&mut harness.account, entry, || 1).await;
    let error = refused.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::ObjectErased)),
        "erase while W1 is pending must be ObjectErased: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1),
        "W0 stays after the refused W1"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn manifest_wait_refuses_stale_generation() -> Result<(), SdkError> {
    let mut harness = open()?;
    let before = harness.account.client.account_db()?.durable_rows_for_test()?;
    GENERATION.with(|cell| cell.set(1));
    queue_manifest_wait();
    set_manifest_await(bump_generation);
    let entry = own_dummy(&harness.account);
    let refused = drive(&mut harness.account, entry, current_generation).await;
    let error = refused.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::Storage(StorageError::AuthorizationRejected))),
        "manifest wait generation bump must refuse W1: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1),
        "W0 committed before the manifest wait"
    );
    assert_eq!(cursor(&harness.account)?, 0);
    assert_eq!(unrouted_journals(harness.account.client.account_db()?)?, 0);
    let _ = before;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn w1_before_commit_sweep_keeps_w0() -> Result<(), SdkError> {
    let mut harness = open()?;
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    set_after_classify(arm_w1_cut);
    let entry = own_dummy(&harness.account);
    let cut = drive(&mut harness.account, entry, || 1).await;
    let error = cut.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(text)))
                if *text == "apply page w1 before-commit"
        ),
        "W1 kill before COMMIT: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    reopen(&mut harness.account)?;
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    let recovered = drive_disk(&mut harness.account, 1, || 1).await?;
    assert!(recovered.0.is_none());
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("held".into()), 1)
    );
    assert_eq!(cursor(&harness.account)?, 1);
    assert_eq!(unrouted_journals(harness.account.client.account_db()?)?, 1);
    Ok(())
}

fn persist_projection_receipt_at(
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
        erasure_targets: Vec::new(),
    };
    account.client.account_db()?.persist_actor_state(key, &receipt)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn admit_open_need_point_is_integrity() -> Result<(), SdkError> {
    let mut harness = open()?;
    force_need_point();
    let entry = live_dummy(&harness.account);
    let error = drive(&mut harness.account, entry, || 1).await.err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(text)))
                if text == "receive admission cannot fetch a point from reconcile"
        ),
        "admit_open NeedPoint is a typed refusal: {error:?}"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_sdk_page(
    account: &crate::bus::state::LocalBusAccountState,
    cursor: u64,
    after: u64,
    covered: u64,
    issued: u64,
    entries: &[u64],
    losses: &[ApplyLoss<'_>],
) -> Result<ApplyOutcome, SdkError> {
    let db = account.client.account_db()?;
    let mut prepared = turn(account, 1)?;
    prepared.cursor = cursor;
    let page = ApplyPage {
        target: &prepared.target,
        incarnation: &prepared.incarnation,
        after,
        covered,
        issued,
        settled: 0,
        entries,
        known_losses: losses,
        oversize_next: None,
        more: covered < issued,
    };
    match apply::apply_page(db, prepared.expected(), 1, page) {
        Ok(outcome) => Ok(outcome),
        Err(apply::ApplyError::Protocol(text)) => Err(SdkError::InboundRejected(text.into())),
        Err(apply::ApplyError::Storage(error)) => Err(error.into()),
    }
}

fn stage_seq(
    account: &crate::bus::state::LocalBusAccountState,
    cursor: u64,
    sequence: u64,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let mut prepared = turn(account, 1)?;
    prepared.cursor = cursor;
    let entry = dummy_seq(
        &account.target_delivery_id,
        &encode_base64url(b"legacy-a2i-dummy"),
        "source",
        "device",
        sequence,
    );
    let bytes = serde_json::to_vec(&entry.entry)?;
    let result = db.receive_transaction(prepared.expected(), 1, |tx| {
        tx.stage(ReceiveStage {
            target: &prepared.target,
            incarnation: &prepared.incarnation,
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

#[tokio::test(flavor = "current_thread")]
async fn stale_page_suffix_progress() -> Result<(), SdkError> {
    let harness = open()?;
    let prefix = [ApplyLoss { from_seq: 1, to_seq: 10, reason: "expired" }];
    assert_eq!(
        apply_sdk_page(&harness.account, 0, 0, 10, 20, &[], &prefix)?,
        ApplyOutcome::Covered { cursor: 10 }
    );
    stage_seq(&harness.account, 10, 12)?;
    let losses = [
        ApplyLoss { from_seq: 6, to_seq: 11, reason: "expired" },
        ApplyLoss { from_seq: 13, to_seq: 20, reason: "nacked" },
    ];
    assert_eq!(
        apply_sdk_page(&harness.account, 10, 5, 20, 20, &[12], &losses)?,
        ApplyOutcome::NeedStage { sequence: 12, cursor: 11 }
    );
    let db = harness.account.client.account_db()?;
    db.set_receipt_disposition_for_test(12, "completed")?;
    assert_eq!(
        apply_sdk_page(&harness.account, 11, 5, 20, 20, &[12], &losses)?,
        ApplyOutcome::Covered { cursor: 20 }
    );
    let once = db.receive_ledger_snap_for_test(&harness.account.target_delivery_id)?;
    assert_eq!(once.cursor, 20);
    assert_eq!(
        apply_sdk_page(&harness.account, 20, 5, 20, 20, &[12], &losses)?,
        ApplyOutcome::AlreadyCovered { cursor: 20 }
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn projection_w1_admits_outbox() -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = live_dummy(&harness.account);
    let key = "authenticated-projection-key".to_owned();
    persist_projection_receipt_at(&harness.account, &entry.entry, &key)?;
    set_projection_key(&key);
    queue_projection();
    drive(&mut harness.account, entry, || 1).await?;
    let stored: Option<ApplicationEvent> =
        harness.account.client.account_db()?.load_actor_state(&format!("{OUTBOX}{key}"))?;
    assert!(stored.is_some(), "projection W1 writes the application outbox");
    assert_eq!(cursor(&harness.account)?, 1, "projection W1 terminal cover advances C");
    let snap = harness
        .account
        .client
        .account_db()?
        .receive_ledger_snap_for_test(&harness.account.target_delivery_id)?;
    assert_eq!(snap.intents, vec![1], "terminal cover writes the ACK intent");
    assert!(snap.receipts.is_empty(), "terminal cover binds and cleans the receipt");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn compat_intent_transition() -> Result<(), SdkError> {
    let mut harness = open()?;
    let mut engine = crate::gateway::GatewaySessionEngine::with_test_transport(
        harness.account.gateway_config.clone(),
        Box::new(CountSends { sends: Arc::new(AtomicUsize::new(0)) }),
    );
    engine.mode = crate::gateway::session_push::SessionMode::Legacy;
    harness.account.engine = Some(engine);
    let entry = live_dummy(&harness.account);
    let key = "authenticated-projection-key".to_owned();
    persist_projection_receipt_at(&harness.account, &entry.entry, &key)?;
    set_projection_key(&key);
    queue_projection();
    drive(&mut harness.account, entry, || 1).await?;
    let snap = harness
        .account
        .client
        .account_db()?
        .receive_ledger_snap_for_test(&harness.account.target_delivery_id)?;
    assert_eq!(snap.cursor, 1, "compat W2 advances C");
    assert_eq!(snap.intents, vec![1], "compat W2 writes the ACK intent");
    assert_eq!(snap.work, 1, "CompatTerminal keeps the registered proof copy");
    assert_eq!(
        snap.receipts,
        vec![(1, "completed".into())],
        "CompatTerminal staged-without-work keeps the completed receipt"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn projection_w1_before_commit_keeps_w0() -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = live_dummy(&harness.account);
    let key = "authenticated-projection-key";
    persist_projection_receipt_at(&harness.account, &entry.entry, key)?;
    set_projection_key(key);
    queue_projection();
    set_after_classify(arm_w1_cut);
    let cut = drive(&mut harness.account, entry, || 1).await;
    let error = cut.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(text)))
                if *text == "apply page w1 before-commit"
        ),
        "projection W1 kill: {error:?}"
    );
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn settle_terminal_prunes_reply_marker() -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = live_dummy(&harness.account);
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    harness
        .account
        .client
        .account_db()?
        .persist_actor_state(&format!("{MARKER}{key}"), &json!({"id": "marker"}))?;
    queue_terminal_reply();
    drive(&mut harness.account, entry, || 1).await?;
    let marker: Option<serde_json::Value> =
        harness.account.client.account_db()?.load_actor_state(&format!("{MARKER}{key}"))?;
    assert!(marker.is_none(), "W0 terminal prunes the reply transfer marker");
    assert_eq!(cursor(&harness.account)?, 1);
    assert_eq!(harness.account.client.account_db()?.receive_state_for_test(1)?, (None, 0));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn projection_refuses_unverified_key() -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = live_dummy(&harness.account);
    // A receipt exists at the unverified-hash key; it must still never be projected.
    let unverified = harness.account.client.inbox_admission_key(&entry.entry)?;
    assert!(unverified.starts_with("inbox/unverified/"));
    persist_projection_receipt_at(&harness.account, &entry.entry, &unverified)?;
    queue_projection();
    let refused = drive(&mut harness.account, entry, || 1).await;
    assert!(refused.is_err(), "unauthenticated entry must not project");
    let stored: Option<ApplicationEvent> =
        harness.account.client.account_db()?.load_actor_state(&format!("{OUTBOX}{unverified}"))?;
    assert!(stored.is_none(), "no outbox row under an unverified key");
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn own_copy_success_without_authenticated_identity_commits_w1() -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = live_dummy(&harness.account);
    let identity = harness.account.client.authenticated_committed_key(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &entry.entry,
    );
    assert!(
        identity.is_err(),
        "fixture must lack a root-qualified authenticated identity: {identity:?}"
    );
    queue_own_copy();
    drive(&mut harness.account, entry.clone(), || 1).await?;
    let locator: Option<serde_json::Value> =
        harness.account.client.account_db()?.load_actor_state(
            &crate::client::own_device_copy::w1::locator_key(&entry.entry.envelope.envelope_id),
        )?;
    assert!(locator.is_some(), "own-copy W1 commits; missing identity is nothing owed");
    assert_eq!(cursor(&harness.account)?, 1, "own-copy terminal cover advances C");
    let snap = harness
        .account
        .client
        .account_db()?
        .receive_ledger_snap_for_test(&harness.account.target_delivery_id)?;
    assert_eq!(snap.intents, vec![1]);
    Ok(())
}

fn marker_present(
    account: &crate::bus::state::LocalBusAccountState,
    key: &str,
) -> Result<bool, SdkError> {
    Ok(account
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&format!("{MARKER}{key}"))?
        .is_some())
}

fn seed_marker(
    account: &crate::bus::state::LocalBusAccountState,
    key: &str,
) -> Result<(), SdkError> {
    account
        .client
        .account_db()?
        .persist_actor_state(&format!("{MARKER}{key}"), &json!({"id": "marker"}))?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn deterministic_reject_prunes_reply_marker() -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = retryable_entry(&harness.account);
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    seed_marker(&harness.account, &key)?;
    queue_policy_kind(ReceiveFailureKind::Retryable);
    drive(&mut harness.account, entry.clone(), || 1).await?;
    assert!(marker_present(&harness.account, &key)?, "a held retry keeps the marker");
    let mut harness = open()?;
    let entry = retryable_entry(&harness.account);
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    seed_marker(&harness.account, &key)?;
    queue_policy_kind(ReceiveFailureKind::Deterministic);
    drive(&mut harness.account, entry, || 1).await?;
    assert!(!marker_present(&harness.account, &key)?, "rejected W0 prunes the marker");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn hold_expiry_prunes_reply_marker() -> Result<(), SdkError> {
    const START: i64 = 1_700_000_000;
    let _clock = crate::time::FixedClock::set(START);
    let mut harness = open()?;
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    let entry = own_dummy(&harness.account);
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    drive(&mut harness.account, entry, || 1).await?;
    seed_marker(&harness.account, &key)?;
    crate::time::FixedClock::advance_to(START + 604_800);
    let plan = crate::bus::sync_driver::prepare_receive(&harness.account, 1)?;
    assert!(plan.turn.is_some());
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (None, 0),
        "expired hold settled"
    );
    assert!(!marker_present(&harness.account, &key)?, "expiry prunes the marker");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn settle_retained_prunes_reply_marker() -> Result<(), SdkError> {
    let mut harness = open()?;
    queue_legacy_hold(std::iter::repeat_n(true, 8));
    let entry = own_dummy(&harness.account);
    let key = harness.account.client.inbox_admission_key(&entry.entry)?;
    drive(&mut harness.account, entry, || 1).await?;
    seed_marker(&harness.account, &key)?;
    let prepared = turn(&harness.account, 1)?;
    crate::bus::account_runtime::settle_retained(&mut harness.account, 1, &prepared, 1)?;
    assert!(!marker_present(&harness.account, &key)?, "retained terminal settle prunes");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn non_ledger_expiry_still_runs_on_activated_accounts() -> Result<(), SdkError> {
    const START: i64 = 1_700_000_000;
    let _clock = crate::time::FixedClock::set(START);
    let harness = open()?;
    let db = harness.account.client.account_db()?;
    // An unrouted row older than the 7-day trim has no ledger work: only the non-ledger
    // part of expire_inbox_holds can remove it.
    db.hold_unrouted("stale-key", 7, b"{}", START - 8 * 24 * 60 * 60)?;
    assert!(db.unrouted_count()? > 0);
    crate::bus::sync_driver::prepare_receive(&harness.account, 1)?;
    assert_eq!(
        harness.account.client.account_db()?.unrouted_count()?,
        0,
        "activated prepare_receive still trims expired unrouted rows"
    );
    Ok(())
}

#[test]
fn epoch_only_is_not_active() -> Result<(), SdkError> {
    let root = tempfile::tempdir().expect("tmp");
    let account =
        runtime_tests::account(root.path(), "acct", None, Arc::new(AtomicBool::new(false)))?;
    let target = account.target_delivery_id.clone();
    let db = account.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test(&target, "e")?;
    assert!(
        !apply_w1::is_active(db, &target)?,
        "epoch-only seed is not the activation discriminator"
    );
    Ok(())
}

#[test]
fn activated_without_epoch_is_integrity() -> Result<(), SdkError> {
    let root = tempfile::tempdir().expect("tmp");
    let account =
        runtime_tests::account(root.path(), "acct", None, Arc::new(AtomicBool::new(false)))?;
    let target = account.target_delivery_id.clone();
    let db = account.client.account_db()?;
    db.set_projection_checkpoint("gateway_receive_activation", "activated")?;
    match apply_w1::is_active(db, &target) {
        Err(SdkError::Storage(StorageError::Integrity(MISSING_EPOCH))) => {}
        other => panic!("Activated without epoch must be MISSING_EPOCH, got {other:?}"),
    }
    Ok(())
}

fn snap(
    account: &crate::bus::state::LocalBusAccountState,
) -> Result<ramflux_storage::ReceiveLedgerSnap, SdkError> {
    Ok(account.client.account_db()?.receive_ledger_snap_for_test(&account.target_delivery_id)?)
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_cover_cut_rolls_w1_with_receipt() -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = live_dummy(&harness.account);
    queue_own_copy();
    set_after_w1_cut(after_w1_cut());
    let cut = drive(&mut harness.account, entry.clone(), || 1).await;
    let error = cut.as_ref().err();
    assert!(
        matches!(
            error,
            Some(SdkError::Storage(StorageError::Integrity(text))) if *text == after_w1_cut()
        ),
        "W1/cover cut: {error:?}"
    );
    let locator: Option<serde_json::Value> =
        harness.account.client.account_db()?.load_actor_state(
            &crate::client::own_device_copy::w1::locator_key(&entry.entry.envelope.envelope_id),
        )?;
    assert!(locator.is_none(), "W1 rolls back with the cover");
    assert_eq!(cursor(&harness.account)?, 0);
    assert_eq!(snap(&harness.account)?.intents, Vec::<u64>::new());
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("staged".into()), 1)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn second_connected_no_redelivery() -> Result<(), SdkError> {
    let mut harness = open()?;
    let entry = live_dummy(&harness.account);
    queue_own_copy();
    drive(&mut harness.account, entry.clone(), || 1).await?;
    assert_eq!(cursor(&harness.account)?, 1);
    assert_eq!(snap(&harness.account)?.intents, vec![1]);
    queue_own_copy();
    drive(&mut harness.account, entry, || 1).await?;
    assert_eq!(cursor(&harness.account)?, 1, "second apply does not move C");
    assert_eq!(snap(&harness.account)?.intents, vec![1], "second apply writes no new intent");
    Ok(())
}

#[test]
fn inactive_account_skips_w2_and_ack_flush() -> Result<(), SdkError> {
    let root = tempfile::tempdir().expect("tmp");
    let account =
        runtime_tests::account(root.path(), "acct", None, Arc::new(AtomicBool::new(false)))?;
    let target = account.target_delivery_id.clone();
    let db = account.client.account_db()?;
    assert!(!apply_w1::is_active(db, &target)?, "inactive discriminator skips the ledger route");
    assert!(db.receive_epoch(&target)?.is_none());
    assert!(db.projection_checkpoint(&format!("gateway_receive_cursor:{target}"))?.is_none());
    let reply = crate::bus::apply_ack_flush(&account, 1, true, now_unix_timestamp(), None, None)?;
    assert!(
        matches!(reply, crate::bus::connection_manager::AckFlushReply::Inactive),
        "inactive AckFlush must return Inactive, got {reply:?}"
    );
    Ok(())
}
