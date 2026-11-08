// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `ApplyPage` fence, binding retry, and routed refusal (S6b P20f / P20c r2 CARRY).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use super::apply_w1::{
    self, apply_page, binding_give_up, routed_refused, set_after_classify, set_cross_await,
};
use crate::bus::connection_manager::{ReceiveEntry, ReceiveTurn};
use crate::bus::contact_backpressure::Backpressure;
use crate::bus::runtime_tests;
use crate::client::a2i::queue_unbound_answers;
use crate::client::legacy_w1::{self, Fault};
use crate::prelude::*;
use ramflux_protocol::encode_base64url;
use ramflux_storage::{AccountDb, StorageError};
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
    let db = account.client.account_db()?;
    apply_w1::capture_turn(db, generation, &account.target_delivery_id)
}

fn envelope(target: &str, payload: &str, principal: &str, device: &str) -> serde_json::Value {
    json!({
        "inbox_seq": 1,
        "target_delivery_id": target,
        "envelope": {
            "schema": "test",
            "version": 1,
            "domain": "test",
            "signing_key_id": "key",
            "signature_alg": "ed25519",
            "signature": "sig",
            "envelope_id": "env-1",
            "source_principal_id": principal,
            "source_device_id": device,
            "target_delivery_id": target,
            "delivery_class": "opaque_event",
            "priority": "normal",
            "ttl": 60,
            "created_at": 1,
            "encrypted_payload": payload,
            "payload_hash": "H1"
        }
    })
}

fn prepared(target: &str, payload: &str) -> ReceiveEntry {
    ReceiveEntry {
        entry: serde_json::from_value(envelope(target, payload, "source", "device"))
            .expect("entry"),
        retry_key: None,
        replay: false,
        turn: None,
    }
}

fn prepared_from(target: &str, payload: &str, principal: &str, device: &str) -> ReceiveEntry {
    ReceiveEntry {
        entry: serde_json::from_value(envelope(target, payload, principal, device)).expect("entry"),
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
    prepared_from(
        &account.target_delivery_id,
        &encode_base64url(b"legacy-a2i-dummy"),
        &account.gateway_config.principal_id,
        &account.gateway_config.device_id,
    )
}

fn reopen(account: &mut crate::bus::state::LocalBusAccountState) -> Result<(), SdkError> {
    account.client.active_account_db = None;
    account.client.unlock_account("acct", b"actor-test-secret")?;
    Ok(())
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
async fn legacy_binding_changed_gives_up_after_three() -> Result<(), SdkError> {
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
        matches!(error, Some(SdkError::InboundRejected(text)) if text == binding_give_up()),
        "give-up must be the typed error through apply_page: {error:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn active_routed_refuses_live_apply() -> Result<(), SdkError> {
    let mut harness = open()?;
    let target = harness.account.target_delivery_id.clone();
    let refused = drive(&mut harness.account, prepared(&target, &routed_payload()), || 1).await;
    let error = refused.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::InboundRejected(text)) if text == routed_refused()),
        "active routed must refuse through apply_page: {error:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn staging_survives_router_expiry() -> Result<(), SdkError> {
    const START: i64 = 1_700_000_000;
    let _clock = crate::time::FixedClock::set(START);
    let mut harness = open()?;
    let sends = attach_counter(&mut harness.account);
    queue_unbound_answers(std::iter::repeat_n(false, 8));
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
    let recovered = drive(&mut harness.account, entry, || 1).await?;
    assert!(recovered.0.is_none(), "recovery writes no ACK intent");
    assert_eq!(
        harness.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("held".into()), 1),
        "one held effect after expiry"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 0);

    let mut missing = open()?;
    let sends = attach_counter(&mut missing.account);
    queue_unbound_answers(std::iter::repeat_n(false, 8));
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
    queue_unbound_answers(std::iter::repeat_n(false, 8));
    legacy_w1::set_fault(Fault::BeforeCommit);
    let entry = own_dummy(&harness.account);
    let cut = drive(&mut harness.account, entry.clone(), || 1).await;
    legacy_w1::set_fault(Fault::None);
    let error = cut.as_ref().err();
    assert!(
        matches!(error, Some(SdkError::Storage(StorageError::Integrity(text))) if *text == BEFORE),
        "{error:?}"
    );
    let once = drive(&mut harness.account, entry.clone(), || 1).await?;
    assert!(once.0.is_none(), "W1 writes no ACK intent");
    let held = harness.account.client.account_db()?.receive_state_for_test(1)?;
    assert_eq!(held, (Some("held".into()), 1), "one held effect");
    reopen(&mut harness.account)?;
    assert_eq!(harness.account.client.account_db()?.receive_state_for_test(1)?, held);
    let again = drive(&mut harness.account, entry, || 1).await?;
    assert!(again.0.is_none());
    assert_eq!(harness.account.client.account_db()?.receive_state_for_test(1)?, held);
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn held_admission_stage_crash() -> Result<(), SdkError> {
    let mut blocked = open()?;
    let sends = attach_counter(&mut blocked.account);
    queue_unbound_answers(std::iter::repeat_n(false, 8));
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
    let held = drive(&mut blocked.account, entry, || 1).await?;
    assert!(held.0.is_none());
    assert_eq!(
        blocked.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("held".into()), 1)
    );
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
    let held = drive(&mut unbound.account, entry, || 1).await?;
    assert!(held.0.is_none());
    assert_eq!(
        unbound.account.client.account_db()?.receive_state_for_test(1)?,
        (Some("held".into()), 1)
    );
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn erasure_late_stage_and_process() -> Result<(), SdkError> {
    let mut harness = open()?;
    let sends = attach_counter(&mut harness.account);
    let prepared_turn = turn(&harness.account, 1)?;
    let before = harness.account.client.account_db()?.durable_rows_for_test()?;
    harness.account.client.account_db()?.advance_erasure_generation_for_test()?;
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
