// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `ApplyPage` fence, binding retry, and routed refusal (S6b P20f / P20c r2 CARRY).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use super::apply_w1::{self, apply_page, binding_give_up, routed_refused, set_cross_await};
use crate::bus::connection_manager::{ReceiveEntry, ReceiveTurn};
use crate::bus::contact_backpressure::Backpressure;
use crate::bus::runtime_tests;
use crate::client::a2i::queue_unbound_answers;
use crate::client::legacy_w1::{self, Fault};
use crate::prelude::*;
use ramflux_protocol::encode_base64url;
use ramflux_storage::StorageError;
use serde_json::json;
use std::cell::Cell;
use std::sync::{Arc, atomic::AtomicBool};

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
    let pressure = Box::new(Backpressure::load(&account.client, now_unix_timestamp())?);
    apply_page(account, &prepared_turn, &generation, prepared, None, pressure).await
}

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
