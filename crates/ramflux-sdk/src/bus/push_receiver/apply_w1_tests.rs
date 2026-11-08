// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `ApplyPage` fence, binding retry, and routed refusal (S6b P20c r2).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use super::apply_w1::{
    binding_give_up, commit_after_await, retry_binding_until, routed_refused, set_cross_await,
};
use crate::bus::connection_manager::ReceiveTurn;
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveStage, ReceiveTransaction, StorageError,
};
use serde_json::json;
use std::cell::Cell;

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

fn turn(db: &AccountDb, generation: u64) -> Result<ReceiveTurn, SdkError> {
    Ok(ReceiveTurn {
        target: "t".into(),
        incarnation: "e".into(),
        cursor: 0,
        generation,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn wire() -> Vec<u8> {
    serde_json::to_vec(&json!({"inbox_seq":1,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":"env-1","source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":"H1"
    }}))
    .unwrap()
}

fn stage(
    tx: &ReceiveTransaction<'_>,
    _expected: ramflux_storage::ReceiveExpectation<'_>,
) -> Result<bool, SdkError> {
    tx.stage(ReceiveStage {
        target: "t",
        incarnation: "e",
        sequence: 1,
        entry_json: &wire(),
        admission_key: "authenticated-key",
        retain_until: now_unix_timestamp() + 300,
        first_seen: 1,
    })
    .map_err(SdkError::from)?;
    Ok(false)
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

#[tokio::test(flavor = "current_thread")]
async fn apply_page_refuses_stale_generation_after_await() -> Result<(), SdkError> {
    let harness = open()?;
    let db = &harness.db;
    let prepared = turn(db, 1)?;
    let before = db.durable_rows_for_test()?;
    GENERATION.with(|cell| cell.set(1));
    set_cross_await(bump_generation);
    let refused = commit_after_await(db, &prepared, current_generation, stage).await;
    assert!(
        matches!(refused, Err(SdkError::Storage(StorageError::AuthorizationRejected))),
        "generation bump during the await must refuse: {refused:?}"
    );
    assert_eq!(
        db.durable_rows_for_test()?,
        before,
        "stale generation after the manifest await writes nothing"
    );
    Ok(())
}

#[test]
fn legacy_binding_changed_gives_up_after_three() {
    let mut calls = 0;
    let refused = retry_binding_until(|| {
        calls += 1;
        Err(SdkError::LegacyBindingChanged)
    });
    assert_eq!(calls, 3, "redrive is bounded at 3");
    assert!(
        matches!(&refused, Err(SdkError::InboundRejected(text)) if text == binding_give_up()),
        "give-up must be the typed error: {refused:?}"
    );
}

#[test]
fn active_routed_refuses_live_apply() {
    let error = SdkError::InboundRejected(routed_refused().into());
    assert!(
        matches!(&error, SdkError::InboundRejected(text) if text == routed_refused()),
        "{error}"
    );
}
