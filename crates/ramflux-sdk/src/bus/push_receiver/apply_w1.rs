// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant `ApplyPage` → W1 adapters. Unactivated accounts (no epoch row) stay on the live path.
#![allow(dead_code)]

use super::apply::{self, ApplyOutcome, cover_held_in};
use crate::bus::account_runtime::lifecycle_fence;
use crate::bus::connection_manager::{ReceiveApplied, ReceiveEntry, ReceiveTurn};
use crate::bus::state::LocalBusAccountState;
use crate::bus::sync_driver::source::PreparedSource;
use crate::bus::sync_driver::source::hold::{HoldDisposition, SourceHold};
use crate::client::legacy_w1::LegacyW1;
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, ProjectionStore, ReceiveCoverResult, ReceiveExpectation, ReceiveGap, ReceiveStage,
    ReceiveStageResult, ReceiveTransaction, StorageError,
};

/// Bounded redrive of `LegacyBindingChanged` before a typed give-up.
const BINDING_ATTEMPTS: u32 = 3;
const BINDING_GIVE_UP: &str = "legacy binding changed after 3 attempts";
const ROUTED_REFUSED: &str = "receive ledger refuses live routed apply";

/// True when `target` has a receive-epoch row. Missing table or row is the live unactivated path.
pub(crate) fn is_active(db: &AccountDb, target: &str) -> Result<bool, SdkError> {
    Ok(db.receive_epoch(target)?.is_some())
}

/// Prepare-time coordinates for one `ApplyPage`: message generation plus DB cursor/E/erase.
pub(crate) fn capture_turn(
    db: &AccountDb,
    generation: u64,
    target: &str,
) -> Result<ReceiveTurn, SdkError> {
    let incarnation = db.receive_epoch(target)?.unwrap_or_default();
    Ok(ReceiveTurn {
        target: target.to_owned(),
        incarnation,
        cursor: read_cursor(db, target)?,
        generation,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

/// W1 + held W2 for one `ApplyPage` entry. No ACK intent (WA is P21).
///
/// `turn` is the prepare-time expectation. `handle_generation` is read at each commit
/// (after any await) from S2/handle state.
pub(crate) async fn apply_page(
    account: &mut LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: ReceiveEntry,
    source: PreparedSource,
    backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
) -> Result<ReceiveApplied, SdkError> {
    let mut source = source.map(|prepared| *prepared).transpose()?;
    let mut turn = turn.clone();
    refresh_cursor(account.client.account_db()?, &mut turn)?;
    let mut attempts = 0;
    #[cfg(test)]
    BINDING_TRIES.with(|cell| cell.set(0));
    loop {
        match Box::pin(apply_once(
            account,
            &mut turn,
            handle_generation,
            &prepared,
            source.as_mut(),
        ))
        .await
        {
            Err(SdkError::LegacyBindingChanged) => note_binding_changed(&mut attempts)?,
            Err(SdkError::PairRecoveryRequired) => {
                recover_own_copy(account, &turn, handle_generation(), &prepared.entry)?;
                break;
            }
            Err(error) => return Err(error),
            Ok(()) => break,
        }
    }
    Ok((None, backpressure))
}

async fn apply_once(
    account: &mut LocalBusAccountState,
    turn: &mut ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: &ReceiveEntry,
    source: Option<&mut crate::client::routed::PreparedInbound>,
) -> Result<(), SdkError> {
    #[cfg(test)]
    cross_await().await;
    let entry = &prepared.entry;
    let sequence = entry.inbox_seq;
    if !admit_open(account, turn, handle_generation(), prepared)? {
        return Ok(());
    }
    let local_device = account.gateway_config.device_id.clone();
    let kind = classify(account, entry, source).await?;
    #[cfg(test)]
    after_classify(account.client.account_db()?);
    match kind {
        Kind::Routed => Err(SdkError::InboundRejected(ROUTED_REFUSED.into())),
        Kind::OwnCopy(manifest) => {
            let message = entry.envelope.envelope_id.clone();
            let client = &account.client;
            run_fenced(client.account_db()?, handle_generation(), turn, |tx, expected| {
                client.apply_own_copy_w1_in(tx, entry, &manifest, expected, sequence, &message)?;
                Ok(false)
            })?;
            Ok(())
        }
        Kind::LegacyDm { conversation } => {
            let client = &account.client;
            run_fenced(client.account_db()?, handle_generation(), turn, |tx, expected| {
                client.apply_legacy_success_w1_in(
                    tx,
                    entry,
                    &local_device,
                    &conversation,
                    expected,
                    handle_generation(),
                )?;
                Ok(false)
            })?;
            Ok(())
        }
        Kind::LegacyA2i => {
            let client = &account.client;
            run_fenced(client.account_db()?, handle_generation(), turn, |tx, expected| {
                let held = client.apply_legacy_a2i_w1_in(
                    tx,
                    entry,
                    &local_device,
                    expected,
                    handle_generation(),
                )?;
                cover_if_held(tx, sequence, held, &[])?;
                Ok(held)
            })?;
            Ok(())
        }
        Kind::LegacyHold => hold_unrouted(account, turn, handle_generation, entry, sequence),
    }
}

fn hold_unrouted(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    entry: &GatewayInboxEntry,
    sequence: u64,
) -> Result<(), SdkError> {
    let key = account.client.inbox_admission_key(entry)?;
    let at = now_unix_timestamp();
    run_fenced(account.client.account_db()?, handle_generation(), turn, |tx, expected| {
        let generation = handle_generation();
        let gate = LegacyW1 { expected, generation };
        let hold = SourceHold { expected, generation };
        match gate.effect_in(tx, sequence, None, || hold.unrouted_in(tx, entry, &key, at))? {
            HoldDisposition::HeldLocal { .. } => {
                // SourceHold.admit_hold settle(Held) already covers C+1 in this
                // transaction (P07). A second Held cover refuses "outside page"
                // and rolls the hold, journal and cover back together.
                Ok(true)
            }
            HoldDisposition::Paused => Ok(false),
        }
    })?;
    Ok(())
}

enum Kind {
    OwnCopy(Box<crate::SdkDeviceManifestResponse>),
    Routed,
    LegacyDm { conversation: String },
    LegacyA2i,
    LegacyHold,
}

async fn classify(
    account: &LocalBusAccountState,
    entry: &GatewayInboxEntry,
    source: Option<&mut crate::client::routed::PreparedInbound>,
) -> Result<Kind, SdkError> {
    if let Some(manifest) = source.and_then(|prepared| prepared.own_copy_manifest.take()) {
        return Ok(Kind::OwnCopy(Box::new(manifest)));
    }
    if let Some(root) = account.client.own_device_receive_manifest_request(entry)? {
        #[cfg(test)]
        cross_await().await;
        let manifest = account
            .client
            .cache_verified_device_manifest(
                &account.gateway_config,
                &root,
                "own_device_message_receive",
            )
            .await?;
        return Ok(Kind::OwnCopy(Box::new(manifest)));
    }
    if crate::client::routed::decode(&entry.envelope).is_ok() {
        return Ok(Kind::Routed);
    }
    let reference = account.client.inbound_device_reference(entry)?;
    if account.client.v2_blocks_legacy(&reference)? {
        return Ok(Kind::LegacyHold);
    }
    #[cfg(test)]
    if take_legacy_hold() {
        return Ok(Kind::LegacyHold);
    }
    if let Some(conversation) =
        account.client.legacy_routing_binding(&account.gateway_config.device_id, entry)?
    {
        return Ok(Kind::LegacyDm { conversation });
    }
    if account.client.legacy_a2i_is_unbound(&account.gateway_config.device_id, entry)? {
        return Ok(Kind::LegacyA2i);
    }
    match account.client.load_legacy_a2i_receipt(entry) {
        Ok(Some(_)) => return Ok(Kind::LegacyA2i),
        Ok(None) => {}
        Err(error) => return Err(error),
    }
    Ok(Kind::LegacyHold)
}

/// Reconcile the single-entry page. `NeedStage` writes W0 using the cursor returned
/// after any gap-prefix cover. Already-covered sequences skip W1.
fn admit_open(
    account: &LocalBusAccountState,
    turn: &mut ReceiveTurn,
    generation: u64,
    prepared: &ReceiveEntry,
) -> Result<bool, SdkError> {
    let sequence = prepared.entry.inbox_seq;
    match reconcile_entry(account.client.account_db()?, turn, generation, sequence)? {
        ApplyOutcome::NeedStage { sequence: need, cursor } if need == sequence => {
            turn.cursor = cursor;
            stage_open(account, turn, generation, prepared)
        }
        ApplyOutcome::NeedStage { .. } => {
            Err(SdkError::InboundRejected("receive page need-stage mismatch".into()))
        }
        ApplyOutcome::Covered { .. }
        | ApplyOutcome::AlreadyCovered { .. }
        | ApplyOutcome::NeedFetch { .. }
        | ApplyOutcome::NeedPoint { .. }
        | ApplyOutcome::Paused { .. } => Ok(false),
    }
}

fn stage_open(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    generation: u64,
    prepared: &ReceiveEntry,
) -> Result<bool, SdkError> {
    let json = serde_json::to_vec(&prepared.entry)?;
    let key = account.client.inbox_admission_key(&prepared.entry)?;
    let retain_until = now_unix_timestamp() + 300;
    let first_seen = now_unix_timestamp();
    run_fenced(account.client.account_db()?, generation, turn, |tx, expected| {
        match tx.stage(ReceiveStage {
            target: expected.target,
            incarnation: expected.incarnation,
            sequence: prepared.entry.inbox_seq,
            entry_json: &json,
            admission_key: &key,
            retain_until,
            first_seen,
        })? {
            ReceiveStageResult::Staged | ReceiveStageResult::Existing => Ok(true),
            ReceiveStageResult::Erased => Ok(false),
            ReceiveStageResult::Conflict { .. } => {
                Err(SdkError::InboundRejected("receive stage conflict".into()))
            }
            ReceiveStageResult::PausedWork
            | ReceiveStageResult::PausedBytes
            | ReceiveStageResult::PausedIntents => {
                Err(SdkError::InboundRejected("receive stage paused".into()))
            }
        }
    })
}

fn recover_own_copy(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: u64,
    entry: &GatewayInboxEntry,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    run_fenced(db, handle_generation, turn, |tx, expected| {
        account.client.recover_own_copy_w1_in(
            tx,
            entry,
            expected,
            entry.inbox_seq,
            now_unix_timestamp(),
        )?;
        Ok(false)
    })?;
    Ok(())
}

fn run_fenced(
    db: &AccountDb,
    handle_generation: u64,
    turn: &ReceiveTurn,
    write: impl FnOnce(&ReceiveTransaction<'_>, ReceiveExpectation<'_>) -> Result<bool, SdkError>,
) -> Result<bool, SdkError> {
    let expected = turn.expected();
    let mut outcome = None;
    let fenced =
        lifecycle_fence::commit(db, handle_generation, expected, |tx| match write(tx, expected) {
            Ok(held) => {
                outcome = Some(Ok(held));
                Ok(())
            }
            Err(error) => {
                outcome = Some(Err(error));
                Err(StorageError::Integrity("apply page w1 failed"))
            }
        });
    match (fenced, outcome) {
        (_, Some(Err(error))) => Err(error),
        (Err(error), _) => Err(error.into()),
        (Ok(()), Some(Ok(held))) => Ok(held),
        (Ok(()), None) => Err(SdkError::LocalBus("apply page w1 did not run".into())),
    }
}

fn cover_if_held(
    tx: &ReceiveTransaction<'_>,
    sequence: u64,
    held: bool,
    gaps: &[ReceiveGap<'_>],
) -> Result<(), SdkError> {
    if !held {
        return Ok(());
    }
    match cover_held_in(tx, sequence, gaps)? {
        ReceiveCoverResult::Covered | ReceiveCoverResult::Paused => Ok(()),
    }
}

/// Validate/reconcile the single-entry page before W1. `NeedStage` is the live sequence
/// this adapter must process; any other outcome is already covered or not this entry.
fn reconcile_entry(
    db: &AccountDb,
    turn: &ReceiveTurn,
    generation: u64,
    sequence: u64,
) -> Result<ApplyOutcome, SdkError> {
    let entries = [sequence];
    let covered = sequence.max(turn.cursor);
    let page = apply::ApplyPage {
        target: &turn.target,
        incarnation: &turn.incarnation,
        after: turn.cursor,
        covered,
        issued: covered,
        settled: 0,
        entries: if sequence > turn.cursor { &entries } else { &[] },
        known_losses: &[],
        oversize_next: None,
        more: false,
    };
    match apply::apply_page(db, turn.expected(), generation, page) {
        Ok(outcome) => Ok(outcome),
        Err(apply::ApplyError::Protocol(text)) => Err(SdkError::InboundRejected(text.into())),
        Err(apply::ApplyError::Storage(error)) => Err(error.into()),
    }
}

fn note_binding_changed(attempts: &mut u32) -> Result<(), SdkError> {
    *attempts += 1;
    #[cfg(test)]
    BINDING_TRIES.with(|cell| cell.set(*attempts));
    if *attempts >= BINDING_ATTEMPTS {
        Err(SdkError::InboundRejected(BINDING_GIVE_UP.into()))
    } else {
        Ok(())
    }
}

/// Keep prepare-time E/erase/generation and reread C so a prior cover in this pass can commit.
pub(crate) fn refresh_cursor(db: &AccountDb, turn: &mut ReceiveTurn) -> Result<(), SdkError> {
    turn.cursor = read_cursor(db, &turn.target)?;
    Ok(())
}

fn read_cursor(db: &AccountDb, target: &str) -> Result<u64, SdkError> {
    Ok(db
        .projection_checkpoint(&format!("gateway_receive_cursor:{target}"))?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?)
}

#[cfg(test)]
thread_local! {
    static CROSS_AWAIT: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
    static AFTER_CLASSIFY: std::cell::Cell<Option<fn(&AccountDb)>> = const { std::cell::Cell::new(None) };
    static BINDING_TRIES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static LEGACY_HOLD: std::cell::RefCell<Vec<bool>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn take_legacy_hold() -> bool {
    LEGACY_HOLD.with(|queue| {
        let mut queue = queue.borrow_mut();
        if queue.is_empty() { false } else { queue.remove(0) }
    })
}

#[cfg(test)]
pub(crate) fn queue_legacy_hold(answers: impl IntoIterator<Item = bool>) {
    LEGACY_HOLD.with(|queue| {
        let mut queue = queue.borrow_mut();
        queue.clear();
        queue.extend(answers);
    });
}

#[cfg(test)]
pub(crate) fn binding_attempts() -> u32 {
    BINDING_TRIES.with(std::cell::Cell::get)
}

#[cfg(test)]
async fn cross_await() {
    tokio::task::yield_now().await;
    if let Some(hook) = CROSS_AWAIT.with(std::cell::Cell::take) {
        hook();
    }
}

#[cfg(test)]
fn after_classify(db: &AccountDb) {
    if let Some(hook) = AFTER_CLASSIFY.with(std::cell::Cell::take) {
        hook(db);
    }
}

#[cfg(test)]
pub(crate) fn set_cross_await(hook: fn()) {
    CROSS_AWAIT.with(|cell| cell.set(Some(hook)));
}

#[cfg(test)]
pub(crate) fn set_after_classify(hook: fn(&AccountDb)) {
    AFTER_CLASSIFY.with(|cell| cell.set(Some(hook)));
}

#[cfg(test)]
pub(crate) const fn binding_give_up() -> &'static str {
    BINDING_GIVE_UP
}

#[cfg(test)]
pub(crate) const fn routed_refused() -> &'static str {
    ROUTED_REFUSED
}

#[cfg(test)]
pub(crate) fn retry_binding_until(
    mut attempt: impl FnMut() -> Result<(), SdkError>,
) -> Result<(), SdkError> {
    let mut attempts = 0;
    loop {
        match attempt() {
            Err(SdkError::LegacyBindingChanged) => note_binding_changed(&mut attempts)?,
            other => return other,
        }
    }
}

/// Awaits once (the same yield the manifest fetch uses), then commits `write` under the fence.
#[cfg(test)]
pub(crate) async fn commit_after_await(
    db: &AccountDb,
    turn: &ReceiveTurn,
    handle_generation: impl Fn() -> u64,
    write: impl FnOnce(&ReceiveTransaction<'_>, ReceiveExpectation<'_>) -> Result<bool, SdkError>,
) -> Result<bool, SdkError> {
    cross_await().await;
    run_fenced(db, handle_generation(), turn, write)
}
