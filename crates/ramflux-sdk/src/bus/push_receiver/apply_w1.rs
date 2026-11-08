// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant `ApplyPage` → W1 adapters. Unactivated accounts (no epoch row) stay on the live path.
#![allow(dead_code)]

use super::apply::cover_held_in;
use crate::bus::account_runtime::lifecycle_fence;
use crate::bus::connection_manager::{ReceiveApplied, ReceiveEntry, ReceiveTurn};
use crate::bus::state::LocalBusAccountState;
use crate::bus::sync_driver::source::PreparedSource;
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, ProjectionStore, ReceiveCoverResult, ReceiveExpectation, ReceiveTransaction,
    StorageError,
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
    let mut attempts = 0;
    loop {
        match Box::pin(apply_once(account, turn, handle_generation, &prepared, source.as_mut()))
            .await
        {
            Err(SdkError::LegacyBindingChanged) => note_binding_changed(&mut attempts)?,
            Err(SdkError::PairRecoveryRequired) => {
                recover_own_copy(account, turn, handle_generation(), &prepared.entry)?;
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
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: &ReceiveEntry,
    source: Option<&mut crate::client::routed::PreparedInbound>,
) -> Result<(), SdkError> {
    #[cfg(test)]
    cross_await().await;
    let entry = &prepared.entry;
    let sequence = entry.inbox_seq;
    let local_device = account.gateway_config.device_id.clone();
    let kind = classify(account, entry, source).await?;
    #[cfg(test)]
    after_classify();
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
                cover_if_held(tx, sequence, held)?;
                Ok(held)
            })?;
            Ok(())
        }
        Kind::LegacyHold => {
            let client = &account.client;
            run_fenced(client.account_db()?, handle_generation(), turn, |tx, expected| {
                client.apply_legacy_group_hold_w1_in(tx, entry, expected, handle_generation())?;
                cover_if_held(tx, sequence, true)?;
                Ok(true)
            })?;
            Ok(())
        }
    }
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
    if let Some(conversation) =
        account.client.legacy_routing_binding(&account.gateway_config.device_id, entry)?
    {
        return Ok(Kind::LegacyDm { conversation });
    }
    if account.client.legacy_a2i_is_unbound(&account.gateway_config.device_id, entry)?
        || account.client.load_legacy_a2i_receipt(entry)?.is_some()
    {
        return Ok(Kind::LegacyA2i);
    }
    Ok(Kind::LegacyHold)
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

fn cover_if_held(tx: &ReceiveTransaction<'_>, sequence: u64, held: bool) -> Result<(), SdkError> {
    if !held {
        return Ok(());
    }
    match cover_held_in(tx, sequence)? {
        ReceiveCoverResult::Covered | ReceiveCoverResult::Paused => Ok(()),
    }
}

fn note_binding_changed(attempts: &mut u32) -> Result<(), SdkError> {
    *attempts += 1;
    if *attempts >= BINDING_ATTEMPTS {
        Err(SdkError::InboundRejected(BINDING_GIVE_UP.into()))
    } else {
        Ok(())
    }
}

fn read_cursor(db: &AccountDb, target: &str) -> Result<u64, SdkError> {
    Ok(db
        .projection_checkpoint(&format!("gateway_receive_cursor:{target}"))?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?)
}

#[cfg(test)]
thread_local! {
    static CROSS_AWAIT: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
    static AFTER_CLASSIFY: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
async fn cross_await() {
    tokio::task::yield_now().await;
    if let Some(hook) = CROSS_AWAIT.with(std::cell::Cell::take) {
        hook();
    }
}

#[cfg(test)]
fn after_classify() {
    if let Some(hook) = AFTER_CLASSIFY.with(std::cell::Cell::take) {
        hook();
    }
}

#[cfg(test)]
pub(crate) fn set_cross_await(hook: fn()) {
    CROSS_AWAIT.with(|cell| cell.set(Some(hook)));
}

#[cfg(test)]
pub(crate) fn set_after_classify(hook: fn()) {
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
