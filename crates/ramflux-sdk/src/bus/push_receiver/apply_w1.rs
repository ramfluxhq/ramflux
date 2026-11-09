// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant `ApplyPage` → W1 adapters. Inactive accounts stay on the live path.
#![allow(dead_code)]

use super::apply::{self, ApplyOutcome, cover_held_in};
use crate::bus::account_runtime::lifecycle_fence;
use crate::bus::connection_manager::{ReceiveApplied, ReceiveEntry, ReceiveTurn};
use crate::bus::state::LocalBusAccountState;
use crate::bus::sync_driver::source::PreparedSource;
use crate::bus::sync_driver::source::failure::SourceFailure;
use crate::bus::sync_driver::source::hold::{HoldDisposition, SourceHold};
use crate::client::application_outbox::{Admit, AdmitRequest, ApplicationOutbox};
use crate::client::inbox_failure::{deterministic, verified_failure_policy, wire_signature_error};
use crate::client::legacy_w1::LegacyW1;
use crate::client::reply_outbox::{MARKER, ReplyOutbox};
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, MISSING_EPOCH, ProjectionStore, ReceiveActivation, ReceiveCoverResult,
    ReceiveExpectation, ReceiveFailure, ReceiveFailureKind, ReceiveGap, ReceiveStage,
    ReceiveStageResult, ReceiveTransaction, StorageError,
};

/// Bounded redrive of `LegacyBindingChanged` before a typed give-up.
const BINDING_ATTEMPTS: u32 = 3;
const BINDING_GIVE_UP: &str = "legacy binding changed after 3 attempts";
const ROUTED_REFUSED: &str = "receive ledger refuses live routed apply";
const COVERED_BELOW: &str = "receive page covered below sequence";
const NOT_YET_WIRED: &str = "NotYetWired";

/// True when the P24b1 discriminator is Activated. Activated without an epoch is Integrity.
pub(crate) fn is_active(db: &AccountDb, target: &str) -> Result<bool, SdkError> {
    match db.receive_activation()? {
        ReceiveActivation::Inactive => Ok(false),
        ReceiveActivation::Activated => {
            if db.receive_epoch(target)?.is_none() {
                return Err(StorageError::Integrity(MISSING_EPOCH).into());
            }
            Ok(true)
        }
    }
}

/// Prepare-time coordinates for one `ApplyPage`: message generation plus DB cursor/E/erase.
pub(crate) fn capture_turn(
    db: &AccountDb,
    generation: u64,
    target: &str,
) -> Result<ReceiveTurn, SdkError> {
    let incarnation = db.receive_epoch(target)?.ok_or(StorageError::Integrity(MISSING_EPOCH))?;
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
    let kind = match classify(account, entry, source).await {
        Ok(kind) => kind,
        Err(error) => match failure_of(&error, entry)? {
            Some((kind, code)) => Kind::PolicyFailure(kind, code),
            None => return Err(error),
        },
    };
    #[cfg(test)]
    after_classify(account.client.account_db()?);
    match kind {
        Kind::Routed => Err(SdkError::InboundRejected(ROUTED_REFUSED.into())),
        Kind::OwnCopy(manifest) => {
            let message = entry.envelope.envelope_id.clone();
            let client = &account.client;
            let key = client.inbox_admission_key(entry)?;
            run_fenced(client.account_db()?, handle_generation(), turn, |tx, expected| {
                client.apply_own_copy_w1_in(tx, entry, &manifest, expected, sequence, &message)?;
                project_if_committed(tx, client, entry, sequence, expected)?;
                ReplyOutbox::prune_marker_in(tx, &key)?;
                Ok(false)
            })?;
            Ok(())
        }
        Kind::LegacyDm { conversation } => {
            let client = &account.client;
            let key = client.inbox_admission_key(entry)?;
            run_fenced(client.account_db()?, handle_generation(), turn, |tx, expected| {
                client.apply_legacy_success_w1_in(
                    tx,
                    entry,
                    &local_device,
                    &conversation,
                    expected,
                    handle_generation(),
                )?;
                project_if_committed(tx, client, entry, sequence, expected)?;
                ReplyOutbox::prune_marker_in(tx, &key)?;
                Ok(false)
            })?;
            Ok(())
        }
        Kind::LegacyA2i => {
            let client = &account.client;
            let key = client.inbox_admission_key(entry)?;
            run_fenced(client.account_db()?, handle_generation(), turn, |tx, expected| {
                let held = client.apply_legacy_a2i_w1_in(
                    tx,
                    entry,
                    &local_device,
                    expected,
                    handle_generation(),
                )?;
                cover_if_held(tx, sequence, held, &[])?;
                if !held {
                    ReplyOutbox::prune_marker_in(tx, &key)?;
                }
                Ok(held)
            })?;
            Ok(())
        }
        Kind::LegacyHold => hold_unrouted(account, turn, handle_generation, entry, sequence),
        Kind::PolicyFailure(kind, code) => {
            admit_failure(account, turn, handle_generation, entry, sequence, (kind, code))
        }
        Kind::Projection => project_application(account, turn, handle_generation, entry, sequence),
        Kind::TerminalReply => {
            settle_reply_terminal(account, turn, handle_generation, entry, sequence)
        }
    }
}

fn admit_failure(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    entry: &GatewayInboxEntry,
    sequence: u64,
    (kind, error_code): (ReceiveFailureKind, &'static str),
) -> Result<(), SdkError> {
    let key = account.client.inbox_admission_key(entry)?;
    let json = serde_json::to_vec(entry)?;
    let at = now_unix_timestamp();
    // The verified sender policy, exactly as live retry admission builds it.
    let policy =
        verified_failure_policy(&account.client, &account.gateway_config.device_id, entry, at)?;
    run_fenced(account.client.account_db()?, handle_generation(), turn, |tx, expected| {
        let _ = expected;
        match SourceFailure::admit_in(
            tx,
            ReceiveFailure {
                sequence,
                admission_key: &key,
                entry: &json,
                kind,
                error_code,
                at,
                policy: policy.policy(),
            },
        )? {
            ramflux_storage::ReceiveFailureResult::Held => {}
            ramflux_storage::ReceiveFailureResult::Rejected => {
                ReplyOutbox::prune_marker_in(tx, &key)?;
            }
        }
        Ok(true)
    })?;
    Ok(())
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
    PolicyFailure(ReceiveFailureKind, &'static str),
    Projection,
    TerminalReply,
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
        manifest_await().await;
        #[cfg(test)]
        if skip_manifest_fetch() {
            return Ok(Kind::LegacyHold);
        }
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
    #[cfg(test)]
    if take_manifest_wait() {
        manifest_await().await;
        return Ok(Kind::LegacyHold);
    }
    #[cfg(test)]
    if let Some(error) = take_classify_error() {
        return Err(error);
    }
    #[cfg(test)]
    if take_own_copy() {
        return Ok(Kind::OwnCopy(Box::new(dummy_own_copy_manifest())));
    }
    #[cfg(test)]
    if take_projection() {
        return Ok(Kind::Projection);
    }
    #[cfg(test)]
    if take_terminal_reply() {
        return Ok(Kind::TerminalReply);
    }
    if let Some(kind) = settled_routed_kind(account, entry)? {
        return Ok(kind);
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

/// An authenticated entry that an earlier routed commit already settled. A transferred
/// reply marker ranks above a pending projection: W0 then only needs its terminal cover
/// (the projection already transferred with the reply). A committed receipt without a
/// marker means only the application projection is still owed. Missing identity is
/// nothing owed; every other key-derivation error (including storage) propagates.
fn settled_routed_kind(
    account: &LocalBusAccountState,
    entry: &GatewayInboxEntry,
) -> Result<Option<Kind>, SdkError> {
    let auth_key = match projection_key(&account.client, entry) {
        Ok(key) => key,
        Err(error) if identity_absence(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let db = account.client.account_db()?;
    if db.actor_state_exists(&format!("{MARKER}{auth_key}"))? {
        return Ok(Some(Kind::TerminalReply));
    }
    if db.load_actor_state::<crate::client::routed::Committed>(&auth_key)?.is_some() {
        return Ok(Some(Kind::Projection));
    }
    Ok(None)
}

/// Maps a classification error to a failure-policy admission. Shares live
/// `quarantine_failure`'s wire-signature, `deterministic()` and oversized-retry
/// mapping, and differs in three ways: this adapter propagates `InboundRejected`
/// (live dead-letters it as `routing_rejected`); it has no `routed_seen_marker`
/// short-circuit; it defers only `InboundPending` (live defers every
/// non-deterministic error). Local state refusals and everything else keep W0
/// staged and propagate.
fn failure_of(
    error: &SdkError,
    entry: &GatewayInboxEntry,
) -> Result<Option<(ReceiveFailureKind, &'static str)>, SdkError> {
    if matches!(error, SdkError::InboundRejected(_)) {
        return Ok(None);
    }
    // Immutable malformed signature bytes cannot become valid after a directory refresh.
    let wire = wire_signature_error(entry);
    let error = wire.as_ref().unwrap_or(error);
    if let Some(code) = deterministic(error) {
        return Ok(Some((ReceiveFailureKind::Deterministic, code)));
    }
    if crate::bus::sync_driver::inbound_failure_kind(error) == "InboundPending" {
        if serde_json::to_vec(entry)?.len() > 1024 * 1024 {
            return Ok(Some((ReceiveFailureKind::Deterministic, "oversized_retry")));
        }
        return Ok(Some((ReceiveFailureKind::Retryable, "inbound_pending")));
    }
    Ok(None)
}

/// Reconcile the single-entry page. `NeedStage` writes W0 using the cursor returned
/// after any gap-prefix cover. `Covered`/`AlreadyCovered` with C >= seq skip W1.
/// A cover that leaves C behind seq is a plan bug.
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
        ApplyOutcome::Covered { cursor } | ApplyOutcome::AlreadyCovered { cursor }
            if cursor < sequence =>
        {
            Err(SdkError::Storage(StorageError::Integrity(COVERED_BELOW)))
        }
        ApplyOutcome::NeedPoint { seq, cursor } => {
            turn.cursor = cursor;
            fetch_point(account, turn, generation, seq)?;
            Ok(false)
        }
        ApplyOutcome::Covered { .. }
        | ApplyOutcome::AlreadyCovered { .. }
        | ApplyOutcome::NeedFetch { .. }
        | ApplyOutcome::Paused { .. } => Ok(false),
    }
}

/// A point the router could not stage needs a real `FetchEntry` reply (Entry/TooLarge/Gone).
/// That fetch is not wired until P24b2, and `reconcile_entry` never yields `NeedPoint`
/// while `oversize_next` is `None`, so this refuses rather than invent a loss or a
/// `retain_until`. No W0 terminal path exists here until the fetch lands.
fn fetch_point(
    _account: &LocalBusAccountState,
    _turn: &mut ReceiveTurn,
    _generation: u64,
    seq: u64,
) -> Result<(), SdkError> {
    Err(SdkError::LocalBus(format!("{NOT_YET_WIRED}: fetch point {seq}")))
}

fn project_application(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    entry: &GatewayInboxEntry,
    sequence: u64,
) -> Result<(), SdkError> {
    let client = &account.client;
    // Only an authenticated admission key may key the outbox: an unverified-hash key never
    // reaches `ApplicationOutbox` (and a derivation failure is an error, not a skip).
    let key = projection_key(client, entry)?;
    run_fenced(client.account_db()?, handle_generation(), turn, |tx, expected| {
        project_with_key(tx, client, entry, sequence, expected, &key)?;
        Ok(false)
    })?;
    Ok(())
}

pub(super) fn project_if_committed(
    tx: &ReceiveTransaction<'_>,
    client: &RamfluxClient,
    entry: &GatewayInboxEntry,
    sequence: u64,
    expected: ReceiveExpectation<'_>,
) -> Result<(), SdkError> {
    // Own-copy and legacy-DM success: a missing authenticated identity means
    // nothing is owed. Every other derivation error (including storage) still
    // propagates. `project_application` keeps failing on the same derivation error.
    let auth_key = match projection_key(client, entry) {
        Ok(key) => key,
        Err(error) if identity_absence(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    if tx.account().load_actor_state::<crate::client::routed::Committed>(&auth_key)?.is_none() {
        return Ok(());
    }
    project_with_key(tx, client, entry, sequence, expected, &auth_key)
}

/// The authenticated admission key; derivation failure is an error, never a fallback key.
fn projection_key(client: &RamfluxClient, entry: &GatewayInboxEntry) -> Result<String, SdkError> {
    #[cfg(test)]
    if let Some(error) = PROJECTION_ERROR.with(std::cell::RefCell::take) {
        return Err(error);
    }
    #[cfg(test)]
    if let Some(key) = PROJECTION_KEY.with(std::cell::RefCell::take) {
        return Ok(key);
    }
    client.authenticated_committed_key(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        entry,
    )
}

/// Identity-absence is nothing owed on own-copy / legacy-DM success and on the
/// settled-routed probe. Local and directory failures must not be swallowed.
fn identity_absence(error: &SdkError) -> bool {
    matches!(error, SdkError::IdentityRootMissing)
        || matches!(error, SdkError::InboundRejected(reason) if reason.starts_with("identity authority:"))
}

fn project_with_key(
    tx: &ReceiveTransaction<'_>,
    client: &RamfluxClient,
    entry: &GatewayInboxEntry,
    sequence: u64,
    expected: ReceiveExpectation<'_>,
    auth_key: &str,
) -> Result<(), SdkError> {
    let gate = ApplicationOutbox { expected, generation: expected.generation };
    match gate.admit_in(tx, &AdmitRequest { sequence, auth_key, entry, client })? {
        Admit::Admitted | Admit::Duplicate | Admit::OutboxFull => Ok(()),
    }
}

fn settle_reply_terminal(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    entry: &GatewayInboxEntry,
    sequence: u64,
) -> Result<(), SdkError> {
    let key = account.client.inbox_admission_key(entry)?;
    let gate = ReplyOutbox { expected: turn.expected(), generation: handle_generation() };
    gate.settle_terminal(account.client.account_db()?, sequence, &key)
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
                #[cfg(test)]
                if let Some(hook) = BEFORE_COMMIT_HOOK.with(std::cell::Cell::take) {
                    hook(tx.account());
                }
                #[cfg(test)]
                if let Some(text) = BEFORE_COMMIT.with(std::cell::Cell::take) {
                    outcome = Some(Err(SdkError::Storage(StorageError::Integrity(text))));
                    return Err(StorageError::Integrity(text));
                }
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
    #[cfg(test)]
    if FORCE_COVERED_BELOW.with(std::cell::Cell::take) {
        return Ok(ApplyOutcome::Covered { cursor: sequence.saturating_sub(1) });
    }
    #[cfg(test)]
    if FORCE_NEED_POINT.with(std::cell::Cell::take) {
        return Ok(ApplyOutcome::NeedPoint { seq: sequence, cursor: turn.cursor });
    }
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
    static FORCE_COVERED_BELOW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FORCE_NEED_POINT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static PROJECTION_KEY: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
    static PROJECTION_ERROR: std::cell::RefCell<Option<SdkError>> =
        const { std::cell::RefCell::new(None) };
    static CLASSIFY_ERROR: std::cell::RefCell<Option<SdkError>> =
        const { std::cell::RefCell::new(None) };
    static PROJECTION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static OWN_COPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TERMINAL_REPLY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static MANIFEST_WAIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static SKIP_FETCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static MANIFEST_AWAIT: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
    static BEFORE_COMMIT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    static BEFORE_COMMIT_HOOK: std::cell::Cell<Option<fn(&AccountDb)>> =
        const { std::cell::Cell::new(None) };
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
pub(crate) const fn covered_below() -> &'static str {
    COVERED_BELOW
}

#[cfg(test)]
pub(crate) fn force_covered_below() {
    FORCE_COVERED_BELOW.with(|cell| cell.set(true));
}

#[cfg(test)]
pub(crate) fn force_need_point() {
    FORCE_NEED_POINT.with(|cell| cell.set(true));
}

#[cfg(test)]
pub(crate) fn queue_projection() {
    PROJECTION.with(|cell| cell.set(true));
}

#[cfg(test)]
fn take_projection() -> bool {
    PROJECTION.with(std::cell::Cell::take)
}

#[cfg(test)]
pub(crate) fn queue_terminal_reply() {
    TERMINAL_REPLY.with(|cell| cell.set(true));
}

#[cfg(test)]
fn take_terminal_reply() -> bool {
    TERMINAL_REPLY.with(std::cell::Cell::take)
}

/// Injects the classification error that production `failure_of` then maps for real.
/// `Exhausted` injects `ReplayMismatch`, which classifies as Deterministic
/// `replay_mismatch`; no test drives a true exhausted-retry policy through this hook.
#[cfg(test)]
pub(crate) fn queue_policy_kind(kind: ReceiveFailureKind) {
    let error = match kind {
        ReceiveFailureKind::Retryable => SdkError::InboundPending("directory miss".into()),
        ReceiveFailureKind::Deterministic => {
            SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed)
        }
        ReceiveFailureKind::Exhausted => SdkError::ReplayMismatch,
    };
    CLASSIFY_ERROR.with(|cell| cell.replace(Some(error)));
}

#[cfg(test)]
pub(crate) fn queue_own_copy() {
    OWN_COPY.with(|cell| cell.set(true));
}

#[cfg(test)]
fn take_own_copy() -> bool {
    OWN_COPY.with(std::cell::Cell::take)
}

/// Dummy directory material for the own-copy classify hook. `commit_own_copy_from_entry`
/// returns `Ok(false)` on the dummy payload before reading this value.
#[cfg(test)]
fn dummy_own_copy_manifest() -> crate::SdkDeviceManifestResponse {
    crate::SdkDeviceManifestResponse {
        custody: None,
        signed_device_set: None,
        principal_id: String::new(),
        principal_commitment: String::new(),
        root_public_key: String::new(),
        devices: Vec::new(),
    }
}

/// Stands in for the identity authority's answer only; admission itself is the real path.
#[cfg(test)]
pub(crate) fn set_projection_key(key: &str) {
    PROJECTION_KEY.with(|cell| cell.replace(Some(key.to_owned())));
}

/// Injects a key-derivation error into both nothing-owed arms.
#[cfg(test)]
pub(crate) fn set_projection_error(error: SdkError) {
    PROJECTION_ERROR.with(|cell| cell.replace(Some(error)));
}

#[cfg(test)]
fn take_classify_error() -> Option<SdkError> {
    CLASSIFY_ERROR.with(std::cell::RefCell::take)
}

#[cfg(test)]
pub(crate) fn queue_manifest_wait() {
    MANIFEST_WAIT.with(|cell| cell.set(true));
    SKIP_FETCH.with(|cell| cell.set(true));
}

#[cfg(test)]
fn take_manifest_wait() -> bool {
    MANIFEST_WAIT.with(std::cell::Cell::take)
}

#[cfg(test)]
fn skip_manifest_fetch() -> bool {
    SKIP_FETCH.with(std::cell::Cell::take)
}

#[cfg(test)]
async fn manifest_await() {
    tokio::task::yield_now().await;
    if let Some(hook) = MANIFEST_AWAIT.with(std::cell::Cell::take) {
        hook();
    }
}

#[cfg(test)]
pub(crate) fn set_manifest_await(hook: fn()) {
    MANIFEST_AWAIT.with(|cell| cell.set(Some(hook)));
}

#[cfg(test)]
pub(crate) fn set_before_commit(text: &'static str) {
    BEFORE_COMMIT.with(|cell| cell.set(Some(text)));
}

#[cfg(test)]
pub(crate) fn set_before_commit_hook(hook: fn(&AccountDb)) {
    BEFORE_COMMIT_HOOK.with(|cell| cell.set(Some(hook)));
}

#[cfg(test)]
pub(crate) const fn failure_before_commit() -> &'static str {
    "source failure before-commit"
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
