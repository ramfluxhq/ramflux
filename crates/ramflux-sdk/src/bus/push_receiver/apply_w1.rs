// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant `ApplyPage` → W1 adapters. Inactive accounts stay on the live path.
#![allow(dead_code)]

use super::apply::{self, ApplyOutcome, ApplyPoint, cover_held_in, cover_terminal_in};
use crate::bus::account_runtime::lifecycle_fence;
use crate::bus::connection_manager::{ReceiveApplied, ReceiveEntry, ReceiveTurn};
use crate::bus::contact_backpressure::Backpressure;
use crate::bus::state::LocalBusAccountState;
use crate::bus::sync_driver::source::PreparedSource;
use crate::bus::sync_driver::source::failure::SourceFailure;
use crate::bus::sync_driver::source::hold::{HoldDisposition, SourceHold};
use crate::client::application_outbox::{Admit, AdmitRequest, ApplicationOutbox};
use crate::client::inbox_failure::{deterministic, verified_failure_policy, wire_signature_error};
use crate::client::legacy_w1::LegacyW1;
use crate::client::reply_outbox::{MARKER, ReplyOutbox};
use crate::prelude::*;
use ramflux_protocol::Envelope;
use ramflux_storage::{
    AccountDb, MISSING_EPOCH, ProjectionStore, ReceiveActivation, ReceiveCoverResult,
    ReceiveExpectation, ReceiveFailure, ReceiveFailureKind, ReceiveGap, ReceiveStage,
    ReceiveStageResult, ReceiveTransaction, StorageError,
};

/// Bounded redrive of `LegacyBindingChanged` before a typed give-up.
const BINDING_ATTEMPTS: u32 = 3;
const BINDING_GIVE_UP: &str = "legacy binding changed after 3 attempts";
const COVERED_BELOW: &str = "receive page covered below sequence";

thread_local! {
    static PAIR_REPLY: std::cell::RefCell<Option<Envelope>> = const { std::cell::RefCell::new(None) };
}

fn stash_pair_reply(reply: Option<Envelope>) {
    PAIR_REPLY.with(|cell| *cell.borrow_mut() = reply);
}

/// Pair-reset reply produced by the last successful [`apply_page`]. Connection apply submits it.
pub(crate) fn take_pair_reply() -> Option<Envelope> {
    PAIR_REPLY.with(|cell| cell.borrow_mut().take())
}

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

/// Activated receive is the actor `ApplyPage` path. Standalone `sync_driver::run` must not bind.
pub(crate) fn account_is_active(account: &LocalBusAccountState) -> Result<bool, SdkError> {
    is_active(account.client.account_db()?, &account.target_delivery_id)
}

/// Same key as [`super::executor::LedgerExecutor::bind_actor`]. Skip standalone while it is held.
pub(crate) fn receive_executor_bound(account: &LocalBusAccountState) -> Result<bool, SdkError> {
    let db = account.client.account_db()?;
    let key = format!("{}:{}", db.path.display(), db.local_account_id);
    Ok(super::executor::LedgerExecutor::is_bound(&key))
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
        compat: false,
    })
}

/// W1 + W2 for one `ApplyPage` entry. A non-held W1 writes the terminal cover in the
/// same fenced transaction (receipt bind, ACK intent, C). Held W1 keeps the held cover.
/// ACK emission is the actor `AckFlush` arm (`SourceWa`).
///
/// `turn` is the prepare-time expectation. `handle_generation` is read at each commit
/// (after any await) from S2/handle state.
pub(crate) async fn apply_page(
    account: &mut LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: ReceiveEntry,
    source: PreparedSource,
    mut backpressure: Box<Backpressure>,
) -> Result<ReceiveApplied, SdkError> {
    let mut turn = turn.clone();
    turn.compat = account.bound_session_mode().is_some_and(|mode| !mode.is_push());
    refresh_cursor(account.client.account_db()?, &mut turn)?;
    let mut source = match source.map(|prepared| *prepared).transpose() {
        Ok(source) => source,
        Err(error) if crate::bus::contact_backpressure::deferred(&prepared.entry, &error) => {
            hold_contact_capacity(account, &turn, handle_generation, &prepared, &mut backpressure)?;
            return Ok((None, backpressure));
        }
        Err(SdkError::ContactRequestCapacity(_)) => {
            admit_mapped(
                account,
                &turn,
                handle_generation,
                &prepared,
                SdkError::InboundRejected("deferred contact root capacity exhausted".into()),
            )?;
            return Ok((None, backpressure));
        }
        Err(error) => return Err(error),
    };
    let mut attempts = 0;
    #[cfg(test)]
    BINDING_TRIES.with(|cell| cell.set(0));
    loop {
        match Box::pin(apply_once(
            account,
            &mut turn,
            handle_generation,
            &prepared,
            &mut source,
            &mut backpressure,
        ))
        .await
        {
            Err(SdkError::LegacyBindingChanged) => note_binding_changed(&mut attempts)?,
            Err(SdkError::PairRecoveryRequired) => {
                recover_own_copy(account, &turn, handle_generation(), &prepared.entry)?;
                stash_pair_reply(None);
                break;
            }
            Err(error) => return Err(error),
            Ok(reply) => {
                stash_pair_reply(reply);
                break;
            }
        }
    }
    Ok((None, backpressure))
}

/// Publish durable application-outbox rows into RAM after a production `ApplyPage`.
pub(crate) fn replay_projected(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    crate::client::application_outbox::replay(
        account.client.account_db()?,
        &mut account.pending_deliveries,
    )
}

async fn apply_once(
    account: &mut LocalBusAccountState,
    turn: &mut ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: &ReceiveEntry,
    source: &mut Option<crate::client::routed::PreparedInbound>,
    backpressure: &mut Backpressure,
) -> Result<Option<Envelope>, SdkError> {
    #[cfg(test)]
    cross_await().await;
    let entry = &prepared.entry;
    let sequence = entry.inbox_seq;
    let cover = admit_open(account, turn, handle_generation(), prepared)?;
    if !cover && !open_already_covered(account, turn, handle_generation, prepared, backpressure)? {
        return Ok(None);
    }
    let local_device = account.gateway_config.device_id.clone();
    let own_copy = source.as_mut().and_then(|prepared| prepared.own_copy_manifest.take());
    let (kind, classified_pending) =
        classified_kind(account, entry, own_copy, prepared.retry_key.as_deref()).await?;
    #[cfg(test)]
    after_classify(account.client.account_db()?);
    match kind {
        Kind::Routed => {
            Box::pin(apply_routed_or_defer(
                account,
                turn,
                handle_generation,
                prepared,
                source.take(),
                cover,
                classified_pending,
                backpressure,
            ))
            .await
        }
        Kind::OwnCopy(manifest) => {
            let message = entry.envelope.envelope_id.clone();
            let client = &account.client;
            let key = client.inbox_admission_key(entry)?;
            run_fenced(client.account_db()?, handle_generation(), turn, |tx, expected| {
                client.apply_own_copy_w1_in(tx, entry, &manifest, expected, sequence, &message)?;
                // Sibling control has no routed DM projection; the outer envelope is not one.
                ReplyOutbox::prune_marker_in(tx, &key)?;
                cover_w1_outcome(tx, sequence, false, &[], turn.compat)?;
                Ok(false)
            })?;
            Ok(None)
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
                cover_w1_outcome(tx, sequence, false, &[], turn.compat)?;
                Ok(false)
            })?;
            Ok(None)
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
                cover_w1_outcome(tx, sequence, held, &[], turn.compat)?;
                if !held {
                    ReplyOutbox::prune_marker_in(tx, &key)?;
                }
                Ok(held)
            })?;
            Ok(None)
        }
        Kind::LegacyHold => {
            hold_unrouted(account, turn, handle_generation, entry, sequence)?;
            Ok(None)
        }
        Kind::PolicyFailure(kind, code) => {
            let key = account.client.inbox_admission_key(entry)?;
            admit_failure(account, turn, handle_generation, entry, sequence, &key, (kind, code))?;
            Ok(None)
        }
        Kind::Projection => {
            project_committed(account, turn, handle_generation, prepared, cover)?;
            Ok(None)
        }
        Kind::TerminalReply => {
            settle_reply_terminal(account, turn, handle_generation, entry, sequence)?;
            Ok(None)
        }
    }
}

async fn classified_kind(
    account: &LocalBusAccountState,
    entry: &GatewayInboxEntry,
    own_copy: Option<crate::SdkDeviceManifestResponse>,
    retry_key: Option<&str>,
) -> Result<(Kind, Option<SdkError>), SdkError> {
    match classify(account, entry, own_copy, retry_key).await {
        Ok(kind) => Ok((kind, None)),
        Err(error) => {
            if crate::client::routed::decode(&entry.envelope).is_ok() && directory_pending(&error) {
                Ok((Kind::Routed, Some(error)))
            } else {
                match failure_of(&error, entry)? {
                    Some((kind, code)) => Ok((Kind::PolicyFailure(kind, code), None)),
                    None => Err(error),
                }
            }
        }
    }
}

/// Open/decrypt outside the fence; persist + terminal (or held) cover in the same fenced tx.
/// Directory/head misses become a held retry plus retain, not a page abort.
#[allow(
    clippy::too_many_arguments,
    reason = "joins classify-pending root with the routed W1 deferral"
)]
async fn apply_routed_or_defer(
    account: &mut LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: &ReceiveEntry,
    source: Option<crate::client::routed::PreparedInbound>,
    cover: bool,
    classified_pending: Option<SdkError>,
    backpressure: &mut Backpressure,
) -> Result<Option<Envelope>, SdkError> {
    // W0 `source::request` skips a duplicate contact root before any manifest fetch.
    // Standalone W1 has no Writer prepare, so the same cut lives here.
    if backpressure.duplicate(&prepared.entry) {
        return admit_mapped(
            account,
            turn,
            handle_generation,
            prepared,
            SdkError::InboundRejected("deferred contact root capacity exhausted".into()),
        );
    }
    if crate::client::routed::decode(&prepared.entry.envelope)
        .is_ok_and(|packet| packet.schema == crate::client::contact_requests::ENVELOPE_SCHEMA)
    {
        // W0 `source::request` quarantines `contact_candidate_manifest_request`
        // errors (sender rate-limit, closed root, malformed) before any fetch.
        // Global/account pressure still identifies the requester (one fetch) so
        // overflow roots can be recorded; rescans skip W1 via `saturated()`.
        if let Err(error) = account.client.contact_candidate_manifest_request(&prepared.entry) {
            return admit_mapped(account, turn, handle_generation, prepared, error);
        }
    }
    match Box::pin(apply_routed_w1(account, turn, handle_generation, prepared, source, cover)).await
    {
        Ok(reply) => {
            backpressure.completed(&account.client, &prepared.entry)?;
            Ok(reply)
        }
        Err(SdkError::StorageCapacity { source_anchor, .. }) => {
            run_fenced(account.client.account_db()?, handle_generation(), turn, |tx, _| {
                account.client.record_generated_capacity(&prepared.entry, &source_anchor, now_unix_timestamp())?;
                cover_w1_outcome(tx, prepared.entry.inbox_seq, true, &[], turn.compat)?;
                Ok(())
            })?;
            Ok(None)
        }
        Err(error) if directory_pending(&error) => {
            defer_routed_pending(
                account,
                turn,
                handle_generation,
                &prepared.entry,
                retain_error(classified_pending, error),
            )?;
            Ok(None)
        }
        Err(error) if crate::bus::contact_backpressure::deferred(&prepared.entry, &error) => {
            hold_contact_capacity(account, turn, handle_generation, prepared, backpressure)
        }
        Err(SdkError::ContactRequestCapacity(_)) => admit_mapped(
            account,
            turn,
            handle_generation,
            prepared,
            SdkError::InboundRejected("deferred contact root capacity exhausted".into()),
        ),
        Err(error) => admit_mapped(account, turn, handle_generation, prepared, error),
    }
}

/// First envelope of a deferred contact root: record the durable floor and held-cover
/// without ACK so the gateway keeps the ciphertext. Duplicate seqs of the same root
/// dead-letter as `routing_rejected` (W0 `quarantine_failure` after `record` returns
/// false). Replay skips a second cover: C already advanced on the live pass.
fn hold_contact_capacity(
    account: &mut LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: &ReceiveEntry,
    backpressure: &mut Backpressure,
) -> Result<Option<Envelope>, SdkError> {
    if backpressure.record(&account.client, &prepared.entry, now_unix_timestamp())? {
        if !prepared.replay {
            run_fenced(
                account.client.account_db()?,
                handle_generation(),
                turn,
                |tx, _expected| {
                    cover_w1_outcome(tx, prepared.entry.inbox_seq, true, &[], turn.compat)?;
                    Ok(())
                },
            )?;
        }
        return Ok(None);
    }
    admit_mapped(
        account,
        turn,
        handle_generation,
        prepared,
        SdkError::InboundRejected("deferred contact root capacity exhausted".into()),
    )
}

fn admit_mapped(
    account: &mut LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: &ReceiveEntry,
    error: SdkError,
) -> Result<Option<Envelope>, SdkError> {
    match failure_of(&error, &prepared.entry)? {
        Some(pair) => {
            let key = account.client.inbox_admission_key(&prepared.entry)?;
            admit_failure(
                account,
                turn,
                handle_generation,
                &prepared.entry,
                prepared.entry.inbox_seq,
                &key,
                pair,
            )?;
            Ok(None)
        }
        None => Err(error),
    }
}

/// Prefer a classify miss that already names the blocked root over a later
/// directory `InboundPending` (which `retain` cannot key).
fn retain_error(classified: Option<SdkError>, applied: SdkError) -> SdkError {
    match classified {
        Some(error) if retain_root(&error).is_some() => error,
        _ => applied,
    }
}

fn retain_root(error: &SdkError) -> Option<&str> {
    match error {
        SdkError::DirectoryAuthorityUnavailable { root, .. }
        | SdkError::SenderManifestRequired { root }
        | SdkError::FreshHeadRequired { root } => Some(root.as_str()),
        _ => None,
    }
}

fn directory_pending(error: &SdkError) -> bool {
    matches!(
        error,
        SdkError::DirectoryAuthorityUnavailable { .. }
            | SdkError::InboundPending(_)
            | SdkError::SenderManifestRequired { .. }
            | SdkError::FreshHeadRequired { .. }
    )
}

fn defer_routed_pending(
    account: &mut LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    entry: &GatewayInboxEntry,
    error: SdkError,
) -> Result<(), SdkError> {
    let (kind, code) = match failure_of(&error, entry)? {
        Some(pair) => pair,
        None if directory_pending(&error) => (ReceiveFailureKind::Retryable, "inbound_pending"),
        None => return Err(error),
    };
    let computed = account.client.inbox_admission_key(entry)?;
    let key = staged_admission_key(account, turn, handle_generation(), entry.inbox_seq, &computed)?;
    let already = account.client.account_db()?.has_inbox_retry(&key)?;
    admit_failure(account, turn, handle_generation, entry, entry.inbox_seq, &key, (kind, code))?;
    // Leftover persist-without-cover re-opens W1. Skip only while the first
    // root is still blocking; a granted/cancelled attempt must re-retain so
    // group.receive waits again if the head is stale.
    if already && crate::bus::couriers::head_refresh::inbound::blocking(account, &key) {
        return Ok(());
    }
    crate::bus::couriers::head_refresh::inbound::retain(account, entry, &key, &error)?;
    Ok(())
}

fn staged_admission_key(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    generation: u64,
    sequence: u64,
    computed: &str,
) -> Result<String, SdkError> {
    Ok(account.client.account_db()?.receive_transaction(
        turn.expected(),
        generation,
        |tx| match tx.work_admission_key(sequence)? {
            Some(existing) => Ok(existing),
            None => Ok(computed.to_owned()),
        },
    )?)
}

async fn apply_routed_w1(
    account: &mut LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: &ReceiveEntry,
    source: Option<crate::client::routed::PreparedInbound>,
    cover: bool,
) -> Result<Option<Envelope>, SdkError> {
    let pool = account.relay_quic_pool()?;
    let generation = handle_generation();
    if account.connection.is_some() {
        let mut engine = account.live_session_client()?;
        // Fill directory coordinates without switching the live transport kind
        // (test injectors stay on Injected; a TcpTls overlay would talk HTTP
        // to a directory fixture and lose the typed FreshHeadRequired).
        if engine.config.tcp_gateway_addr.is_none()
            && account.gateway_config.tcp_gateway_addr.is_some()
        {
            engine.config.tcp_gateway_addr = account.gateway_config.tcp_gateway_addr;
            engine.config.ca_cert.clone_from(&account.gateway_config.ca_cert);
            engine.config.server_name.clone_from(&account.gateway_config.server_name);
        }
        let result =
            join_routed_w1(account, &mut engine, &pool, turn, generation, prepared, source, cover)
                .await;
        account.apply_session_metadata(engine);
        return result;
    }
    let seed_directory = account.gateway_config.tcp_gateway_addr.is_some()
        || account.engine.as_ref().is_some_and(|engine| engine.config.tcp_gateway_addr.is_some());
    if !seed_directory {
        return account.live_session_client().map(|_| None);
    }
    let mut engine = account.engine.take().ok_or(SdkError::GatewaySessionNotEstablished)?;
    let result =
        join_routed_w1(account, &mut engine, &pool, turn, generation, prepared, source, cover)
            .await;
    account.engine = Some(engine);
    result
}

#[allow(
    clippy::too_many_arguments,
    reason = "joins the live session or seed engine onto one W1 persist"
)]
async fn join_routed_w1(
    account: &mut LocalBusAccountState,
    engine: &mut impl crate::gateway::access::GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    turn: &ReceiveTurn,
    generation: u64,
    prepared: &ReceiveEntry,
    source: Option<crate::client::routed::PreparedInbound>,
    cover: bool,
) -> Result<Option<Envelope>, SdkError> {
    let sequence = prepared.entry.inbox_seq;
    let entry = &prepared.entry;
    let delivery = account
        .client
        .apply_routed_entry_joining(engine, pool, entry, source.map(Ok), |client, write| {
            run_fenced(client.account_db()?, generation, turn, |tx, expected| match write {
                crate::client::routed::JoinedW1::Project(ctx) => {
                    let (projected, admitted, held) =
                        client.commit_routed_w1_in(tx, sequence, ctx)?;
                    project_if_committed(tx, client, entry, sequence, expected)?;
                    cover_or_retire_retry(tx, sequence, held, turn, cover)?;
                    Ok((projected, admitted))
                }
                crate::client::routed::JoinedW1::Cover => {
                    project_if_committed(tx, client, entry, sequence, expected)?;
                    cover_or_retire_retry(tx, sequence, false, turn, cover)?;
                    Ok((None, Vec::new()))
                }
                crate::client::routed::JoinedW1::ContactBootstrap { entry, manifest, local } => {
                    tx.require_open_input(sequence)?;
                    client.commit_contact_request_bootstrap_in(entry, manifest, local)?;
                    cover_or_retire_retry(tx, sequence, false, turn, cover)?;
                    Ok((None, Vec::new()))
                }
            })
        })
        .await?;
    Ok(delivery.pair_reply)
}

fn cover_or_retire_retry(
    tx: &ReceiveTransaction<'_>,
    sequence: u64,
    held: bool,
    turn: &ReceiveTurn,
    cover: bool,
) -> Result<(), SdkError> {
    if cover {
        return cover_w1_outcome(tx, sequence, held, &[], turn.compat);
    }
    if !held && let Some(key) = tx.work_admission_key(sequence)? {
        tx.account().remove_inbox_retry(&key)?;
    }
    Ok(())
}

/// `AlreadyCovered` of a held contact floor still runs W1 once admission is
/// open: C advanced on the live hold, and the durable floor owns redrive.
/// W0 `saturated` on replay skips W1 while capacity is still closed (a second
/// Held/Terminal cover of seq <= C is Integrity).
fn open_already_covered(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: &ReceiveEntry,
    backpressure: &mut Backpressure,
) -> Result<bool, SdkError> {
    let entry = &prepared.entry;
    if held_retry_open(account, turn, handle_generation(), entry.inbox_seq, prepared)? {
        return Ok(true);
    }
    if account.client.generated_capacity_held(entry)? { return Ok(true); }
    if !backpressure.holds(entry) {
        return Ok(false);
    }
    let now = now_unix_timestamp();
    if !account.client.contact_admission_capacity(None, now)? {
        let _ = backpressure.saturated(&account.client, entry, now)?;
        return Ok(false);
    }
    Ok(true)
}

fn held_retry_open(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    generation: u64,
    sequence: u64,
    prepared: &ReceiveEntry,
) -> Result<bool, SdkError> {
    let db = account.client.account_db()?;
    if let Some(key) = &prepared.retry_key
        && db.has_inbox_retry(key)?
    {
        return Ok(true);
    }
    Ok(db.receive_transaction(turn.expected(), generation, |tx| {
        match tx.work_admission_key(sequence)? {
            Some(key) => tx.account().has_inbox_retry(&key),
            None => Ok(false),
        }
    })?)
}

#[allow(
    clippy::too_many_arguments,
    reason = "failure admission keeps the live key, policy, and cover together"
)]
fn admit_failure(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    entry: &GatewayInboxEntry,
    sequence: u64,
    computed: &str,
    (kind, error_code): (ReceiveFailureKind, &'static str),
) -> Result<(), SdkError> {
    let json = serde_json::to_vec(entry)?;
    let at = now_unix_timestamp();
    // The verified sender policy, exactly as live retry admission builds it.
    let policy =
        verified_failure_policy(&account.client, &account.gateway_config.device_id, entry, at)?;
    run_fenced(account.client.account_db()?, handle_generation(), turn, |tx, expected| {
        let _ = expected;
        let key = match tx.work_admission_key(sequence)? {
            Some(existing) => existing,
            None => computed.to_owned(),
        };
        // Leftover persist-without-cover re-opens held W1; a still-retryable
        // outcome must keep the original backoff. Re-deferring from wall-clock
        // `now` would make the row due immediately on the next group.receive.
        if tx.account().has_inbox_retry(&key)? {
            return Ok(true);
        }
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
    let legacy_group = matches!(group_entry_is_sender_key_message(entry), Ok(true));
    let computed = if legacy_group {
        crate::client::group_quarantine::legacy_key(entry)?
    } else {
        account.client.inbox_admission_key(entry)?
    };
    let at = now_unix_timestamp();
    run_fenced(account.client.account_db()?, handle_generation(), turn, |tx, expected| {
        let generation = handle_generation();
        let key = match tx.work_admission_key(sequence)? {
            Some(existing) => existing,
            None => computed.clone(),
        };
        let gate = LegacyW1 { expected, generation };
        let hold = SourceHold { expected, generation };
        match gate
            .effect_in(tx, sequence, None, || hold.unrouted_in(tx, entry, &key, at, legacy_group))?
        {
            HoldDisposition::HeldLocal { .. } => {
                if legacy_group {
                    tx.account().retain_legacy_inbox(&key)?;
                }
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
    own_copy: Option<crate::SdkDeviceManifestResponse>,
    retry_key: Option<&str>,
) -> Result<Kind, SdkError> {
    if let Some(manifest) = own_copy {
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
    if let Some(kind) = settled_routed_kind(account, entry, retry_key)? {
        return Ok(kind);
    }
    if crate::client::routed::decode(&entry.envelope).is_ok() {
        return Ok(Kind::Routed);
    }
    if matches!(group_entry_is_sender_key_message(entry), Ok(true)) {
        return Ok(Kind::LegacyHold);
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
/// marker means only the application projection is still owed. Missing identity or an
/// incomplete sender cache is nothing settled yet; every other key-derivation error
/// (including storage) propagates.
fn settled_routed_kind(
    account: &LocalBusAccountState,
    entry: &GatewayInboxEntry,
    retry_key: Option<&str>,
) -> Result<Option<Kind>, SdkError> {
    let auth_key = match account.client.retained_committed_receipt_key(entry) {
        Ok(Some(key)) => key,
        Err(SdkError::InboundRejected(reason))
            if reason.starts_with("envelope id reused with a different authenticated payload") =>
        {
            return Err(SdkError::InboundRejected(reason));
        }
        Ok(None) | Err(_) => {
            if let Some(key) = retry_key {
                key.to_owned()
            } else {
                match projection_key(&account.client, entry) {
                    Ok(key) => key,
                    Err(error) if identity_absence(&error) => return Ok(None),
                    // Incomplete cache / stale head: nothing is settled yet. Fall through to
                    // decode (routed W1) or sender-key hold. DirectoryAuthorityUnavailable
                    // still propagates so the settled-key probe stays a typed miss.
                    Err(
                        SdkError::InboundPending(_)
                        | SdkError::FreshHeadRequired { .. }
                        | SdkError::SenderManifestRequired { .. },
                    ) => {
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
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

/// Maps a classification or W1-apply error to a failure-policy admission. Shares live
/// `quarantine_failure`'s wire-signature, `deterministic()` and oversized-retry
/// mapping. Identity-absence stays a typed miss. Other `InboundRejected` admits as
/// `routing_rejected` so one bad envelope cannot abort the receive pass. Directory
/// lookup and `InboundPending` stay retryable. Session, storage, contact-capacity
/// and every other local refusal keep W0 staged and propagate — a dummy signature
/// must not rewrite `GatewaySessionNotEstablished`.
fn failure_of(
    error: &SdkError,
    entry: &GatewayInboxEntry,
) -> Result<Option<(ReceiveFailureKind, &'static str)>, SdkError> {
    if identity_absence(error) || local_refusal(error) {
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
    account: &mut LocalBusAccountState,
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
        ApplyOutcome::Covered { cursor } | ApplyOutcome::AlreadyCovered { cursor } => {
            map_page_outcome(
                if cursor < sequence {
                    ApplyOutcome::Covered { cursor }
                } else {
                    ApplyOutcome::AlreadyCovered { cursor }
                },
                sequence,
            )?;
            Ok(false)
        }
        ApplyOutcome::NeedPoint { .. } | ApplyOutcome::NeedFetch { .. } => Err(SdkError::Storage(
            StorageError::Integrity("receive admission cannot fetch a point from reconcile"),
        )),
        ApplyOutcome::Paused { .. } => Ok(false),
    }
}

/// Maps a durable page outcome onto one sequence. `Covered`/`AlreadyCovered` with
/// `cursor < sequence` is Integrity `COVERED_BELOW`.
pub(crate) fn map_page_outcome(
    outcome: ApplyOutcome,
    sequence: u64,
) -> Result<ApplyOutcome, SdkError> {
    match outcome {
        ApplyOutcome::Covered { cursor } | ApplyOutcome::AlreadyCovered { cursor }
            if cursor < sequence =>
        {
            Err(SdkError::Storage(StorageError::Integrity(COVERED_BELOW)))
        }
        other => Ok(other),
    }
}

async fn fetch_and_cover_point(
    account: &mut LocalBusAccountState,
    turn: &mut ReceiveTurn,
    generation: u64,
    seq: u64,
) -> Result<(), SdkError> {
    let reply = fetch_entry_reply(account, seq).await?;
    let target = turn.target.clone();
    let incarnation = turn.incarnation.clone();
    let point = match &reply {
        crate::gateway::push_point::PointReply::Entry(record) => ApplyPoint::Entry {
            seq: record.entry.inbox_seq,
            target: &target,
            incarnation: &incarnation,
        },
        crate::gateway::push_point::PointReply::TooLarge { retain_until } => {
            ApplyPoint::TooLarge { seq, retain_until: *retain_until, incarnation: &incarnation }
        }
        crate::gateway::push_point::PointReply::Gone { observed_issued_inbox_seq, reason } => {
            ApplyPoint::Gone {
                seq,
                observed_issued: *observed_issued_inbox_seq,
                reason: reason.as_str(),
                incarnation: &incarnation,
            }
        }
        crate::gateway::push_point::PointReply::Refused(reason) => {
            return Err(SdkError::GatewaySessionRejected(format!(
                "fetch_entry refused: {}",
                reason.as_str()
            )));
        }
    };
    let db = account.client.account_db()?;
    match apply::apply_point(db, turn.expected(), generation, seq, point) {
        Ok(outcome) => {
            let outcome = map_page_outcome(outcome, seq)?;
            if let ApplyOutcome::Covered { cursor }
            | ApplyOutcome::AlreadyCovered { cursor }
            | ApplyOutcome::Paused { cursor }
            | ApplyOutcome::NeedStage { cursor, .. }
            | ApplyOutcome::NeedPoint { cursor, .. } = outcome
            {
                turn.cursor = cursor;
            }
            Ok(())
        }
        Err(apply::ApplyError::Protocol(text)) => Err(SdkError::InboundRejected(text.into())),
        Err(apply::ApplyError::Storage(error)) => Err(error.into()),
    }
}

async fn fetch_entry_reply(
    account: &mut LocalBusAccountState,
    seq: u64,
) -> Result<crate::gateway::push_point::PointReply, SdkError> {
    #[cfg(test)]
    if let Some(reply) = take_point_reply() {
        return Ok(reply);
    }
    let timeout = account.timeouts.call;
    if let Some(handle) = account.connection.clone() {
        return handle
            .call(
                move |engine| Box::pin(engine.fetch_entry(seq)),
                tokio::time::Instant::now() + timeout,
            )
            .await;
    }
    if let Some(engine) = account.engine.as_mut() {
        return engine.fetch_entry(seq).await;
    }
    Err(SdkError::NetworkingPending)
}

/// Drop a leftover inbox retry whose sequence is already on C. The planted key
/// is required: `work_admission_key` is gone after the first terminal cleanup.
fn retire_retry_in(tx: &ReceiveTransaction<'_>, prepared: &ReceiveEntry) -> Result<(), SdkError> {
    if let Some(key) = &prepared.retry_key {
        tx.account().remove_inbox_retry(key)?;
    }
    if let Some(key) = tx.work_admission_key(prepared.entry.inbox_seq)? {
        tx.account().remove_inbox_retry(&key)?;
    }
    Ok(())
}

fn projection_auth_key(
    client: &RamfluxClient,
    entry: &GatewayInboxEntry,
) -> Result<String, SdkError> {
    match client.retained_committed_receipt_key(entry) {
        Ok(Some(key)) => Ok(key),
        Err(SdkError::InboundRejected(reason))
            if reason.starts_with("envelope id reused with a different authenticated payload") =>
        {
            Err(SdkError::InboundRejected(reason))
        }
        Ok(None) | Err(_) => projection_key(client, entry),
    }
}

/// Application projection for a committed receipt. A leftover of already-applied
/// W0 ciphertext has no open W1 receipt (C may already include the seq, or
/// migration imported nothing); skip Terminal cover in that case and retire
/// the planted retry so standalone can ACK.
fn project_committed(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: &dyn Fn() -> u64,
    prepared: &ReceiveEntry,
    cover: bool,
) -> Result<(), SdkError> {
    let entry = &prepared.entry;
    let sequence = entry.inbox_seq;
    let client = &account.client;
    let key = projection_auth_key(client, entry)?;
    run_fenced(client.account_db()?, handle_generation(), turn, |tx, expected| {
        let open = match tx.require_open_input(sequence) {
            Ok(()) => true,
            Err(StorageError::Integrity("source effect requires staged receive work")) => false,
            Err(error) => return Err(error.into()),
        };
        if open {
            project_with_key(tx, client, entry, sequence, expected, &key)?;
            if cover {
                match cover_w1_outcome(tx, sequence, false, &[], turn.compat) {
                    Err(SdkError::Storage(StorageError::Integrity(
                        "receive cover requires a receipt" | "receive cover interval outside page",
                    ))) => {}
                    other => other?,
                }
            }
        }
        retire_retry_in(tx, prepared)?;
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

/// Session, storage, and contact-capacity refusals stay typed. Wire-signature
/// classification must not turn them into `routing_rejected` / `schema_invalid`.
fn local_refusal(error: &SdkError) -> bool {
    matches!(
        error,
        SdkError::GatewaySessionNotEstablished
            | SdkError::ContactRequestCapacity(_)
            | SdkError::Storage(_)
            | SdkError::LocalBus(_)
            | SdkError::Transport(_)
            | SdkError::LegacyBindingChanged
            | SdkError::PairRecoveryRequired
            | SdkError::AccountDbNotUnlocked
    )
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
    let key = match &prepared.retry_key {
        Some(key) => key.clone(),
        None => account.client.inbox_admission_key(&prepared.entry)?,
    };
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
        cover_w1_outcome(tx, entry.inbox_seq, false, &[], turn.compat)?;
        Ok(false)
    })?;
    Ok(())
}

fn run_fenced<T>(
    db: &AccountDb,
    handle_generation: u64,
    turn: &ReceiveTurn,
    write: impl FnOnce(&ReceiveTransaction<'_>, ReceiveExpectation<'_>) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    let expected = turn.expected();
    let mut outcome = None;
    let fenced =
        lifecycle_fence::commit(db, handle_generation, expected, |tx| match write(tx, expected) {
            Ok(value) => {
                #[cfg(test)]
                if let Some(hook) = BEFORE_COMMIT_HOOK.with(std::cell::Cell::take) {
                    hook(tx.account());
                }
                #[cfg(test)]
                if let Some(text) = BEFORE_COMMIT.with(std::cell::Cell::take) {
                    outcome = Some(Err(SdkError::Storage(StorageError::Integrity(text))));
                    return Err(StorageError::Integrity(text));
                }
                outcome = Some(Ok(value));
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
        (Ok(()), Some(Ok(value))) => Ok(value),
        (Ok(()), None) => Err(SdkError::LocalBus("apply page w1 did not run".into())),
    }
}

fn cover_w1_outcome(
    tx: &ReceiveTransaction<'_>,
    sequence: u64,
    held: bool,
    gaps: &[ReceiveGap<'_>],
    compat: bool,
) -> Result<(), SdkError> {
    #[cfg(test)]
    if let Some(text) = AFTER_W1_CUT.with(std::cell::Cell::take) {
        return Err(SdkError::Storage(StorageError::Integrity(text)));
    }
    let covered = if held {
        cover_held_in(tx, sequence, gaps)?
    } else if compat {
        super::compat::CompatExecutor {
            expected: ramflux_storage::ReceiveExpectation {
                target: "",
                incarnation: "",
                cursor: 0,
                generation: 0,
                erasure_generation: 0,
            },
            generation: 0,
        }
        .admit_in(tx, &super::compat::AdmitRequest { sequence, now: now_unix_timestamp() })?
    } else {
        cover_terminal_in(tx, sequence, gaps)?
    };
    match covered {
        ReceiveCoverResult::Covered => {}
        ReceiveCoverResult::Paused if held => return Ok(()),
        ReceiveCoverResult::Paused => {
            return Err(SdkError::InboundRejected("receive terminal cover paused".into()));
        }
    }
    // Compat keeps ledger work until WA; the inbox retry is only the W1 deferral.
    if !held && let Some(key) = tx.work_admission_key(sequence)? {
        tx.account().remove_inbox_retry(&key)?;
    }
    Ok(())
}

/// Validate/reconcile the single-entry page before W1. `NeedStage` is the live sequence
/// this adapter must process; any other outcome is already covered or not this entry.
pub(crate) fn reconcile_entry(
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
        Ok(outcome) => map_page_outcome(outcome, sequence),
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

pub(crate) fn read_cursor(db: &AccountDb, target: &str) -> Result<u64, SdkError> {
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
    static POINT_REPLY: std::cell::RefCell<Option<crate::gateway::push_point::PointReply>> =
        const { std::cell::RefCell::new(None) };
    static PROJECTION_KEY: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
    static PROJECTION_ERROR: std::cell::RefCell<Option<SdkError>> =
        const { std::cell::RefCell::new(None) };
    static CLASSIFY_ERROR: std::cell::RefCell<Option<SdkError>> =
        const { std::cell::RefCell::new(None) };
    static PROJECTION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static OWN_COPY: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static TERMINAL_REPLY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static MANIFEST_WAIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static SKIP_FETCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static MANIFEST_AWAIT: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
    static BEFORE_COMMIT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    static BEFORE_COMMIT_HOOK: std::cell::Cell<Option<fn(&AccountDb)>> =
        const { std::cell::Cell::new(None) };
    static AFTER_W1_CUT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
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
pub(crate) fn queue_point_reply(reply: crate::gateway::push_point::PointReply) {
    POINT_REPLY.with(|cell| cell.replace(Some(reply)));
}

#[cfg(test)]
fn take_point_reply() -> Option<crate::gateway::push_point::PointReply> {
    POINT_REPLY.with(std::cell::RefCell::take)
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
    queue_own_copy_n(1);
}

#[cfg(test)]
pub(crate) fn queue_own_copy_n(n: u32) {
    OWN_COPY.with(|cell| cell.set(n));
}

#[cfg(test)]
fn take_own_copy() -> bool {
    OWN_COPY.with(|cell| {
        let n = cell.get();
        if n == 0 {
            false
        } else {
            cell.set(n - 1);
            true
        }
    })
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
pub(crate) fn set_after_w1_cut(text: &'static str) {
    AFTER_W1_CUT.with(|cell| cell.set(Some(text)));
}

#[cfg(test)]
pub(crate) const fn after_w1_cut() -> &'static str {
    "receive w1-cover cut"
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
