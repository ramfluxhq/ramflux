// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Standalone public receive: the same ledger pass under `bind_standalone` (D5).

use super::super::connection_manager::receive::entry_id;
use super::super::connection_manager::{ReceiveEntry, ReceiveTurn};
use super::super::push_receiver::apply::{self, ApplyLoss, ApplyOutcome, ApplyPage, ApplyPoint};
use super::super::push_receiver::apply_w1;
use super::super::push_receiver::executor::LedgerExecutor;
use crate::SdkError;
use crate::bus::contact_backpressure::Backpressure;
use crate::bus::state::LocalBusAccountState;
use crate::gateway::access::GatewayPushAccess;
use crate::gateway::push_point::PointReply;
use crate::gateway::push_resume::{PageReply, ResumePage};
use crate::gateway::session_push::PageEntryRecord;
use crate::{GatewayInboxEntry, time::now_unix_timestamp};
use serde_json::json;
use std::collections::BTreeMap;

const PAGE_LIMIT: usize = super::super::connection_manager::receive::RECEIVE_PAGE_LIMIT;
const YIELD_AFTER: u32 = super::super::connection_manager::receive::RECEIVE_YIELD_AFTER_PAGES;

pub(super) async fn receive(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    now: i64,
) -> Result<(usize, Vec<crate::client::surface::ResyncReply>), SdkError> {
    receive_inner(account, engine, now, true).await
}

/// Same pass as [`receive`] while the actor already holds the exclusive bind (D5).
pub(super) async fn receive_on_actor_bind(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    now: i64,
) -> Result<(usize, Vec<crate::client::surface::ResyncReply>), SdkError> {
    receive_inner(account, engine, now, false).await
}

async fn receive_inner(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    now: i64,
    bind_standalone: bool,
) -> Result<(usize, Vec<crate::client::surface::ResyncReply>), SdkError> {
    let _exec = if bind_standalone {
        let db = account.client.account_db()?;
        let key = format!("{}:{}", db.path.display(), db.local_account_id);
        Some(LedgerExecutor::bind_standalone(key)?)
    } else {
        None
    };
    account.client.prune_surface_resync_state()?;
    let generation = account
        .connection
        .as_ref()
        .map_or(1, super::super::connection_manager::ConnectionHandle::generation);
    let mut turn = apply_w1::capture_turn(
        account.client.account_db()?,
        generation,
        &account.target_delivery_id,
    )?;
    let recovered = super::source::w0::recover_standalone_retries(account, &turn, generation)?;
    let mut retries: BTreeMap<_, _> =
        recovered.into_iter().map(|prepared| (entry_id(&prepared.entry), prepared)).collect();
    merge_disk_retries(account, &mut retries, now)?;
    let mut backpressure = Box::new(Backpressure::load(&account.client, now)?);
    let mut applied = 0_usize;
    let mut pages = 0_u32;
    let mut envelope_ids = BTreeMap::new();
    loop {
        let page = resume_one(account, engine, turn.cursor, PAGE_LIMIT).await?;
        pages = pages.saturating_add(1);
        if pages >= YIELD_AFTER {
            tokio::task::yield_now().await;
            pages = 0;
        }
        let more = page.more;
        match drive_page(
            account,
            engine,
            &mut turn,
            generation,
            &page,
            &mut retries,
            backpressure,
            applied,
            &mut envelope_ids,
        )
        .await?
        {
            PageDrive::Paused { applied } => {
                flush_live_acks(account, engine, generation, &envelope_ids).await?;
                account.client.retry_pair_resets(engine, now).await?;
                return Ok((applied, Vec::new()));
            }
            PageDrive::Continue { backpressure: next, applied: next_applied } => {
                backpressure = next;
                applied = next_applied;
            }
        }
        if !more {
            break;
        }
    }
    (backpressure, applied) = redrive_held_floor(
        account,
        engine,
        &mut turn,
        generation,
        backpressure,
        applied,
        &mut envelope_ids,
        now,
    )
    .await?;
    applied = apply_leftover(
        account,
        engine,
        &mut turn,
        generation,
        retries,
        backpressure,
        applied,
        &mut envelope_ids,
    )
    .await?;
    flush_live_acks(account, engine, generation, &envelope_ids).await?;
    // W0 `receive` flushes due pair-reset work after the page. The actor has a
    // pair-reset courier; standalone `run` is the one-shot driver tests use.
    account.client.retry_pair_resets(engine, now).await?;
    Ok((applied, Vec::new()))
}

/// W0 `append_pending_entries` rows that are not yet open ledger recovery inputs.
/// A planted inbox retry keeps its durable key so a stripped call payload cannot
/// recompute a different admission key at `stage_open`.
fn merge_disk_retries(
    account: &LocalBusAccountState,
    retries: &mut BTreeMap<(String, u64, String), ReceiveEntry>,
    now: i64,
) -> Result<(), SdkError> {
    use std::collections::btree_map::Entry;
    let db = account.client.account_db()?;
    for (key, bytes) in db.due_inbox_retry_rows(now)? {
        let entry: GatewayInboxEntry = serde_json::from_slice(&bytes)?;
        match retries.entry(entry_id(&entry)) {
            Entry::Vacant(slot) => {
                slot.insert(ReceiveEntry {
                    entry,
                    retry_key: Some(key),
                    replay: false,
                    turn: None,
                });
            }
            Entry::Occupied(mut slot) => {
                if slot.get().retry_key.is_none() {
                    slot.get_mut().retry_key = Some(key);
                }
            }
        }
    }
    for bytes in db.unrouted_entries()? {
        let entry: GatewayInboxEntry = serde_json::from_slice(&bytes)?;
        retries.entry(entry_id(&entry)).or_insert_with(|| ReceiveEntry {
            entry,
            retry_key: None,
            replay: false,
            turn: None,
        });
    }
    for (key, entry) in crate::bus::couriers::head_refresh::inbound::entries(account) {
        if !db.has_inbox_retry(key)? {
            continue;
        }
        match retries.entry(entry_id(entry)) {
            Entry::Vacant(slot) => {
                slot.insert(ReceiveEntry {
                    entry: entry.clone(),
                    retry_key: Some(key.clone()),
                    replay: false,
                    turn: None,
                });
            }
            Entry::Occupied(mut slot) => {
                if slot.get().retry_key.is_none() {
                    slot.get_mut().retry_key = Some(key.clone());
                }
            }
        }
    }
    Ok(())
}

async fn resume_one(
    account: &LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    after: u64,
    limit: usize,
) -> Result<ResumePage, SdkError> {
    let use_push = match account.bound_session_mode() {
        Some(mode) => mode.is_push(),
        None => apply_w1::is_active(account.client.account_db()?, &account.target_delivery_id)?,
    };
    if use_push {
        return match engine.resume_page(after, limit).await? {
            PageReply::Page(page) => Ok(*page),
            PageReply::Refused(reason) => Err(SdkError::GatewaySessionRejected(format!(
                "resume_page refused: {}",
                reason.as_str()
            ))),
        };
    }
    let entries = engine.resume_after(after, limit).await?;
    Ok(legacy_page(after, limit, entries))
}

fn legacy_page(after: u64, limit: usize, entries: Vec<GatewayInboxEntry>) -> ResumePage {
    use crate::bus::push_receiver::compat::fallback_deadline;
    let entries: Vec<GatewayInboxEntry> =
        entries.into_iter().filter(|entry| entry.inbox_seq > after).take(limit).collect();
    let high = entries.iter().map(|entry| entry.inbox_seq).max().unwrap_or(after);
    let more = !entries.is_empty() && entries.len() == limit;
    let covered = high;
    let issued = if more { covered.saturating_add(1) } else { covered };
    let first_seen = now_unix_timestamp();
    ResumePage {
        after_inbox_seq: after,
        covered_through_seq: covered,
        issued_inbox_seq: issued,
        settled_through_seq: covered,
        entries: entries
            .into_iter()
            .map(|entry| {
                let ttl = i64::from(entry.envelope.ttl);
                let deadline = fallback_deadline(entry.envelope.created_at, ttl, first_seen, None)
                    .unwrap_or(crate::bus::push_receiver::compat::FallbackDeadline {
                        expires_at: 0,
                        fallback_clock_unverified: true,
                        guaranteed_retirement: false,
                    });
                PageEntryRecord { retain_until: deadline.expires_at, entry }
            })
            .collect(),
        known_losses: Vec::new(),
        oversize_next: None,
        more,
    }
}

enum PageDrive {
    Paused { applied: usize },
    Continue { backpressure: Box<Backpressure>, applied: usize },
}

/// W0 `scan_cursor` redrive of a held contact floor behind C. `replay: true`
/// bypasses `apply_owned` `AlreadyCovered` of the live page.
#[allow(clippy::too_many_arguments, reason = "standalone floor redrive shares the live handles")]
async fn redrive_held_floor(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    turn: &mut ReceiveTurn,
    generation: u64,
    mut backpressure: Box<Backpressure>,
    mut applied: usize,
    envelope_ids: &mut BTreeMap<u64, String>,
    now: i64,
) -> Result<(Box<Backpressure>, usize), SdkError> {
    let walk = account.client.gateway_receive_cursor(&account.target_delivery_id)?;
    let Some((cursor, until)) = backpressure.scan_cursor(&account.client, walk, now)? else {
        return Ok((backpressure, applied));
    };
    let mut page = resume_one(account, engine, cursor, PAGE_LIMIT).await?;
    let count = page.entries.len();
    page.entries.retain(|record| record.entry.inbox_seq <= until);
    let last = page.entries.iter().map(|record| record.entry.inbox_seq).max();
    for record in &page.entries {
        if backpressure.saturated(&account.client, &record.entry, now)? {
            continue;
        }
        envelope_ids
            .entry(record.entry.inbox_seq)
            .or_insert_with(|| record.entry.envelope.envelope_id.clone());
        let prepared = ReceiveEntry {
            entry: record.entry.clone(),
            retry_key: None,
            replay: true,
            turn: Some(turn.clone()),
        };
        let handle_generation = || generation;
        let (_, next) =
            apply_w1::apply_page(account, turn, &handle_generation, prepared, None, backpressure)
                .await?;
        apply_w1::replay_projected(account)?;
        backpressure = next;
        applied = applied.saturating_add(1);
        apply_w1::refresh_cursor(account.client.account_db()?, turn)?;
        ack_if_terminal(
            account,
            engine,
            generation,
            &record.entry,
            record.entry.inbox_seq,
            None,
            &backpressure,
            envelope_ids,
        )
        .await?;
    }
    backpressure.scanned(&account.client, last, count, now)?;
    Ok((backpressure, applied))
}

#[allow(clippy::too_many_arguments, reason = "standalone page drive shares the live handles")]
async fn drive_page(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    turn: &mut ReceiveTurn,
    generation: u64,
    page: &ResumePage,
    retries: &mut BTreeMap<(String, u64, String), ReceiveEntry>,
    mut backpressure: Box<Backpressure>,
    mut applied: usize,
    envelope_ids: &mut BTreeMap<u64, String>,
) -> Result<PageDrive, SdkError> {
    let records = page.entries.clone();
    loop {
        let outcome = apply_owned(account, turn, generation, page)?;
        match outcome {
            ApplyOutcome::Covered { cursor } | ApplyOutcome::AlreadyCovered { cursor } => {
                for row in &records {
                    envelope_ids
                        .entry(row.entry.inbox_seq)
                        .or_insert_with(|| row.entry.envelope.envelope_id.clone());
                }
                let high = records
                    .iter()
                    .map(|row| row.entry.inbox_seq)
                    .max()
                    .unwrap_or(page.covered_through_seq);
                apply_w1::map_page_outcome(outcome, high)?;
                turn.cursor = cursor;
                break;
            }
            ApplyOutcome::Paused { cursor } => {
                turn.cursor = cursor;
                return Ok(PageDrive::Paused { applied });
            }
            ApplyOutcome::NeedStage { sequence, cursor } => {
                turn.cursor = cursor;
                let record = records.iter().find(|row| row.entry.inbox_seq == sequence).ok_or(
                    SdkError::InboundRejected("receive page need-stage missing entry".into()),
                )?;
                let retry_key = take_page_retry(retries, &record.entry);
                let entry = ReceiveEntry {
                    entry: record.entry.clone(),
                    retry_key: retry_key.clone(),
                    replay: false,
                    turn: Some(turn.clone()),
                };
                let handle_generation = || generation;
                envelope_ids
                    .entry(sequence)
                    .or_insert_with(|| record.entry.envelope.envelope_id.clone());
                let (_, next) = apply_w1::apply_page(
                    account,
                    turn,
                    &handle_generation,
                    entry,
                    None,
                    backpressure,
                )
                .await?;
                apply_w1::replay_projected(account)?;
                backpressure = next;
                applied = applied.saturating_add(1);
                apply_w1::refresh_cursor(account.client.account_db()?, turn)?;
                ack_if_terminal(
                    account,
                    engine,
                    generation,
                    &record.entry,
                    sequence,
                    retry_key.as_deref(),
                    &backpressure,
                    envelope_ids,
                )
                .await?;
            }
            ApplyOutcome::NeedFetch { after } => {
                turn.cursor = after;
                backpressure = cover_point(
                    account,
                    engine,
                    turn,
                    generation,
                    after.saturating_add(1),
                    backpressure,
                )
                .await?;
            }
            ApplyOutcome::NeedPoint { seq, cursor } => {
                turn.cursor = cursor;
                backpressure =
                    cover_point(account, engine, turn, generation, seq, backpressure).await?;
            }
        }
    }
    Ok(PageDrive::Continue { backpressure, applied })
}

fn take_page_retry(
    retries: &mut BTreeMap<(String, u64, String), ReceiveEntry>,
    entry: &crate::GatewayInboxEntry,
) -> Option<String> {
    retries.remove(&entry_id(entry)).and_then(|prepared| prepared.retry_key)
}

#[allow(clippy::too_many_arguments, reason = "standalone leftover apply shares the live handles")]
async fn apply_leftover(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    turn: &mut ReceiveTurn,
    generation: u64,
    retries: BTreeMap<(String, u64, String), ReceiveEntry>,
    mut backpressure: Box<Backpressure>,
    mut applied: usize,
    envelope_ids: &mut BTreeMap<u64, String>,
) -> Result<usize, SdkError> {
    let mut leftover: Vec<_> = retries.into_values().collect();
    leftover.sort_by_key(|entry| entry.entry.inbox_seq);
    crate::bus::connection_manager::receive::bind_retry_turns(&mut leftover, Some(turn));
    for mut prepared in leftover {
        envelope_ids
            .entry(prepared.entry.inbox_seq)
            .or_insert_with(|| prepared.entry.envelope.envelope_id.clone());
        let entry = prepared.entry.clone();
        let retry_key = prepared.retry_key.clone();
        prepared.turn = Some(turn.clone());
        let handle_generation = || generation;
        let (_, next) =
            apply_w1::apply_page(account, turn, &handle_generation, prepared, None, backpressure)
                .await?;
        apply_w1::replay_projected(account)?;
        backpressure = next;
        applied = applied.saturating_add(1);
        apply_w1::refresh_cursor(account.client.account_db()?, turn)?;
        ack_if_terminal(
            account,
            engine,
            generation,
            &entry,
            entry.inbox_seq,
            retry_key.as_deref(),
            &backpressure,
            envelope_ids,
        )
        .await?;
    }
    Ok(applied)
}

/// Gateway ACK only after a terminal cover: contact floors and inbox retries
/// keep the ciphertext (W0 ACK-after-commit). A stripped leftover payload hashes
/// to a different admission key, so the planted retry key is checked first.
#[allow(clippy::too_many_arguments, reason = "standalone ACK shares the live page handles")]
async fn ack_if_terminal(
    account: &LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    generation: u64,
    entry: &GatewayInboxEntry,
    sequence: u64,
    retry_key: Option<&str>,
    backpressure: &Backpressure,
    envelope_ids: &BTreeMap<u64, String>,
) -> Result<(), SdkError> {
    if backpressure.holds(entry) {
        return Ok(());
    }
    let db = account.client.account_db()?;
    if let Some(key) = retry_key
        && db.has_inbox_retry(key)?
    {
        return Ok(());
    }
    let key = account.client.inbox_admission_key(entry)?;
    if db.has_inbox_retry(&key)? {
        return Ok(());
    }
    emit_engine_ack(account, engine, generation, sequence, envelope_ids).await
}

/// Emit one gateway ACK and settle the WA intent. Held contact floors skip this
/// so the ciphertext stays on the wire; remaining intents still flush at the
/// end of the pass.
async fn emit_engine_ack(
    account: &LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    generation: u64,
    sequence: u64,
    envelope_ids: &BTreeMap<u64, String>,
) -> Result<(), SdkError> {
    let Some(envelope_id) = envelope_ids.get(&sequence) else {
        return Ok(());
    };
    let receiver = account.client.owned_device_identity()?;
    let now = now_unix_timestamp();
    let mut ack = crate::dm::gateway_ack(envelope_id, &receiver, now);
    ack.ext.ext.insert("inbox_seq".into(), json!(sequence));
    let outcome = if engine.ack(ack).await.is_ok() {
        ramflux_storage::ReceiveAckOutcome::Acked
    } else {
        ramflux_storage::ReceiveAckOutcome::Uncertain
    };
    let db = account.client.account_db()?;
    let target = account.target_delivery_id.as_str();
    if !apply_w1::is_active(db, target)? {
        return Ok(());
    }
    let turn = apply_w1::capture_turn(db, generation, target)?;
    let wa =
        crate::bus::push_receiver::ack_batch::SourceWa { expected: turn.expected(), generation };
    let input = ramflux_storage::ReceiveAckApply {
        incarnation: &turn.incarnation,
        sequences: &[sequence],
        results: &[ramflux_storage::ReceiveAckResult { sequence, outcome }],
        now,
    };
    if let Err(error) = wa.apply(db, input) {
        tracing::debug!(sequence, %error, "standalone ACK settle deferred");
    }
    Ok(())
}

async fn flush_live_acks(
    account: &LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    generation: u64,
    envelope_ids: &BTreeMap<u64, String>,
) -> Result<(), SdkError> {
    if let Some((handle, work)) = (account.connection.clone()).zip(account.connection_work.clone())
    {
        return crate::bus::connection_manager::receive::flush_acks(
            &handle,
            &work,
            generation,
            true,
            account.timeouts.call,
        )
        .await;
    }
    flush_engine_acks(account, engine, generation, envelope_ids).await
}

async fn flush_engine_acks(
    account: &LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    generation: u64,
    envelope_ids: &BTreeMap<u64, String>,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let target = account.target_delivery_id.as_str();
    if !apply_w1::is_active(db, target)? {
        return Ok(());
    }
    let turn = apply_w1::capture_turn(db, generation, target)?;
    let wa =
        crate::bus::push_receiver::ack_batch::SourceWa { expected: turn.expected(), generation };
    let now = now_unix_timestamp();
    let sequences = wa.select(db, now, true)?;
    if sequences.is_empty() {
        return Ok(());
    }
    let receiver = account.client.owned_device_identity()?;
    let mut sent = Vec::new();
    let mut results = Vec::new();
    for seq in sequences {
        let envelope_id = envelope_ids
            .get(&seq)
            .cloned()
            .or_else(|| {
                account
                    .pending_deliveries
                    .iter()
                    .find(|entry| entry.inbox_seq == seq)
                    .map(|entry| entry.envelope.envelope_id.clone())
            })
            .or_else(|| db.ack_envelope_id(target, &turn.incarnation, seq).ok().flatten());
        let Some(envelope_id) = envelope_id else {
            continue;
        };
        let mut ack = crate::dm::gateway_ack(&envelope_id, &receiver, now);
        ack.ext.ext.insert("inbox_seq".into(), json!(seq));
        let outcome = if engine.ack(ack).await.is_ok() {
            ramflux_storage::ReceiveAckOutcome::Acked
        } else {
            tracing::debug!(seq, "standalone ACK remains pending after transport failure");
            ramflux_storage::ReceiveAckOutcome::Uncertain
        };
        sent.push(seq);
        results.push(ramflux_storage::ReceiveAckResult { sequence: seq, outcome });
    }
    if sent.is_empty() {
        return Ok(());
    }
    let input = ramflux_storage::ReceiveAckApply {
        incarnation: &turn.incarnation,
        sequences: &sent,
        results: &results,
        now,
    };
    let _ = wa.apply(db, input)?;
    Ok(())
}

fn apply_owned(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    generation: u64,
    page: &ResumePage,
) -> Result<ApplyOutcome, SdkError> {
    let seqs: Vec<u64> = page.entries.iter().map(|row| row.entry.inbox_seq).collect();
    let reasons: Vec<&'static str> =
        page.known_losses.iter().map(|loss| loss.reason.as_str()).collect();
    let losses: Vec<ApplyLoss<'_>> = page
        .known_losses
        .iter()
        .zip(reasons.iter())
        .map(|(loss, reason)| ApplyLoss { from_seq: loss.from_seq, to_seq: loss.to_seq, reason })
        .collect();
    match apply::apply_page(
        account.client.account_db()?,
        turn.expected(),
        generation,
        ApplyPage {
            target: &turn.target,
            incarnation: &turn.incarnation,
            after: page.after_inbox_seq,
            covered: page.covered_through_seq,
            issued: page.issued_inbox_seq,
            settled: page.settled_through_seq,
            entries: &seqs,
            known_losses: &losses,
            oversize_next: page.oversize_next,
            more: page.more,
        },
    ) {
        Ok(outcome) => Ok(outcome),
        Err(apply::ApplyError::Protocol(text)) => Err(SdkError::InboundRejected(text.into())),
        Err(apply::ApplyError::Storage(error)) => Err(error.into()),
    }
}

async fn cover_point(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewayPushAccess,
    turn: &mut ReceiveTurn,
    generation: u64,
    seq: u64,
    backpressure: Box<Backpressure>,
) -> Result<Box<Backpressure>, SdkError> {
    let reply = engine.fetch_entry(seq).await?;
    let target = turn.target.clone();
    let incarnation = turn.incarnation.clone();
    let gone_reason;
    let fetched = match &reply {
        PointReply::Entry(record) => Some(record.entry.clone()),
        _ => None,
    };
    let point = match &reply {
        PointReply::Entry(record) => ApplyPoint::Entry {
            seq: record.entry.inbox_seq,
            target: &target,
            incarnation: &incarnation,
        },
        PointReply::TooLarge { retain_until } => {
            ApplyPoint::TooLarge { seq, retain_until: *retain_until, incarnation: &incarnation }
        }
        PointReply::Gone { observed_issued_inbox_seq, reason } => {
            gone_reason = reason.as_str();
            ApplyPoint::Gone {
                seq,
                observed_issued: *observed_issued_inbox_seq,
                reason: gone_reason,
                incarnation: &incarnation,
            }
        }
        PointReply::Refused(reason) => {
            return Err(SdkError::GatewaySessionRejected(format!(
                "fetch_entry refused: {}",
                reason.as_str()
            )));
        }
    };
    let outcome = match apply::apply_point(
        account.client.account_db()?,
        turn.expected(),
        generation,
        seq,
        point,
    ) {
        Ok(outcome) => apply_w1::map_page_outcome(outcome, seq)?,
        Err(apply::ApplyError::Protocol(text)) => {
            return Err(SdkError::InboundRejected(text.into()));
        }
        Err(apply::ApplyError::Storage(error)) => return Err(error.into()),
    };
    match outcome {
        ApplyOutcome::NeedStage { sequence, cursor } if sequence == seq => {
            turn.cursor = cursor;
            let Some(entry) = fetched else {
                return Err(SdkError::InboundRejected(
                    "receive point need-stage missing entry".into(),
                ));
            };
            let handle_generation = || generation;
            let (_, next) = apply_w1::apply_page(
                account,
                turn,
                &handle_generation,
                ReceiveEntry { entry, retry_key: None, replay: false, turn: Some(turn.clone()) },
                None,
                backpressure,
            )
            .await?;
            apply_w1::replay_projected(account)?;
            apply_w1::refresh_cursor(account.client.account_db()?, turn)?;
            Ok(next)
        }
        ApplyOutcome::Covered { cursor }
        | ApplyOutcome::AlreadyCovered { cursor }
        | ApplyOutcome::Paused { cursor }
        | ApplyOutcome::NeedStage { cursor, .. }
        | ApplyOutcome::NeedPoint { cursor, .. }
        | ApplyOutcome::NeedFetch { after: cursor } => {
            turn.cursor = cursor;
            Ok(backpressure)
        }
    }
}

#[cfg(test)]
mod retry_key_tests {
    use super::*;
    use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};

    fn inbox(seq: u64) -> crate::GatewayInboxEntry {
        crate::GatewayInboxEntry {
            forwarded: false,
            inbox_seq: seq,
            target_delivery_id: "t".into(),
            envelope: Envelope {
                schema: "ramflux.envelope.v1".into(),
                version: 1,
                domain: "test".into(),
                ext: Ext::default(),
                signed: SignedFields {
                    signing_key_id: "key".into(),
                    signature_alg: SignatureAlg::Ed25519,
                    signature: "sig".into(),
                },
                envelope_id: format!("env-{seq}"),
                source_principal_id: "source".into(),
                source_device_id: "device".into(),
                target_delivery_id: "t".into(),
                routing_set_id: None,
                delivery_class: DeliveryClass::OpaqueEvent,
                priority: Priority::Normal,
                ttl: 60,
                created_at: 1,
                encrypted_payload: "cipher".into(),
                payload_hash: "hash".into(),
                delivery_mode: None,
                collapse_tag: None,
                report_commitment: None,
            },
        }
    }

    #[test]
    fn page_served_retry_keeps_key() {
        let entry = inbox(1);
        let mut retries = BTreeMap::from([(
            entry_id(&entry),
            ReceiveEntry {
                entry: entry.clone(),
                retry_key: Some("retry-1".into()),
                replay: false,
                turn: None,
            },
        )]);
        assert_eq!(take_page_retry(&mut retries, &entry).as_deref(), Some("retry-1"));
        assert_eq!(retries.len(), 0, "page-served retry must not remain as leftover");
    }

    #[test]
    fn unknown_page_entry_has_no_retry_key() {
        let entry = inbox(2);
        let mut retries = BTreeMap::new();
        assert_eq!(take_page_retry(&mut retries, &entry), None);
    }
}
