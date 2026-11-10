// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account receive scheduling uses only ticks, connection establishment, and explicit resync.

#[path = "receive_ledger.rs"]
mod receive_ledger;

use super::{
    AccountWork, AckFlushReply, AckFlushResults, ConnectionHandle, NetworkingState, ReceiveTurn,
    RuntimeTimeouts,
};
use crate::SdkError;
use crate::gateway::push_point::BatchReply;
use crate::gateway::session_push::{AckOutcome, AckResult};
use ramflux_storage::{ReceiveAckOutcome, ReceiveAckResult};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, timeout},
};

/// Catch-up page size (§7).
pub(crate) const RECEIVE_PAGE_LIMIT: usize = 64;
/// Catch-up pages before the receive child yields so other accounts run (§7).
pub(crate) const RECEIVE_YIELD_AFTER_PAGES: u32 = 16;

/// True when this catch-up has taken 16 pages and must yield.
#[must_use]
pub(crate) const fn catch_up_yields(pages: u32) -> bool {
    pages >= RECEIVE_YIELD_AFTER_PAGES
}

pub(crate) struct ReceivePlan {
    pub cursor: u64,
    pub limit: usize,
    pub retries: Vec<ReceiveEntry>,
    pub backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
    /// Prepare-time fence coordinates. `Some` when the receive ledger is active.
    pub turn: Option<ReceiveTurn>,
}
pub(crate) type ReceiveApplied = (
    Option<crate::bus::sync_driver::PreparedAck>,
    Box<crate::bus::contact_backpressure::Backpressure>,
);
pub(crate) type ReceiveAcked = (bool, Box<crate::bus::contact_backpressure::Backpressure>);
#[derive(Clone)]
pub(crate) struct ReceiveEntry {
    pub entry: crate::GatewayInboxEntry,
    pub retry_key: Option<String>,
    pub replay: bool,
    /// Prepare-time fence coordinates cloned from `ReceivePlan` when the ledger is active.
    pub turn: Option<ReceiveTurn>,
}

/// Retries keep prepare-time E and erasure generation. Cursor is refreshed per `ApplyPage`.
pub(crate) fn bind_retry_turn(entry: &mut ReceiveEntry, pass_turn: Option<&ReceiveTurn>) {
    if entry.turn.is_none() {
        entry.turn = pass_turn.cloned();
    }
}

/// `pass` binds every leftover retry with the prepare-time turn before `apply_entry`.
pub(crate) fn bind_retry_turns(retries: &mut [ReceiveEntry], pass_turn: Option<&ReceiveTurn>) {
    for entry in retries {
        bind_retry_turn(entry, pass_turn);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiveTrigger {
    Tick,
    Connected,
    Resync,
}

pub(super) async fn run(
    handle: ConnectionHandle,
    work: mpsc::Sender<AccountWork>,
    limits: RuntimeTimeouts,
) {
    let mut stop = handle.stop.subscribe();
    let mut interval = limits.receive_min;
    let mut next = Instant::now() + interval;
    let mut connected_generation = None;
    loop {
        let tick = tokio::select! {biased;_=stop.changed()=>break,()=handle.receive_wake()=>false,()=tokio::time::sleep_until(next)=>true};
        let snapshot = handle.snapshot();
        if snapshot.state != NetworkingState::Live {
            interval = interval.saturating_mul(2).min(limits.receive_max);
            next = Instant::now() + interval;
            continue;
        }
        let trigger = if connected_generation != Some(snapshot.generation) {
            ReceiveTrigger::Connected
        } else if handle.resync_needed() {
            ReceiveTrigger::Resync
        } else if tick {
            ReceiveTrigger::Tick
        } else {
            continue;
        };
        tracing::trace!(?trigger, generation = snapshot.generation, "account receive pass");
        #[cfg(test)]
        handle
            .shared
            .receive_trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((trigger, false));
        let epoch = handle.resync_epoch();
        let pass =
            timeout(limits.sync, pass(&handle, &work, snapshot.generation, trigger, limits.call));
        let result = tokio::select! {biased;_=stop.changed()=>break,result=pass=>result};
        connected_generation = Some(snapshot.generation);
        match result {
            Ok(Ok(active)) => {
                handle.resync_applied(snapshot.generation, epoch);
                #[cfg(test)]
                handle
                    .shared
                    .receive_trace
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((trigger, true));
                #[cfg(test)]
                handle.shared.receive_completed.notify_one();
                interval = if active {
                    limits.receive_min
                } else {
                    interval.saturating_mul(2).min(limits.receive_max)
                };
            }
            Ok(Err(error)) => {
                tracing::debug!(%error,"receive pass deferred");
                interval = interval.saturating_mul(2).min(limits.receive_max);
            }
            Err(_) => {
                tracing::debug!("receive pass deadline expired");
                interval = interval.saturating_mul(2).min(limits.receive_max);
            }
        }
        next = Instant::now() + interval;
    }
}

/// Candidate P23 loop: Connected catch-up within 100 ms, then an anchored sweep.
/// Activated sessions (`session_push_advertise`) run this in place of [`run`].
pub(crate) async fn run_anchored(
    handle: ConnectionHandle,
    work: mpsc::Sender<AccountWork>,
    limits: RuntimeTimeouts,
    setting: crate::bus::push_receiver::sweep::SweepSetting,
    mut mode: crate::bus::push_receiver::sweep::SweepMode,
) {
    use crate::bus::push_receiver::sweep::{Planner, SweepMode};
    let mut stop = handle.stop.subscribe();
    let mut planner = Planner::new(&setting, mode);
    let mut mode_locked = false;
    let origin = handle.receive_origin();
    loop {
        let snapshot = handle.snapshot();
        if snapshot.state == NetworkingState::Live && !mode_locked {
            let next = if handle.session_is_push() { SweepMode::Push } else { SweepMode::Compat };
            if next != mode {
                mode = next;
                planner = Planner::new(&setting, mode);
            }
            mode_locked = true;
        }
        let now_ms = handle.receive_now_ms();
        let view = crate::bus::push_receiver::sweep::View {
            live: snapshot.state == NetworkingState::Live,
            generation: snapshot.generation,
            resync: handle.resync_needed(),
        };
        let resume = planner.decide(now_ms, view);
        if let Some(kind) = resume {
            if handle.reorder().in_flight() {
                handle.reorder().note_hint(hint_of(kind));
            }
            let trigger = trigger_of(Some(kind));
            match Box::pin(run_one_anchored(
                &handle,
                &work,
                &limits,
                snapshot.generation,
                trigger,
                &mut stop,
            ))
            .await
            {
                None => break,
                Some((ok, paused)) => {
                    let finished_ms = handle.receive_now_ms();
                    handle.reorder().finish_catch_up(finished_ms);
                    if ok {
                        handle.note_catch_up_finished(finished_ms);
                    }
                    planner.finish(now_ms, finished_ms, snapshot.generation, ok, paused);
                }
            }
            continue;
        }
        if reorder_catch_up_due(&handle, now_ms) {
            let Some(_) = Box::pin(run_one_anchored(
                &handle,
                &work,
                &limits,
                snapshot.generation,
                ReceiveTrigger::Tick,
                &mut stop,
            ))
            .await
            else {
                break;
            };
            let finished_ms = handle.receive_now_ms();
            handle.reorder().finish_catch_up(finished_ms);
            continue;
        }
        let wait = anchored_wait(&handle, origin, now_ms, &planner, snapshot.state);
        tokio::select! {biased;
            _ = stop.changed() => break,
            () = handle.receive_wake() => {}
            () = async {
                match wait {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
}

fn hint_of(
    kind: crate::bus::push_receiver::sweep::ResumeKind,
) -> crate::bus::push_receiver::reorder::CatchUpHint {
    use crate::bus::push_receiver::reorder::CatchUpHint;
    use crate::bus::push_receiver::sweep::ResumeKind;
    match kind {
        ResumeKind::Connected => CatchUpHint::Connected,
        ResumeKind::Sweep => CatchUpHint::SafetySweep,
        ResumeKind::Resync => CatchUpHint::Resync,
    }
}

fn trigger_of(kind: Option<crate::bus::push_receiver::sweep::ResumeKind>) -> ReceiveTrigger {
    use crate::bus::push_receiver::sweep::ResumeKind;
    match kind {
        Some(ResumeKind::Connected) => ReceiveTrigger::Connected,
        Some(ResumeKind::Resync) => ReceiveTrigger::Resync,
        Some(ResumeKind::Sweep) | None => ReceiveTrigger::Tick,
    }
}

fn reorder_catch_up_due(handle: &ConnectionHandle, now_ms: u64) -> bool {
    matches!(
        handle.reorder().tick(now_ms),
        crate::bus::push_receiver::reorder::Tick::CatchUp { .. }
    )
}

fn anchored_wait(
    handle: &ConnectionHandle,
    origin: Instant,
    now_ms: u64,
    planner: &crate::bus::push_receiver::sweep::Planner,
    state: NetworkingState,
) -> Option<Instant> {
    if state != NetworkingState::Live {
        return None;
    }
    let planner_at = planner.wake_at_ms(now_ms);
    let gap_at = handle.reorder().gap_deadline_ms();
    planner_at
        .into_iter()
        .chain(gap_at)
        .min()
        .and_then(|ms| origin.checked_add(std::time::Duration::from_millis(ms)))
}

async fn run_one_anchored(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    limits: &RuntimeTimeouts,
    generation: u64,
    trigger: ReceiveTrigger,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) -> Option<(bool, bool)> {
    tracing::trace!(?trigger, generation, "account receive pass");
    #[cfg(test)]
    handle
        .shared
        .receive_trace
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((trigger, false));
    let epoch = handle.resync_epoch();
    let pass = timeout(limits.sync, pass_anchored(handle, work, generation, trigger, limits.call));
    let result = tokio::select! {
        biased;
        _ = stop.changed() => {
            #[cfg(test)]
            {
                *handle
                    .shared
                    .receive_last_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some("receive pass stopped".into());
            }
            return None;
        }
        result = pass => result
    };
    let (ok, paused) = match &result {
        Ok(Ok((_, paused))) => (true, *paused),
        _ => (false, false),
    };
    match result {
        Ok(Ok(_)) => {
            handle.resync_applied(generation, epoch);
            #[cfg(test)]
            handle
                .shared
                .receive_trace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((trigger, true));
            #[cfg(test)]
            handle.shared.receive_completed.notify_one();
        }
        Ok(Err(error)) => {
            tracing::debug!(%error, "receive pass deferred");
            #[cfg(test)]
            {
                *handle
                    .shared
                    .receive_last_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error.to_string());
            }
        }
        Err(_) => {
            tracing::debug!("receive pass deadline expired");
            #[cfg(test)]
            {
                *handle
                    .shared
                    .receive_last_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some("receive pass deadline expired".into());
            }
        }
    }
    Some((ok, paused))
}

async fn pass(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    trigger: ReceiveTrigger,
    call_timeout: std::time::Duration,
) -> Result<bool, SdkError> {
    let (active, _, backpressure) =
        Box::pin(catch_up(handle, work, generation, trigger, call_timeout)).await?;
    let (more, _) = rescan(handle, work, generation, call_timeout, backpressure).await?;
    Ok(active || more)
}

/// Candidate catch-up: same Resume pages as live, without the contact-floor rescan.
async fn pass_anchored(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    trigger: ReceiveTrigger,
    call_timeout: std::time::Duration,
) -> Result<(bool, bool), SdkError> {
    let (active, paused, _) =
        Box::pin(catch_up(handle, work, generation, trigger, call_timeout)).await?;
    Ok((active, paused))
}

async fn catch_up(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    trigger: ReceiveTrigger,
    call_timeout: std::time::Duration,
) -> Result<(bool, bool, Box<crate::bus::contact_backpressure::Backpressure>), SdkError> {
    let (reply, response) = oneshot::channel();
    work.send(AccountWork::PrepareReceive { generation, trigger, reply })
        .await
        .map_err(|_| handle.pending())?;
    let plan = response.await.map_err(|_| handle.pending())??;
    let mut cursor = plan.cursor;
    let mut backpressure = plan.backpressure;
    let turn = plan.turn;
    if let Some(turn) = turn.clone() {
        let done = Box::pin(receive_ledger::catch_up_ledger(receive_ledger::CatchUp {
            handle,
            work,
            generation,
            trigger,
            call_timeout,
            turn,
            cursor,
            backpressure,
            retries: plan.retries,
            limit: plan.limit.min(RECEIVE_PAGE_LIMIT),
        }))
        .await?;
        return Ok((done.active, done.paused, done.backpressure));
    }
    let mut retries: std::collections::BTreeMap<_, _> =
        plan.retries.into_iter().map(|prepared| (entry_id(&prepared.entry), prepared)).collect();
    let mut active = false;
    let limit = plan.limit.min(RECEIVE_PAGE_LIMIT);
    let mut pages = 0_u32;
    loop {
        let entries = handle
            .call(
                move |engine| Box::pin(engine.resume_authoritative_after(cursor, limit)),
                Instant::now() + call_timeout,
            )
            .await?;
        let count = entries.len();
        let last = entries.iter().map(|entry| entry.inbox_seq).max().unwrap_or(cursor);
        for entry in entries {
            let retry_key =
                retries.remove(&entry_id(&entry)).and_then(|prepared| prepared.retry_key);
            let (accepted, next) = apply_entry(
                handle,
                work,
                generation,
                ReceiveEntry { entry, retry_key, replay: false, turn: turn.clone() },
                call_timeout,
                backpressure,
            )
            .await?;
            active |= accepted;
            backpressure = next;
        }
        pages = pages.saturating_add(1);
        if catch_up_yields(pages) {
            handle.note_catch_up_yield();
            tokio::task::yield_now().await;
            pages = 0;
        }
        // A gateway can return a short page at its byte limit. Only an empty page
        // (or a non-advancing cursor) proves this bounded pass has caught up.
        if count == 0 || last <= cursor {
            break;
        }
        cursor = last;
    }
    let mut retries: Vec<_> = retries.into_values().collect();
    retries.sort_by_key(|entry| entry.entry.inbox_seq);
    bind_retry_turns(&mut retries, turn.as_ref());
    for entry in retries {
        let (accepted, next) =
            apply_entry(handle, work, generation, entry, call_timeout, backpressure).await?;
        active |= accepted;
        backpressure = next;
    }
    Ok((active, false, backpressure))
}

/// Test entry to `catch_up` with an explicit trigger (Tick does not force the 16/1s gate).
#[cfg(test)]
pub(crate) async fn test_catch_up(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    trigger: ReceiveTrigger,
    call_timeout: std::time::Duration,
) -> Result<(bool, Box<crate::bus::contact_backpressure::Backpressure>), SdkError> {
    let (active, _, backpressure) =
        Box::pin(catch_up(handle, work, generation, trigger, call_timeout)).await?;
    Ok((active, backpressure))
}

/// Test entry to the full `pass` (catch-up + rescan).
#[cfg(test)]
pub(crate) async fn test_pass(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    trigger: ReceiveTrigger,
    call_timeout: std::time::Duration,
) -> Result<bool, SdkError> {
    Box::pin(pass(handle, work, generation, trigger, call_timeout)).await
}

/// Test entry to the activated `pass_anchored` (pages only; no contact-floor rescan).
#[cfg(test)]
pub(crate) async fn test_pass_anchored(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    trigger: ReceiveTrigger,
    call_timeout: std::time::Duration,
) -> Result<(bool, bool), SdkError> {
    Box::pin(pass_anchored(handle, work, generation, trigger, call_timeout)).await
}

/// Contact capacity can leave an unacknowledged range behind the live cursor. Redrive one
/// bounded page with the same durable floor and per-pass root deduplication as normal receive.
async fn rescan(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    call_timeout: std::time::Duration,
    mut backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
) -> Result<ReceiveAcked, SdkError> {
    let writer = crate::bus::couriers::writer::Writer::new(work.clone(), generation);
    let (scan, next) = writer
        .apply(move |account| {
            let walk = account.client.gateway_receive_cursor(&account.target_delivery_id)?;
            let scan = backpressure.scan_cursor(
                &account.client,
                walk,
                crate::time::now_unix_timestamp(),
            )?;
            Ok((scan, backpressure))
        })
        .await?;
    backpressure = next;
    let Some((cursor, until)) = scan else { return Ok((false, backpressure)) };
    let mut page = handle
        .call(
            move |engine| Box::pin(engine.resume_authoritative_after(cursor, RECEIVE_PAGE_LIMIT)),
            Instant::now() + call_timeout,
        )
        .await?;
    let count = page.len();
    page.retain(|entry| entry.inbox_seq <= until);
    let last = page.iter().map(|entry| entry.inbox_seq).max();
    let mut active = false;
    for entry in page {
        let (accepted, next) = apply_entry(
            handle,
            work,
            generation,
            ReceiveEntry { entry, retry_key: None, replay: true, turn: None },
            call_timeout,
            backpressure,
        )
        .await?;
        active |= accepted;
        backpressure = next;
    }
    writer
        .apply(move |account| {
            backpressure.scanned(
                &account.client,
                last,
                count,
                crate::time::now_unix_timestamp(),
            )?;
            Ok((active, backpressure))
        })
        .await
}

pub(crate) fn entry_id(entry: &crate::GatewayInboxEntry) -> (String, u64, String) {
    (entry.envelope.envelope_id.clone(), entry.inbox_seq, entry.envelope.payload_hash.clone())
}

pub(crate) async fn apply_entry(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    entry: ReceiveEntry,
    call_timeout: std::time::Duration,
    backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
) -> Result<ReceiveAcked, SdkError> {
    let writer = crate::bus::couriers::writer::Writer::new(work.clone(), generation);
    #[cfg(test)]
    let source_started = {
        handle.test_record_receive("source-start", std::time::Duration::ZERO);
        std::time::Instant::now()
    };
    let (entry, backpressure, source) =
        crate::bus::sync_driver::source::prepare(&writer, entry, backpressure).await?;
    #[cfg(test)]
    handle.test_record_receive("source", source_started.elapsed());
    let ledger = entry.turn.is_some();
    let (reply, response) = oneshot::channel();
    work.send(AccountWork::ApplyPage {
        generation,
        turn: entry.turn.clone().map(Box::new),
        entry: Box::new(entry),
        source,
        backpressure,
        reply,
    })
    .await
    .map_err(|_| handle.pending())?;
    let (prepared, backpressure) = response.await.map_err(|_| handle.pending())??;
    let pair_reply = prepared
        .as_ref()
        .and_then(|ack| ack.pair_reply.clone())
        .or_else(crate::bus::push_receiver::apply_w1::take_pair_reply);
    if let Some(envelope) = pair_reply {
        let submitted = handle
            .call(
                move |engine| Box::pin(engine.submit_envelope(envelope)),
                Instant::now() + call_timeout,
            )
            .await;
        if let Err(error) = submitted {
            tracing::debug!(%error, "encrypted reset acknowledgement awaits a later reset");
        }
    }
    if ledger {
        return Ok((true, backpressure));
    }
    let Some(prepared) = prepared else { return Ok((false, backpressure)) };
    ack_prepared(
        handle,
        work,
        generation,
        None,
        prepared.ack,
        prepared.state,
        backpressure,
        call_timeout,
    )
    .await
}

/// Select a due WA batch (16 / 1s / `force`), send `ack_batch` on a Push session, apply.
pub(crate) async fn flush_acks(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    force: bool,
    call_timeout: std::time::Duration,
) -> Result<(), SdkError> {
    let now = crate::time::now_unix_timestamp();
    let (reply, response) = oneshot::channel();
    work.send(AccountWork::AckFlush {
        generation,
        force,
        now,
        results: None,
        lookups: None,
        reply,
    })
    .await
    .map_err(|_| handle.pending())?;
    let selected = response.await.map_err(|_| handle.pending())??;
    let AckFlushReply::Selected { incarnation, mut sequences } = selected else {
        return Ok(());
    };
    {
        let buffer = handle.reorder();
        sequences.retain(|seq| !buffer.is_overflowed(*seq));
    }
    if sequences.is_empty() {
        return Ok(());
    }
    if !handle.session_is_push() {
        return flush_compat_acks(handle, work, generation, incarnation, sequences, call_timeout)
            .await;
    }
    let sent = sequences.clone();
    let batch = handle
        .call(move |engine| Box::pin(engine.ack_batch(sent)), Instant::now() + call_timeout)
        .await;
    let results = map_batch_results(&sequences, batch);
    apply_ack_results_flush(handle, work, generation, incarnation, sequences, results).await
}

async fn flush_compat_acks(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    incarnation: String,
    sequences: Vec<u64>,
    call_timeout: std::time::Duration,
) -> Result<(), SdkError> {
    use crate::bus::push_receiver::compat::{LOOKUP_LIMIT, OwnedLookup};
    let mut lookups = Vec::with_capacity(sequences.len());
    for &sequence in &sequences {
        let after = sequence.saturating_sub(1);
        let lookup = match handle
            .call(
                move |engine| Box::pin(engine.resume_after(after, LOOKUP_LIMIT as usize)),
                Instant::now() + call_timeout,
            )
            .await
        {
            Ok(entries) => match entries.first() {
                Some(entry) if entry.inbox_seq == sequence => OwnedLookup::Entry {
                    seq: sequence,
                    envelope_id: entry.envelope.envelope_id.clone(),
                    payload_hash: entry.envelope.payload_hash.clone(),
                    incarnation: None,
                },
                Some(entry) => OwnedLookup::Empty { first_seq: Some(entry.inbox_seq) },
                None => OwnedLookup::Empty { first_seq: None },
            },
            Err(_) => OwnedLookup::Timeout,
        };
        lookups.push((sequence, lookup));
    }
    let (reply, response) = oneshot::channel();
    work.send(AccountWork::AckFlush {
        generation,
        force: false,
        now: crate::time::now_unix_timestamp(),
        results: None,
        lookups: Some(lookups),
        reply,
    })
    .await
    .map_err(|_| handle.pending())?;
    let AckFlushReply::Authorized { plans } = response.await.map_err(|_| handle.pending())?? else {
        return Ok(());
    };
    let mut results = Vec::with_capacity(plans.len());
    let mut sent_seqs = Vec::with_capacity(plans.len());
    for plan in plans {
        sent_seqs.push(plan.sequence);
        let outcome = if let Some(envelope_id) = plan.envelope_id {
            match send_legacy_ack(handle, envelope_id, plan.sequence, call_timeout).await {
                Ok(()) => ramflux_storage::ReceiveAckOutcome::Acked,
                Err(_) => ramflux_storage::ReceiveAckOutcome::Uncertain,
            }
        } else {
            plan.outcome
        };
        results.push(ramflux_storage::ReceiveAckResult { sequence: plan.sequence, outcome });
    }
    apply_ack_results_flush(handle, work, generation, incarnation, sent_seqs, results).await
}

async fn send_legacy_ack(
    handle: &ConnectionHandle,
    envelope_id: String,
    sequence: u64,
    call_timeout: std::time::Duration,
) -> Result<(), SdkError> {
    let receiver = handle
        .metadata()
        .and_then(|meta| meta.config.source_identity)
        .ok_or(SdkError::IdentityRootMissing)?;
    let now = crate::time::now_unix_timestamp();
    let mut ack = crate::dm::gateway_ack(&envelope_id, &receiver, now);
    ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(sequence));
    handle
        .call(move |engine| Box::pin(engine.ack(ack)), Instant::now() + call_timeout)
        .await
        .map(|_| ())
}

async fn apply_ack_results_flush(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    incarnation: String,
    sequences: Vec<u64>,
    results: Vec<ramflux_storage::ReceiveAckResult>,
) -> Result<(), SdkError> {
    let (reply, response) = oneshot::channel();
    work.send(AccountWork::AckFlush {
        generation,
        force: false,
        now: crate::time::now_unix_timestamp(),
        results: Some(AckFlushResults { incarnation, sequences, results }),
        lookups: None,
        reply,
    })
    .await
    .map_err(|_| handle.pending())?;
    match response.await.map_err(|_| handle.pending())?? {
        AckFlushReply::Applied(_)
        | AckFlushReply::Inactive
        | AckFlushReply::Selected { .. }
        | AckFlushReply::Authorized { .. } => Ok(()),
    }
}

fn map_batch_results(
    sequences: &[u64],
    batch: Result<BatchReply, SdkError>,
) -> Vec<ReceiveAckResult> {
    match batch {
        Ok(BatchReply::Done { results, .. }) => results.iter().map(map_ack_result).collect(),
        Ok(BatchReply::Refused(_)) | Err(_) => sequences
            .iter()
            .map(|sequence| ReceiveAckResult {
                sequence: *sequence,
                outcome: ReceiveAckOutcome::Uncertain,
            })
            .collect(),
    }
}

fn map_ack_result(result: &AckResult) -> ReceiveAckResult {
    let outcome = match (&result.outcome, result.reason.as_deref()) {
        (AckOutcome::Acked, _) => ReceiveAckOutcome::Acked,
        (AckOutcome::AlreadySettled, _) => ReceiveAckOutcome::AlreadySettled,
        (AckOutcome::NotFound, _) => ReceiveAckOutcome::NotFound,
        (AckOutcome::InvalidSeq, _) | (AckOutcome::Rejected, Some("invalid_seq")) => {
            ReceiveAckOutcome::InvalidSeq
        }
        (AckOutcome::Rejected, _) => ReceiveAckOutcome::Transient,
    };
    ReceiveAckResult { sequence: result.inbox_seq, outcome }
}

/// Transmit one ACK and record the outcome. For `turn: Some` the actor decides first
/// (intent, `seq <= C`, fence); a refused sequence produces no ACK on the wire.
/// `turn: None` is the live path and stays unchanged.
#[allow(clippy::too_many_arguments, reason = "mirrors the live apply_entry tail")]
pub(crate) async fn ack_prepared(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    turn: Option<ReceiveTurn>,
    ack: ramflux_protocol::Ack,
    state: crate::bus::sync_driver::AckState,
    backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
    call_timeout: std::time::Duration,
) -> Result<ReceiveAcked, SdkError> {
    if let Some(turn) = &turn {
        let (reply, response) = oneshot::channel();
        work.send(AccountWork::AckPermit {
            generation,
            turn: Box::new(turn.clone()),
            sequence: state.entry.inbox_seq,
            reply,
        })
        .await
        .map_err(|_| handle.pending())?;
        let record = response.await.map_err(|_| handle.pending())??;
        if record != crate::bus::account_runtime::lifecycle_fence::AckRecord::Permitted {
            return Ok((false, backpressure));
        }
    }
    #[cfg(test)]
    let started = std::time::Instant::now();
    let cursor = handle
        .call(
            move |engine| Box::pin(async move { engine.ack(ack).await }),
            Instant::now() + call_timeout,
        )
        .await;
    #[cfg(test)]
    handle.test_record_receive("ack-network", started.elapsed());
    let (reply, response) = oneshot::channel();
    work.send(AccountWork::AckResults {
        generation,
        turn: turn.map(Box::new),
        state: Box::new(state),
        cursor: Box::new(cursor),
        backpressure,
        reply,
    })
    .await
    .map_err(|_| handle.pending())?;
    response.await.map_err(|_| handle.pending())?
}

#[cfg(test)]
pub(crate) async fn test_redrive(
    account: &mut crate::bus::state::LocalBusAccountState,
    conversation: &str,
    expected: usize,
) -> Result<(), SdkError> {
    let handle = account.connection.clone().ok_or(SdkError::NetworkingPending)?;
    let (writer, mut work) = mpsc::channel(8);
    let limits = RuntimeTimeouts {
        receive_min: std::time::Duration::from_secs(3600),
        receive_max: std::time::Duration::from_secs(3600),
        ..account.timeouts.clone()
    };
    let completion = handle.shared.receive_completed.clone();
    let child = tokio::spawn(run(handle.clone(), writer, limits));
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let message = tokio::select! {
                message = work.recv() => message.ok_or(SdkError::NetworkingPending)?,
                () = completion.notified() => {
                    assert_eq!(account.client.direct_messages(conversation)?.len(), expected,
                        "receive pass must not drop or duplicate parked entries");
                    break;
                }
            };
            match message {
                AccountWork::PrepareReceive { generation, reply, .. } => {
                    let _ =
                        reply.send(crate::bus::sync_driver::prepare_receive(account, generation));
                }
                AccountWork::Courier(step) => step.apply(account),
                AccountWork::ApplyPage { generation, turn, entry, source, backpressure, reply } => {
                    if let Some(key) = &entry.retry_key
                        && crate::bus::couriers::head_refresh::inbound::eligible(account, key)
                    {
                        assert!(
                            !account
                                .client
                                .account_db()?
                                .inbox_retry_ready(key, crate::prelude::now_unix_timestamp(),)?,
                            "refresh applies before the durable retry deadline"
                        );
                    }
                    let _ = reply.send(
                        redrive_apply_page(account, generation, turn, *entry, source, backpressure)
                            .await,
                    );
                }
                AccountWork::ReceiveObservation { .. } => {}
                AccountWork::AckResults { state, cursor, mut backpressure, reply, .. } => {
                    let result = crate::bus::sync_driver::finish_prepared_ack(
                        account,
                        &state,
                        *cursor,
                        &mut backpressure,
                    );
                    let _ = reply.send(result.map(|accepted| (accepted, backpressure)));
                }
                AccountWork::AckFlush { results, reply, .. } => {
                    let _ = reply.send(Ok(match results {
                        None => AckFlushReply::Inactive,
                        Some(_) => AckFlushReply::Applied(
                            ramflux_storage::ReceiveAckApplyResult::Applied {
                                settled: 0,
                                revalidate: false,
                            },
                        ),
                    }));
                }
                AccountWork::StageIntake { reply, .. } => {
                    let _ = reply.send(Ok(None));
                }
                _ => return Err(SdkError::NetworkingPending),
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| SdkError::NetworkingPending);
    child.abort();
    let _ = child.await;
    result?
}

#[cfg(test)]
async fn redrive_apply_page(
    account: &mut crate::bus::state::LocalBusAccountState,
    generation: u64,
    turn: Option<Box<ReceiveTurn>>,
    entry: ReceiveEntry,
    source: crate::bus::sync_driver::source::PreparedSource,
    backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
) -> Result<ReceiveApplied, SdkError> {
    let target = account.target_delivery_id.clone();
    let active =
        crate::bus::push_receiver::apply_w1::is_active(account.client.account_db()?, &target)?;
    if !active && turn.is_none() {
        return crate::bus::sync_driver::apply_prepared_receive(
            account,
            entry,
            source,
            backpressure,
        )
        .await;
    }
    let turn = match turn {
        Some(turn) => *turn,
        None => crate::bus::push_receiver::apply_w1::capture_turn(
            account.client.account_db()?,
            generation,
            &target,
        )?,
    };
    let applied = Box::pin(crate::bus::push_receiver::apply_w1::apply_page(
        account,
        &turn,
        &|| generation,
        entry,
        source,
        backpressure,
    ))
    .await?;
    crate::bus::push_receiver::apply_w1::replay_projected(account)?;
    Ok(applied)
}
