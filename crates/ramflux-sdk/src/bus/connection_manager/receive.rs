// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account receive scheduling uses only ticks, connection establishment, and explicit resync.

use super::{AccountWork, ConnectionHandle, NetworkingState, ReceiveTurn, RuntimeTimeouts};
use crate::SdkError;
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
/// Live [`run`] keeps the 250 ms–5 s tick until P24 activation.
#[allow(dead_code, reason = "P24 activation replaces live receive::run with this loop")]
pub(super) async fn run_anchored(
    handle: ConnectionHandle,
    work: mpsc::Sender<AccountWork>,
    limits: RuntimeTimeouts,
    setting: crate::bus::push_receiver::sweep::SweepSetting,
    mode: crate::bus::push_receiver::sweep::SweepMode,
) {
    use crate::bus::push_receiver::sweep::{Planner, ResumeKind};
    let mut stop = handle.stop.subscribe();
    let mut planner = Planner::new(&setting, mode);
    let origin = Instant::now();
    loop {
        let snapshot = handle.snapshot();
        let now_ms = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let view = crate::bus::push_receiver::sweep::View {
            live: snapshot.state == NetworkingState::Live,
            generation: snapshot.generation,
            resync: handle.resync_needed(),
        };
        if let Some(kind) = planner.decide(now_ms, view) {
            let trigger = match kind {
                ResumeKind::Connected => ReceiveTrigger::Connected,
                ResumeKind::Sweep => ReceiveTrigger::Tick,
                ResumeKind::Resync => ReceiveTrigger::Resync,
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
            let pass = timeout(
                limits.sync,
                pass_anchored(&handle, &work, snapshot.generation, trigger, limits.call),
            );
            let result = tokio::select! {biased;_=stop.changed()=>break,result=pass=>result};
            let ok = matches!(result, Ok(Ok(_)));
            match result {
                Ok(Ok(_)) => {
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
                }
                Ok(Err(error)) => tracing::debug!(%error,"receive pass deferred"),
                Err(_) => tracing::debug!("receive pass deadline expired"),
            }
            let finished_ms = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
            planner.finish(now_ms, finished_ms, snapshot.generation, ok);
            continue;
        }
        // Not live: decide() cannot fire, so wait for wake instead of a past deadline spin.
        let wait = if snapshot.state == NetworkingState::Live {
            planner
                .wake_at_ms(now_ms)
                .and_then(|ms| origin.checked_add(std::time::Duration::from_millis(ms)))
        } else {
            None
        };
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

async fn pass(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    trigger: ReceiveTrigger,
    call_timeout: std::time::Duration,
) -> Result<bool, SdkError> {
    let (active, backpressure) = catch_up(handle, work, generation, trigger, call_timeout).await?;
    let (more, _) = rescan(handle, work, generation, call_timeout, backpressure).await?;
    Ok(active || more)
}

/// Candidate catch-up: same Resume pages as live, without the contact-floor rescan.
#[allow(dead_code, reason = "P24 activation uses this in place of pass+rescan")]
async fn pass_anchored(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    trigger: ReceiveTrigger,
    call_timeout: std::time::Duration,
) -> Result<bool, SdkError> {
    Ok(catch_up(handle, work, generation, trigger, call_timeout).await?.0)
}

async fn catch_up(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    generation: u64,
    trigger: ReceiveTrigger,
    call_timeout: std::time::Duration,
) -> Result<(bool, Box<crate::bus::contact_backpressure::Backpressure>), SdkError> {
    let (reply, response) = oneshot::channel();
    work.send(AccountWork::PrepareReceive { generation, trigger, reply })
        .await
        .map_err(|_| handle.pending())?;
    let plan = response.await.map_err(|_| handle.pending())??;
    let mut cursor = plan.cursor;
    let mut backpressure = plan.backpressure;
    let turn = plan.turn;
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
    Ok((active, backpressure))
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

fn entry_id(entry: &crate::GatewayInboxEntry) -> (String, u64, String) {
    (entry.envelope.envelope_id.clone(), entry.inbox_seq, entry.envelope.payload_hash.clone())
}

async fn apply_entry(
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
    let Some(prepared) = prepared else { return Ok((false, backpressure)) };
    if let Some(envelope) = prepared.pair_reply {
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
                AccountWork::ApplyPage { entry, source, backpressure, reply, .. } => {
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
                        crate::bus::sync_driver::apply_prepared_receive(
                            account,
                            *entry,
                            source,
                            backpressure,
                        )
                        .await,
                    );
                }
                AccountWork::ReceiveObservation { .. } | AccountWork::Observation { .. } => {}
                AccountWork::AckResults { state, cursor, mut backpressure, reply, .. } => {
                    let result = crate::bus::sync_driver::finish_prepared_ack(
                        account,
                        &state,
                        *cursor,
                        &mut backpressure,
                    );
                    let _ = reply.send(result.map(|accepted| (accepted, backpressure)));
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
