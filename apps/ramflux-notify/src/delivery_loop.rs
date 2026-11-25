// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Async delivery workers. A row with nothing to send waits for its next due
//! time or for a queue, route, credential, or cancel pulse. It does not commit.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ramflux_node_core::NotifyQueueEntry;

use super::{ConcurrentProviderPushWorkerPool, note_provider_send};

enum AfterClaim {
    /// A send was attempted, or the scan failed. Look again immediately.
    Retry,
    /// Nothing was sent. Park until `deadline`, or until a pulse when it is absent.
    Idle(Option<Instant>),
}

pub(crate) fn start(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let worker_count =
        super::notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_DELIVERY_WORKERS", || {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        })
        .max(1);
    let scan_limit =
        super::notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_DELIVERY_SCAN_LIMIT", || 256).max(1);
    let idle_sleep_ms =
        super::notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_DELIVERY_IDLE_SLEEP_MS", || 10)
            .max(1);
    let provider_worker_count =
        super::notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_PROVIDER_WORKERS", || {
            worker_count.saturating_mul(2).max(1)
        })
        .max(1);
    let provider_workers = Arc::new(ConcurrentProviderPushWorkerPool::new(provider_worker_count)?);
    let in_flight = Arc::new(Mutex::new(BTreeSet::<String>::new()));
    for worker_id in 0..worker_count {
        let thread_store = Arc::clone(store);
        let thread_provider_workers = Arc::clone(&provider_workers);
        let thread_in_flight = Arc::clone(&in_flight);
        ramflux_node_core::spawn_service_worker(
            format!("ramflux-notify-async-delivery-{worker_id}"),
            move |_| {
                worker_loop(
                    &thread_store,
                    &thread_provider_workers,
                    &thread_in_flight,
                    scan_limit,
                    Duration::from_millis(u64::try_from(idle_sleep_ms).unwrap_or(u64::MAX)),
                );
            },
        )
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    }
    tracing::info!(
        worker_count,
        provider_worker_count,
        scan_limit,
        idle_sleep_ms,
        "notify async accept delivery workers initialized"
    );
    Ok(())
}

fn worker_loop(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    provider_workers: &ConcurrentProviderPushWorkerPool,
    in_flight: &Arc<Mutex<BTreeSet<String>>>,
    scan_limit: usize,
    idle_sleep: Duration,
) {
    let mut seen = store.delivery_generation();
    while !ramflux_node_core::service_shutdown_token().is_cancelled() {
        match notify_async_claim_entries(store, in_flight, scan_limit) {
            Ok(entries) if entries.is_empty() => {
                seen = store.wait_for_delivery(seen, None);
            }
            Ok(entries) => match deliver_claimed(store, provider_workers, in_flight, entries) {
                AfterClaim::Retry => {}
                AfterClaim::Idle(deadline) => {
                    seen = store.wait_for_delivery(seen, deadline);
                }
            },
            Err(error) => {
                tracing::warn!(%error, "notify async delivery scan failed");
                std::thread::sleep(idle_sleep);
            }
        }
    }
}

pub(crate) fn notify_async_claim_entries(
    store: &ramflux_node_core::NotifyRedbStore,
    in_flight: &Arc<Mutex<BTreeSet<String>>>,
    scan_limit: usize,
) -> Result<Vec<NotifyQueueEntry>, ramflux_node_core::NodeCoreError> {
    if tracing::enabled!(tracing::Level::TRACE) {
        for shard in store.notify_wal_pending_counts(scan_limit.saturating_mul(2)) {
            tracing::trace!(
                shard_id = shard.shard_id,
                pending_queue_entries = shard.counts.queue_entry_count,
                pending_raw_wakes = shard.counts.raw_wake_count,
                "notify async delivery WAL pending scan"
            );
        }
    }
    let candidates = store.pending_entries_without_attempts(scan_limit.saturating_mul(2))?;
    let candidate_count = candidates.len();
    let mut claimed = Vec::new();
    let mut guard = in_flight.lock().map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "notify async in-flight lock poisoned: {source}"
        ))
    })?;
    for entry in candidates {
        if claimed.len() >= scan_limit {
            break;
        }
        if guard.insert(entry.queue_id.clone()) {
            claimed.push(entry);
        }
    }
    tracing::trace!(
        candidate_count,
        claimed_count = claimed.len(),
        scan_limit,
        "notify async delivery claimed pending entries"
    );
    Ok(claimed)
}

fn release_entry(in_flight: &Arc<Mutex<BTreeSet<String>>>, queue_id: &str) {
    match in_flight.lock() {
        Ok(mut guard) => {
            guard.remove(queue_id);
        }
        Err(error) => tracing::warn!(%error, "notify async in-flight lock poisoned on release"),
    }
}

fn deliver_claimed(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    provider_workers: &ConcurrentProviderPushWorkerPool,
    in_flight: &Arc<Mutex<BTreeSet<String>>>,
    entries: Vec<NotifyQueueEntry>,
) -> AfterClaim {
    let mut retry_now = false;
    let mut earliest: Option<u64> = None;
    for entry in entries {
        let queue_id = entry.queue_id.clone();
        match deliver_entry(store, provider_workers, &entry) {
            Ok(true) => retry_now = true,
            Ok(false) => earliest = earlier_due(store, &entry, earliest, &mut retry_now),
            Err(error) => {
                tracing::warn!(queue_id = queue_id, %error, "notify async delivery failed");
                retry_now = true;
            }
        }
        release_entry(in_flight, &queue_id);
    }
    if retry_now { AfterClaim::Retry } else { AfterClaim::Idle(earliest.map(due_instant)) }
}

fn earlier_due(
    store: &ramflux_node_core::NotifyRedbStore,
    entry: &NotifyQueueEntry,
    earliest: Option<u64>,
    retry_now: &mut bool,
) -> Option<u64> {
    match store.next_unsent_wake_unix(entry) {
        Ok(Some(due)) => Some(earliest.map_or(due, |current| current.min(due))),
        Ok(None) => earliest,
        Err(error) => {
            tracing::warn!(%error, "notify async delivery due time unavailable");
            *retry_now = true;
            earliest
        }
    }
}

/// At least one second, so a due time inside the current unix second cannot spin.
fn due_instant(unix: u64) -> Instant {
    let now_unix = ramflux_node_core::now_unix_seconds();
    let secs = unix.saturating_sub(now_unix).clamp(1, 60 * 60 * 24 * 366);
    let now = Instant::now();
    now.checked_add(Duration::from_secs(secs)).unwrap_or(now)
}

fn deliver_entry(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    provider_workers: &ConcurrentProviderPushWorkerPool,
    entry: &NotifyQueueEntry,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    if let Some(central) = super::central_handoff::active() {
        return central.deliver(store, entry);
    }
    let pushes = store.prepare_provider_pushes_for_entry(entry)?;
    if pushes.is_empty() {
        tracing::debug!("notify async delivery found no provider pushes for pending entry");
        return Ok(false);
    }
    tracing::trace!(push_count = pushes.len(), "notify async delivery prepared provider pushes");
    let mut pending = Vec::with_capacity(pushes.len());
    for prepared in pushes {
        let response = provider_workers.dispatch(Arc::clone(store), prepared.clone())?;
        pending.push((prepared, response));
    }
    let total_count = pending.len();
    let mut accepted_count = 0_usize;
    for (prepared, response) in pending {
        let received = response.recv().map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify async provider worker response closed: {error}"
            ))
        })?;
        let accepted = note_provider_send(store, &prepared, received);
        if accepted {
            accepted_count = accepted_count.saturating_add(1);
        }
        let attempt = ramflux_node_core::redacted_provider_attempt(
            entry,
            &prepared,
            accepted,
            (!accepted).then(|| "provider_send_failed".to_owned()),
        );
        store.record_provider_attempt(attempt)?;
    }
    tracing::trace!(
        accepted_count,
        total_count,
        "notify async delivery recorded provider attempts"
    );
    Ok(true)
}
