// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wake async delivery when a queue row, route, or credential changes.
//!
//! Pending rows with no provider stay queued until `expires_at`. Retention then
//! drops them (`NotifyQueueState::prune_retention`). This gate is how a worker
//! waits for that moment, or for a route that can send earlier, without a commit.

use super::{
    NOTIFY_RATE_ALIAS_PER_HOUR, NOTIFY_RATE_ALIAS_PER_MINUTE, NOTIFY_RATE_PROVIDER_PER_MINUTE,
    NodeCoreError, NotifyQueueEntry, NotifyQueueStatus, NotifyRedbStore, PushProviderKind,
    now_unix_seconds,
};
use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

const SHUTDOWN_POLL: Duration = Duration::from_millis(500);
const RATE_EVENT_CAP: usize = 4_096;

pub(super) struct DeliveryGate {
    generation: Mutex<u64>,
    changed: Condvar,
}

impl DeliveryGate {
    pub(super) fn new() -> Self {
        Self { generation: Mutex::new(0), changed: Condvar::new() }
    }
}

impl NotifyRedbStore {
    pub fn note_delivery_work(&self) {
        let mut generation = lock_generation(&self.delivery_gate);
        *generation = generation.wrapping_add(1);
        self.delivery_gate.changed.notify_all();
    }

    #[must_use]
    pub fn delivery_generation(&self) -> u64 {
        *lock_generation(&self.delivery_gate)
    }

    /// Park until `seen` is stale, `deadline` passes, or process shutdown starts.
    #[must_use]
    pub fn wait_for_delivery(&self, seen: u64, deadline: Option<Instant>) -> u64 {
        let mut generation = lock_generation(&self.delivery_gate);
        let shutdown = crate::service_shutdown_token();
        loop {
            if shutdown.is_cancelled() || *generation != seen {
                return *generation;
            }
            let now = Instant::now();
            if deadline.is_some_and(|deadline| now >= deadline) {
                return *generation;
            }
            let wait = match deadline {
                Some(deadline) => SHUTDOWN_POLL.min(deadline.saturating_duration_since(now)),
                None => SHUTDOWN_POLL,
            };
            if wait.is_zero() {
                return *generation;
            }
            generation = wait_generation(&self.delivery_gate, generation, wait);
        }
    }

    /// Unix second when this still-pending row should be looked at again.
    ///
    /// `None` means the row is not pending or already expired. A live row with no
    /// provider is due at `expires_at`. A rate-limited provider route is due when
    /// its window opens, and not later than `expires_at`.
    ///
    /// # Errors
    /// Returns an error when routes or the rate-limit lock cannot be read.
    pub fn next_unsent_wake_unix(
        &self,
        entry: &NotifyQueueEntry,
    ) -> Result<Option<u64>, NodeCoreError> {
        let now = now_unix_seconds();
        if entry.status != NotifyQueueStatus::Pending || entry.expires_at <= now {
            return Ok(None);
        }
        let open = self.selected_route_rate_open(entry, now)?;
        let until = open
            .filter(|open| *open > now)
            .map_or(entry.expires_at, |open| open.min(entry.expires_at));
        Ok(Some(until))
    }

    fn selected_route_rate_open(
        &self,
        entry: &NotifyQueueEntry,
        now: u64,
    ) -> Result<Option<u64>, NodeCoreError> {
        let mut routes = self
            .load_notify_routes(&entry.device_delivery_id)?
            .into_iter()
            .filter(|route| route.expires_at > now)
            .collect::<Vec<_>>();
        if !routes.is_empty() && !self.authorize_push_route(&entry.device_delivery_id)? {
            routes.clear();
        }
        if routes.is_empty() {
            return Ok(None);
        }
        let mut credential_cache = BTreeMap::new();
        let routes = super::route_selection::select_wake_routes(
            routes,
            &entry.wake.delivery_class,
            self.voip_enabled(),
            |route| {
                self.provider_credential_for_route(&mut credential_cache, route).is_ok_and(
                    |credential| credential.provider_kind() == PushProviderKind::ApnsVoip,
                )
            },
        );
        let mut earliest: Option<u64> = None;
        for route in &routes {
            let Some(open) = self.route_rate_open(&route.provider, &entry.push_alias_hash, now)?
            else {
                return Ok(None);
            };
            earliest = Some(earliest.map_or(open, |current| current.min(open)));
        }
        Ok(earliest)
    }

    fn route_rate_open(
        &self,
        provider: &PushProviderKind,
        alias: &str,
        now: u64,
    ) -> Result<Option<u64>, NodeCoreError> {
        let state = self.runtime_state.lock().map_err(|source| {
            NodeCoreError::ItestJson(format!("notify runtime state lock poisoned: {source}"))
        })?;
        let alias_events = state.rate_events_by_alias.get(alias).map_or(&[][..], Vec::as_slice);
        let provider_events =
            state.rate_events_by_provider.get(provider).map_or(&[][..], Vec::as_slice);
        Ok(rate_open_unix(alias_events, provider_events, now))
    }
}

fn lock_generation(gate: &DeliveryGate) -> std::sync::MutexGuard<'_, u64> {
    gate.generation.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn wait_generation<'a>(
    gate: &DeliveryGate,
    generation: std::sync::MutexGuard<'a, u64>,
    wait: Duration,
) -> std::sync::MutexGuard<'a, u64> {
    match gate.changed.wait_timeout(generation, wait) {
        Ok((guard, _)) => guard,
        Err(poisoned) => poisoned.into_inner().0,
    }
}

fn rate_open_unix(alias: &[u64], provider: &[u64], now: u64) -> Option<u64> {
    let minute = window_open(alias, now, 60, NOTIFY_RATE_ALIAS_PER_MINUTE);
    let hour = window_open(alias, now, 3_600, NOTIFY_RATE_ALIAS_PER_HOUR);
    let provider_open = window_open(provider, now, 60, NOTIFY_RATE_PROVIDER_PER_MINUTE);
    [minute, hour, provider_open].into_iter().flatten().max()
}

fn window_open(events: &[u64], now: u64, window: u64, limit: usize) -> Option<u64> {
    let mut fresh = Vec::new();
    for event in events {
        if fresh.len() == RATE_EVENT_CAP {
            break;
        }
        if *event > now.saturating_sub(window) {
            fresh.push(*event);
        }
    }
    if fresh.len() < limit {
        return None;
    }
    fresh.sort_unstable();
    let index = fresh.len().checked_sub(limit)?;
    let pivot = fresh.get(index).copied()?;
    Some(pivot.saturating_add(window))
}
