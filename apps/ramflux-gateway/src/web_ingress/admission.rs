// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-authentication admission of the web listener.
//!
//! Everything here is volatile, bounded memory behind this listener's own mutex. It never
//! takes the gateway state lock and never writes to the store, so an unauthenticated
//! browser connection costs a few map operations and nothing durable. Sources are the
//! transport-observed peer address (IPv6 aggregated per /64) and time is the local
//! monotonic clock; no request header or frame field feeds either.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Limits of the wire contract; `OPEN-VALUE` defaults kept as named constants.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) unauthenticated_per_source: u32,
    pub(crate) connections_per_source: u32,
    pub(crate) upgrades_per_source: u32,
    pub(crate) upgrades_per_origin: u32,
    pub(crate) upgrade_window: Duration,
    pub(crate) failed_proofs_per_source: u32,
    pub(crate) failed_proof_window: Duration,
    /// All connections of this listener, authenticated or not.
    pub(crate) connections_total: u32,
    /// Sources tracked at once; a new source beyond this is refused, not evicted for.
    pub(crate) tracked_sources: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            unauthenticated_per_source: 8,
            connections_per_source: 32,
            upgrades_per_source: 30,
            upgrades_per_origin: 600,
            upgrade_window: Duration::from_secs(60),
            failed_proofs_per_source: 10,
            failed_proof_window: Duration::from_secs(600),
            connections_total: 4096,
            tracked_sources: 65_536,
        }
    }
}

#[derive(Default)]
struct Window {
    started: Option<Instant>,
    count: u32,
    /// One alert per window.
    alerted: bool,
}

impl Window {
    /// Fixed window: count one event, refuse once the window's budget is spent.
    fn admit(&mut self, now: Instant, span: Duration, limit: u32) -> bool {
        if self.started.is_none_or(|started| now.duration_since(started) >= span) {
            self.started = Some(now);
            self.count = 0;
            self.alerted = false;
        }
        if self.count >= limit {
            return false;
        }
        self.count += 1;
        true
    }

    fn idle(&self, now: Instant, span: Duration) -> bool {
        self.started.is_none_or(|started| now.duration_since(started) >= span)
    }
}

#[derive(Default)]
struct Source {
    unauthenticated: u32,
    connections: u32,
    upgrades: Window,
    failed_proofs: Window,
    blocked_until: Option<Instant>,
}

#[derive(Default)]
struct State {
    sources: HashMap<String, Source>,
    origins: HashMap<String, Window>,
    connections: u32,
}

/// Why a connection or an upgrade was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Denied {
    ListenerFull,
    SourceConnections,
    SourceUnauthenticated,
    SourceRate,
    SourceBlocked,
}

pub(crate) struct Admission {
    limits: Limits,
    state: Mutex<State>,
}

/// One accepted connection. Dropping it releases its slots.
pub(crate) struct Slot {
    admission: Arc<Admission>,
    source: String,
    authenticated: bool,
}

impl Admission {
    #[must_use]
    pub(crate) fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self { limits, state: Mutex::new(State::default()) })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Called at TCP accept, before the TLS handshake: the cheapest point to refuse.
    ///
    /// # Errors
    /// Returns the limit that refused the connection.
    pub(crate) fn connect(self: &Arc<Self>, source: &str, now: Instant) -> Result<Slot, Denied> {
        let mut state = self.state();
        if state.connections >= self.limits.connections_total {
            return Err(Denied::ListenerFull);
        }
        if !state.sources.contains_key(source) && state.sources.len() >= self.limits.tracked_sources
        {
            self.prune(&mut state, now);
            if state.sources.len() >= self.limits.tracked_sources {
                return Err(Denied::ListenerFull);
            }
        }
        let entry = state.sources.entry(source.to_owned()).or_default();
        if entry.blocked_until.is_some_and(|until| now < until) {
            return Err(Denied::SourceBlocked);
        }
        if entry.connections >= self.limits.connections_per_source {
            return Err(Denied::SourceConnections);
        }
        if entry.unauthenticated >= self.limits.unauthenticated_per_source {
            return Err(Denied::SourceUnauthenticated);
        }
        entry.connections += 1;
        entry.unauthenticated += 1;
        state.connections += 1;
        Ok(Slot { admission: Arc::clone(self), source: source.to_owned(), authenticated: false })
    }

    /// The upgrade step of the handshake: per-source and per-origin attempt rates.
    ///
    /// # Errors
    /// Returns the limit that refused the upgrade; the caller answers `429`.
    pub(crate) fn upgrade(&self, source: &str, origin: &str, now: Instant) -> Result<(), Denied> {
        let limits = self.limits;
        let mut state = self.state();
        let entry = state.sources.entry(source.to_owned()).or_default();
        if entry.blocked_until.is_some_and(|until| now < until) {
            return Err(Denied::SourceBlocked);
        }
        if !entry.upgrades.admit(now, limits.upgrade_window, limits.upgrades_per_source) {
            return Err(Denied::SourceRate);
        }
        // `Origin` is chosen by the client, so it is never a reason to refuse: a refusal
        // keyed on it would let a few addresses lock every real user of an origin out.
        // The per-origin count only raises an alert. The origin already matched the
        // allow-list, so this map holds at most that many keys.
        let window = state.origins.entry(origin.to_owned()).or_default();
        if !window.admit(now, limits.upgrade_window, limits.upgrades_per_origin)
            && !std::mem::replace(&mut window.alerted, true)
        {
            tracing::warn!(
                limit = limits.upgrades_per_origin,
                "web upgrade rate alert for an allowed origin"
            );
        }
        Ok(())
    }

    /// A refused possession proof. The budget's exhaustion blocks the source's upgrades.
    pub(crate) fn failed_proof(&self, source: &str, now: Instant) {
        let limits = self.limits;
        let mut state = self.state();
        let entry = state.sources.entry(source.to_owned()).or_default();
        if !entry.failed_proofs.admit(now, limits.failed_proof_window, limits.failed_proofs_per_source)
        {
            entry.blocked_until = Some(now + limits.failed_proof_window);
        }
    }

    fn prune(&self, state: &mut State, now: Instant) {
        let limits = self.limits;
        state.sources.retain(|_, source| {
            source.connections > 0
                || source.blocked_until.is_some_and(|until| now < until)
                || !source.upgrades.idle(now, limits.upgrade_window)
                || !source.failed_proofs.idle(now, limits.failed_proof_window)
        });
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> (usize, u32) {
        let state = self.state();
        (state.sources.len(), state.connections)
    }
}

impl Slot {
    /// The gateway session is established: the connection leaves the unauthenticated budget.
    pub(crate) fn mark_authenticated(&mut self) {
        if self.authenticated {
            return;
        }
        self.authenticated = true;
        let mut state = self.admission.state();
        if let Some(source) = state.sources.get_mut(&self.source) {
            source.unauthenticated = source.unauthenticated.saturating_sub(1);
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut state = self.admission.state();
        state.connections = state.connections.saturating_sub(1);
        if let Some(source) = state.sources.get_mut(&self.source) {
            source.connections = source.connections.saturating_sub(1);
            if !self.authenticated {
                source.unauthenticated = source.unauthenticated.saturating_sub(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Admission, Denied, Limits};
    use std::time::{Duration, Instant};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn denied<T>(result: Result<T, Denied>) -> Option<Denied> {
        result.err()
    }

    #[test]
    fn unauthenticated_connections_per_source_are_capped_and_released() -> TestResult {
        let admission = Admission::new(Limits::default());
        let now = Instant::now();
        let mut slots = Vec::new();
        for _ in 0..8 {
            slots.push(admission.connect("a", now).map_err(|d| format!("{d:?}"))?);
        }
        assert_eq!(denied(admission.connect("a", now)), Some(Denied::SourceUnauthenticated));
        // Another source is unaffected.
        let other = admission.connect("b", now).map_err(|d| format!("{d:?}"))?;
        // Authentication frees an unauthenticated slot but not the total.
        if let Some(slot) = slots.first_mut() {
            slot.mark_authenticated();
        }
        slots.push(admission.connect("a", now).map_err(|d| format!("{d:?}"))?);
        drop(slots);
        drop(other);
        assert_eq!(admission.tracked().1, 0);
        assert!(admission.connect("a", now).is_ok());
        Ok(())
    }

    #[test]
    fn total_connections_per_source_are_capped() -> TestResult {
        let admission = Admission::new(Limits::default());
        let now = Instant::now();
        let mut slots = Vec::new();
        for _ in 0..32 {
            let mut slot = admission.connect("a", now).map_err(|d| format!("{d:?}"))?;
            slot.mark_authenticated();
            slots.push(slot);
        }
        assert_eq!(denied(admission.connect("a", now)), Some(Denied::SourceConnections));
        Ok(())
    }

    #[test]
    fn upgrade_rate_is_per_source_and_resets_with_the_window() {
        let admission = Admission::new(Limits::default());
        let now = Instant::now();
        for _ in 0..30 {
            assert!(admission.upgrade("a", "https://app.example.org", now).is_ok());
        }
        assert_eq!(
            denied(admission.upgrade("a", "https://app.example.org", now)),
            Some(Denied::SourceRate)
        );
        assert!(admission.upgrade("b", "https://app.example.org", now).is_ok());
        let later = now + Duration::from_secs(60);
        assert!(admission.upgrade("a", "https://app.example.org", later).is_ok());
    }

    #[test]
    fn per_origin_upgrade_count_alerts_but_never_refuses() {
        let limits = Limits { upgrades_per_origin: 3, ..Limits::default() };
        let admission = Admission::new(limits);
        let now = Instant::now();
        // Many sources naming one origin cannot lock that origin's real users out.
        for source in ["a", "b", "c", "d", "e", "f"] {
            assert!(admission.upgrade(source, "https://app.example.org", now).is_ok());
        }
    }

    #[test]
    fn repeated_failed_proofs_block_the_source_for_the_window() {
        let admission = Admission::new(Limits::default());
        let now = Instant::now();
        for _ in 0..10 {
            admission.failed_proof("a", now);
        }
        assert!(admission.upgrade("a", "https://app.example.org", now).is_ok());
        admission.failed_proof("a", now);
        assert_eq!(
            denied(admission.upgrade("a", "https://app.example.org", now)),
            Some(Denied::SourceBlocked)
        );
        assert_eq!(denied(admission.connect("a", now)), Some(Denied::SourceBlocked));
        let later = now + Duration::from_secs(601);
        assert!(admission.connect("a", later).is_ok());
    }

    #[test]
    fn tracked_sources_are_bounded_and_idle_ones_are_pruned() {
        let limits = Limits { tracked_sources: 4, ..Limits::default() };
        let admission = Admission::new(limits);
        let now = Instant::now();
        for source in ["a", "b", "c", "d"] {
            drop(admission.connect(source, now));
        }
        // All four are idle with no window activity, so a fifth source prunes them.
        assert!(admission.connect("e", now).is_ok());
        assert!(admission.tracked().0 <= 4);
        // Held connections cannot be pruned: the fifth distinct source is refused.
        let held: Vec<_> =
            ["f", "g", "h", "i"].iter().map(|source| admission.connect(source, now)).collect();
        assert_eq!(denied(admission.connect("j", now)), Some(Denied::ListenerFull));
        drop(held);
    }
}
