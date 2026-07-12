// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-account relay QUIC connection pool (T24-A1, transport core).
//!
//! The SDK object path currently opens a fresh QUIC endpoint + handshake for every relay chunk
//! (see `crates/ramflux-sdk/src/client/object.rs::relay_quic_request`). This module provides a
//! reusable, instance-owned pool that keeps at most one live connection per
//! [`RelayQuicPoolKey`] and hands out `request_once` on it, so multi-chunk transfers reuse a
//! single handshake and long-idle connections are kept alive (or evicted) deterministically.
//!
//! Ownership: [`RelayQuicPool`] is a plain instance — T24-A2 will store one on each
//! `LocalBusAccountState`. There is deliberately **no** process-global / static-mutable pool: a
//! process-global keyed only by peer/server-name could hand one account a connection validated
//! against another account's CA. The pool key includes a blake3 fingerprint of the CA file
//! **content** (not its path) precisely so a CA rotation, or two accounts with different CAs,
//! never share a connection.
//!
//! Concurrency mirrors [`crate::mesh_quic`]'s pool: an [`arc_swap`] map of per-key state, a
//! single-flight connect guard, and a [`tokio::sync::Notify`] to wake waiters — no `std` lock is
//! ever held across an `.await`, and the connect handshake runs without holding the map lock.
//!
//! This card exposes only the `request_once` + `invalidate` primitives. It never inspects HTTP
//! status or object capability to decide a retry: a complete [`GatewayQuicResponse`] (any status,
//! including 4xx/5xx) is returned `Ok`, and only genuine transport failures become a typed
//! [`RelayQuicRequestError`]. Retry policy lives entirely in T24-A2.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use tokio::sync::{Mutex, Notify};

use crate::TransportError;
use crate::quic_gateway::relay_client_quic_bind_addr;
use crate::tls_config::relay_quic_pool_client_config;
use crate::{
    GatewayQuicRequest, GatewayQuicResponse, QuicConnectPhase, QuicGatewayClient, QuicRequestPhase,
    RelayClientQuicConfig,
};

/// Backstop poll interval for a single-flight waiter: even if a `notify_waiters()` is ever missed,
/// re-check pool state at least this often instead of blocking forever (mirrors the mesh pool).
const RELAY_QUIC_ACQUIRE_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// IP family of the local bind address — part of the connection identity, since a v4 and a v6
/// connection to the same host are distinct sockets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RelayQuicBindFamily {
    V4,
    V6,
}

impl RelayQuicBindFamily {
    #[must_use]
    fn for_peer(peer_addr: SocketAddr) -> Self {
        if peer_addr.is_ipv6() { Self::V6 } else { Self::V4 }
    }
}

/// The connection identity for a pooled relay QUIC connection. Two lookups share a connection iff
/// all four fields match. `ca_fingerprint` is a blake3 hash of the CA file **content**, so the
/// same file path with rotated content is a miss (never a stale-CA reuse). Token/grant fields
/// (owner home, audience, principal) are request authorization, **not** connection identity, and
/// deliberately do not appear here.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RelayQuicPoolKey {
    peer_addr: SocketAddr,
    server_name: String,
    ca_fingerprint: [u8; 32],
    bind_family: RelayQuicBindFamily,
}

impl RelayQuicPoolKey {
    /// Computes the pool key for a relay client config, reading and fingerprinting the CA file
    /// content on every call (not caching by path or mtime).
    ///
    /// # Errors
    /// Returns [`RelayQuicRequestError::Config`] when the CA file cannot be read.
    pub fn from_config(config: &RelayClientQuicConfig) -> Result<Self, RelayQuicRequestError> {
        let ca_bytes = std::fs::read(&config.ca_cert).map_err(|error| {
            RelayQuicRequestError::Config(format!(
                "read relay CA {}: {error}",
                config.ca_cert.display()
            ))
        })?;
        Ok(Self {
            peer_addr: config.peer_addr,
            server_name: config.server_name.clone(),
            ca_fingerprint: *blake3::hash(&ca_bytes).as_bytes(),
            bind_family: RelayQuicBindFamily::for_peer(config.peer_addr),
        })
    }

    #[cfg(test)]
    #[must_use]
    fn for_test(
        peer_addr: SocketAddr,
        server_name: &str,
        ca_fingerprint: [u8; 32],
        bind_family: RelayQuicBindFamily,
    ) -> Self {
        Self { peer_addr, server_name: server_name.to_owned(), ca_fingerprint, bind_family }
    }
}

/// Per-phase timeouts for the pool. Deliberately not a single reused deadline: `connect_handshake`
/// bounds the handshake, `request` bounds an individual request, and `idle`/`keepalive` are set on
/// the quinn transport config so a pooled connection is kept alive (or times out) predictably.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayQuicTimeouts {
    connect_handshake: Duration,
    request: Duration,
    idle: Duration,
    keepalive: Duration,
}

impl RelayQuicTimeouts {
    /// # Errors
    /// Returns [`RelayQuicRequestError::Config`] when any duration is zero, or when the keep-alive
    /// interval is not strictly less than the idle timeout (a keep-alive at or above the idle
    /// bound cannot keep the connection alive).
    pub fn new(
        connect_handshake: Duration,
        request: Duration,
        idle: Duration,
        keepalive: Duration,
    ) -> Result<Self, RelayQuicRequestError> {
        for (name, value) in [
            ("connect_handshake", connect_handshake),
            ("request", request),
            ("idle", idle),
            ("keepalive", keepalive),
        ] {
            if value.is_zero() {
                return Err(RelayQuicRequestError::Config(format!(
                    "relay QUIC pool {name} timeout must be nonzero"
                )));
            }
        }
        if keepalive >= idle {
            return Err(RelayQuicRequestError::Config(format!(
                "relay QUIC pool keepalive ({}ms) must be strictly less than idle ({}ms)",
                keepalive.as_millis(),
                idle.as_millis()
            )));
        }
        Ok(Self { connect_handshake, request, idle, keepalive })
    }
}

/// Bounded admission for the pool: at most `max_keys` distinct connection identities, and at most
/// `max_in_flight_per_key` concurrent requests multiplexed on one connection. Over either bound
/// the pool returns [`RelayQuicRequestError::Backpressure`] rather than queueing without limit.
/// These are functional safety bounds; PERF-D1 tuning is out of scope for this card.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayQuicCapacity {
    max_keys: usize,
    max_in_flight_per_key: usize,
}

impl RelayQuicCapacity {
    /// # Errors
    /// Returns [`RelayQuicRequestError::Config`] when either bound is zero.
    pub fn new(
        max_keys: usize,
        max_in_flight_per_key: usize,
    ) -> Result<Self, RelayQuicRequestError> {
        if max_keys == 0 || max_in_flight_per_key == 0 {
            return Err(RelayQuicRequestError::Config(
                "relay QUIC pool capacity bounds must be nonzero".to_owned(),
            ));
        }
        Ok(Self { max_keys, max_in_flight_per_key })
    }
}

/// Immutable configuration for a [`RelayQuicPool`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayQuicPoolConfig {
    timeouts: RelayQuicTimeouts,
    capacity: RelayQuicCapacity,
}

impl RelayQuicPoolConfig {
    #[must_use]
    pub fn new(timeouts: RelayQuicTimeouts, capacity: RelayQuicCapacity) -> Self {
        Self { timeouts, capacity }
    }

    /// Safe functional defaults for tests and initial wiring: a 5s handshake, 10s request, 20s
    /// idle with a 5s keep-alive, 64 connection identities, and 256 concurrent streams per
    /// connection. These are correctness-oriented bounds, **not** PERF-D1 production numbers.
    ///
    /// # Errors
    /// Returns an error only if the hard-coded defaults ever violate their own validation, which
    /// they do not; the `Result` is kept so the constructor composes with fallible callers.
    pub fn functional_default() -> Result<Self, RelayQuicRequestError> {
        Ok(Self {
            timeouts: RelayQuicTimeouts::new(
                Duration::from_secs(5),
                Duration::from_secs(10),
                Duration::from_secs(20),
                Duration::from_secs(5),
            )?,
            capacity: RelayQuicCapacity::new(64, 256)?,
        })
    }
}

/// A structured, typed outcome for a failed pooled request. T24-A2 must branch on these variants
/// (never re-parse a `TransportError::Quic(String)`): only [`RelayQuicRequestError::RequestTimeout`]
/// and [`RelayQuicRequestError::ConnectionLost`] mean "no complete application response was
/// received and the connection has been closed + evicted", which is the only situation in which
/// the same byte-identical frame may be retried once. A complete [`GatewayQuicResponse`] (any HTTP
/// status) is never an error here.
#[derive(Debug, thiserror::Error)]
pub enum RelayQuicRequestError {
    #[error("relay QUIC pool config error: {0}")]
    Config(String),
    #[error("relay QUIC connect setup failed: {0}")]
    Connect(String),
    #[error("relay QUIC handshake failed or timed out: {0}")]
    Handshake(String),
    #[error("relay QUIC peer authentication/TLS failed: {0}")]
    PeerAuth(String),
    #[error("relay QUIC request timed out with no complete application response: {0}")]
    RequestTimeout(String),
    #[error("relay QUIC connection lost with no complete application response: {0}")]
    ConnectionLost(String),
    #[error(
        "relay QUIC protocol error (partial or invalid response, not a business response): {0}"
    )]
    Protocol(String),
    #[error(
        "relay QUIC pool backpressure rejected request: capacity={capacity}, in_flight={in_flight}"
    )]
    Backpressure { capacity: u64, in_flight: u64 },
    #[error("relay QUIC request encode failed: {0}")]
    Encode(String),
}

impl RelayQuicRequestError {
    /// `true` iff the failure means no complete application response was received **and** the
    /// connection has been closed + evicted — the only case where T24-A2 may re-send the identical
    /// frame once. Never true for a business response (which is `Ok`), backpressure, config, encode,
    /// or a protocol error on a complete-but-invalid frame.
    #[must_use]
    pub fn is_reconnect_retryable(&self) -> bool {
        matches!(self, Self::RequestTimeout(_) | Self::ConnectionLost(_))
    }
}

/// A single cached connection with the pool generation that produced it. The generation lets an
/// eviction target exactly the connection a failed request used, so a slow task cannot delete a
/// newer connection that another task has already installed.
struct PooledConnection {
    client: Arc<QuicGatewayClient>,
    generation: u64,
}

/// Per-key mutable state.
///
/// - `connection` is the single current connection (or none).
/// - `connecting` is the single-flight guard, released by [`SingleFlightGuard`] on **any** exit
///   (normal, error, or future-cancellation) so a cancelled connect never wedges the key.
/// - `in_flight` bounds concurrent streams; each admitted request holds an [`AdmissionGuard`] whose
///   `Drop` releases the slot exactly once even if the request future is cancelled.
/// - `users` counts live [`KeyLease`] holders (a request holds one from state acquisition to
///   completion); eviction refuses any key with `users != 0`.
/// - `retiring` is a two-flag reservation handshake with [`KeyLease`] acquisition so eviction and a
///   concurrent lease can never both win: a leaser increments `users` then aborts if `retiring` is
///   set; an evictor sets `retiring` then aborts if `users != 0`.
#[derive(Default)]
struct PerKeyState {
    connection: ArcSwapOption<PooledConnection>,
    generation: AtomicU64,
    connecting: AtomicBool,
    in_flight: AtomicUsize,
    users: AtomicUsize,
    retiring: AtomicBool,
    notify: Notify,
}

impl PerKeyState {
    /// Evicts the connection iff it is still the given `generation`, leaving a newer replacement
    /// untouched. Returns whether a connection was actually removed.
    fn evict_generation(&self, generation: u64) -> bool {
        let previous = self.connection.rcu(|current| match current.as_deref() {
            Some(connection) if connection.generation == generation => None,
            _ => current.clone(),
        });
        matches!(previous.as_deref(), Some(connection) if connection.generation == generation)
    }

    /// True when the key holds no leaseholders, no in-flight request, is not connecting, and has no
    /// live connection — the only state safe to remove from the map. (Live-but-idle keys are **not**
    /// reclaimed; at `max_keys` they yield [`RelayQuicRequestError::Backpressure`] instead.)
    fn is_safely_reclaimable(&self) -> bool {
        self.users.load(Ordering::SeqCst) == 0
            && self.in_flight.load(Ordering::SeqCst) == 0
            && !self.connecting.load(Ordering::SeqCst)
            && self.connection.load().as_deref().is_none_or(|c| !c.client.is_live())
    }
}

/// RAII single-flight guard: the connect leader holds one for the duration of its connect attempt.
/// `Drop` clears `connecting` and wakes waiters on **every** exit path — normal return, error, or
/// future cancellation — so an aborted leader can never leave the key permanently `connecting`.
struct SingleFlightGuard<'a> {
    state: &'a PerKeyState,
}

impl Drop for SingleFlightGuard<'_> {
    fn drop(&mut self) {
        self.state.connecting.store(false, Ordering::Release);
        self.state.notify.notify_waiters();
    }
}

/// RAII admission guard: held for the lifetime of one in-flight request. The `in_flight` counter is
/// incremented by the caller (to make the capacity decision) and released here; `Drop` also releases
/// the metrics gauge. Because it lives across the request `.await`, a cancelled request future still
/// returns its slot and gauge exactly once.
struct AdmissionGuard<'a> {
    state: &'a PerKeyState,
    metrics: &'a RelayQuicPoolMetrics,
}

impl<'a> AdmissionGuard<'a> {
    fn new(state: &'a PerKeyState, metrics: &'a RelayQuicPoolMetrics) -> Self {
        metrics.on_admit();
        Self { state, metrics }
    }
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        self.state.in_flight.fetch_sub(1, Ordering::AcqRel);
        self.metrics.on_release();
    }
}

/// RAII lease held from the moment a request acquires a key's state until the request finishes.
/// While any lease exists (`users != 0`) the key cannot be evicted, closing the window between
/// `state_for` and request completion in which a concurrent new-key insertion could otherwise
/// remove a state that is connecting or about to be used.
struct KeyLease {
    state: Arc<PerKeyState>,
}

impl Drop for KeyLease {
    fn drop(&mut self) {
        self.state.users.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Instance-scoped, sensitive-free counters. There are no process-global statics and no labels
/// carrying token/grant/PoP/nonce/seed/path content — every field is a plain running total, plus a
/// current/peak gauge for in-flight streams. Tests read [`RelayQuicPool::metrics_snapshot`] to
/// assert exact deltas.
#[derive(Debug, Default)]
struct RelayQuicPoolMetrics {
    pool_hit: AtomicU64,
    pool_miss: AtomicU64,
    connect: AtomicU64,
    reconnect: AtomicU64,
    stale_evict: AtomicU64,
    backpressure: AtomicU64,
    request_timeout: AtomicU64,
    in_flight_current: AtomicU64,
    in_flight_peak: AtomicU64,
}

impl RelayQuicPoolMetrics {
    fn on_admit(&self) {
        let current = self.in_flight_current.fetch_add(1, Ordering::Relaxed) + 1;
        self.in_flight_peak.fetch_max(current, Ordering::Relaxed);
    }

    fn on_release(&self) {
        self.in_flight_current.fetch_sub(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> RelayQuicPoolMetricsSnapshot {
        RelayQuicPoolMetricsSnapshot {
            pool_hit: self.pool_hit.load(Ordering::Relaxed),
            pool_miss: self.pool_miss.load(Ordering::Relaxed),
            connect: self.connect.load(Ordering::Relaxed),
            reconnect: self.reconnect.load(Ordering::Relaxed),
            stale_evict: self.stale_evict.load(Ordering::Relaxed),
            backpressure: self.backpressure.load(Ordering::Relaxed),
            request_timeout: self.request_timeout.load(Ordering::Relaxed),
            in_flight_current: self.in_flight_current.load(Ordering::Relaxed),
            in_flight_peak: self.in_flight_peak.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time, no-sensitive-data view of a pool's counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct RelayQuicPoolMetricsSnapshot {
    pub pool_hit: u64,
    pub pool_miss: u64,
    pub connect: u64,
    pub reconnect: u64,
    pub stale_evict: u64,
    pub backpressure: u64,
    pub request_timeout: u64,
    pub in_flight_current: u64,
    pub in_flight_peak: u64,
}

/// An instance-owned relay QUIC connection pool. Not `Clone`; T24-A2 owns one behind whatever
/// account state it lives in and shares it via `&self`. All methods take `&self`.
pub struct RelayQuicPool {
    config: RelayQuicPoolConfig,
    keys: ArcSwap<HashMap<RelayQuicPoolKey, Arc<PerKeyState>>>,
    write_lock: Mutex<()>,
    metrics: RelayQuicPoolMetrics,
}

impl RelayQuicPool {
    #[must_use]
    pub fn new(config: RelayQuicPoolConfig) -> Self {
        Self {
            config,
            keys: ArcSwap::from_pointee(HashMap::new()),
            write_lock: Mutex::new(()),
            metrics: RelayQuicPoolMetrics::default(),
        }
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> RelayQuicPoolMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Number of distinct connection identities currently tracked (live or not).
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.keys.load().len()
    }

    /// Sends `request` exactly once over a pooled connection for `config`, reusing a live
    /// connection or establishing one (single-flight). Does **not** retry and does **not**
    /// interpret HTTP status: a complete [`GatewayQuicResponse`] of any status is `Ok`. On a
    /// transport failure the underlying connection is closed and evicted (generation-guarded) so a
    /// caller's next `request_once` gets a fresh connection.
    ///
    /// # Errors
    /// Returns a typed [`RelayQuicRequestError`]; see its variants for the retry contract.
    pub async fn request_once(
        &self,
        config: &RelayClientQuicConfig,
        request: &GatewayQuicRequest,
    ) -> Result<GatewayQuicResponse, RelayQuicRequestError> {
        let key = RelayQuicPoolKey::from_config(config)?;
        // The lease pins the key's state (users != 0) for the whole request, so a concurrent
        // new-key insertion cannot evict a state we are connecting on or using.
        let lease = self.acquire_lease(&key).await?;
        let state = &lease.state;
        let connection = self.acquire(state, config).await?;
        let generation = connection.generation;

        // Reserve one in-flight slot; over the per-key bound is backpressure (no guard taken).
        let admitted = state.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        if admitted > self.config.capacity.max_in_flight_per_key {
            state.in_flight.fetch_sub(1, Ordering::AcqRel);
            self.metrics.backpressure.fetch_add(1, Ordering::Relaxed);
            return Err(RelayQuicRequestError::Backpressure {
                capacity: self.config.capacity.max_in_flight_per_key as u64,
                in_flight: admitted as u64,
            });
        }
        // From here the guard owns the slot + gauge release, so a cancelled request future still
        // returns them exactly once.
        let _admission = AdmissionGuard::new(state, &self.metrics);

        match connection.client.request_pooled(request).await {
            Ok(response) => Ok(response),
            Err(phase) => {
                // No complete application response: close and evict this exact generation so the
                // next request reconnects; a newer connection installed by another task is left
                // untouched (generation guard).
                connection.client.close();
                if state.evict_generation(generation) {
                    state.notify.notify_waiters();
                }
                let classified = map_request_phase(phase);
                if matches!(classified, RelayQuicRequestError::RequestTimeout(_)) {
                    self.metrics.request_timeout.fetch_add(1, Ordering::Relaxed);
                }
                Err(classified)
            }
        }
    }

    /// Explicitly evicts the connection for `key` at exactly `generation`, closing it. A no-op if
    /// the current connection is a newer generation (already replaced) or absent. Exposed so
    /// T24-A2 can invalidate a connection it observed failing without racing a concurrent
    /// replacement.
    pub fn invalidate(&self, key: &RelayQuicPoolKey, generation: u64) {
        if let Some(state) = self.keys.load().get(key) {
            if let Some(connection) = state.connection.load().as_deref()
                && connection.generation == generation
            {
                connection.client.close();
            }
            if state.evict_generation(generation) {
                state.notify.notify_waiters();
            }
        }
    }

    /// Acquires a [`KeyLease`] for `key`, creating the per-key state (and, at `max_keys`, reclaiming
    /// a safely-reclaimable key) if needed. The lease is taken via a two-flag `retiring`/`users`
    /// handshake so it can never race an eviction: the leaser increments `users` then re-checks
    /// `retiring` / map membership; if the key is being retired or was removed, it retries under the
    /// write lock (where evictions are serialized).
    async fn acquire_lease(
        &self,
        key: &RelayQuicPoolKey,
    ) -> Result<KeyLease, RelayQuicRequestError> {
        // Fast path: existing key, no lock. Take the lease optimistically, then verify the key was
        // neither retiring nor already removed. The SeqCst on `users` vs the evictor's `retiring`
        // handshake guarantees at most one of {this lease, that eviction} proceeds.
        if let Some(state) = self.keys.load().get(key).map(Arc::clone) {
            state.users.fetch_add(1, Ordering::SeqCst);
            let lease = KeyLease { state: Arc::clone(&state) };
            if !state.retiring.load(Ordering::SeqCst)
                && self.keys.load().get(key).is_some_and(|current| Arc::ptr_eq(current, &state))
            {
                return Ok(lease);
            }
            // Retiring or replaced: drop the optimistic lease and fall through to the locked path.
            drop(lease);
        }

        let _guard = self.write_lock.lock().await;
        // Under the write lock, evictions are serialized; a present key is stable to lease.
        if let Some(state) = self.keys.load().get(key).map(Arc::clone) {
            state.users.fetch_add(1, Ordering::SeqCst);
            return Ok(KeyLease { state });
        }
        let mut next = self.keys.load().as_ref().clone();
        if next.len() >= self.config.capacity.max_keys {
            let evictable = next
                .iter()
                .find(|(_, state)| Self::try_retire(state))
                .map(|(candidate, _)| candidate.clone());
            if let Some(candidate) = evictable {
                next.remove(&candidate);
            } else {
                self.metrics.backpressure.fetch_add(1, Ordering::Relaxed);
                return Err(RelayQuicRequestError::Backpressure {
                    capacity: self.config.capacity.max_keys as u64,
                    in_flight: next.len() as u64,
                });
            }
        }
        let state = Arc::new(PerKeyState::default());
        state.users.fetch_add(1, Ordering::SeqCst);
        next.insert(key.clone(), Arc::clone(&state));
        self.keys.store(Arc::new(next));
        Ok(KeyLease { state })
    }

    /// Eviction side of the reservation handshake (called only under the write lock). Sets
    /// `retiring`, then confirms the key is safely reclaimable; if a concurrent lease has raised
    /// `users`, it clears `retiring` and reports the key not evictable.
    fn try_retire(state: &Arc<PerKeyState>) -> bool {
        state.retiring.store(true, Ordering::SeqCst);
        if state.is_safely_reclaimable() {
            if let Some(connection) = state.connection.load_full() {
                connection.client.close();
            }
            true
        } else {
            state.retiring.store(false, Ordering::SeqCst);
            false
        }
    }

    async fn acquire(
        &self,
        state: &PerKeyState,
        config: &RelayClientQuicConfig,
    ) -> Result<Arc<PooledConnection>, RelayQuicRequestError> {
        loop {
            // Enroll with the Notify BEFORE inspecting pool state so a notify_waiters() firing
            // between the checks and the await is not lost (same rationale as the mesh pool).
            let notified = state.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if let Some(connection) = state.connection.load_full() {
                if connection.client.is_live() {
                    self.metrics.pool_hit.fetch_add(1, Ordering::Relaxed);
                    return Ok(connection);
                }
                self.metrics.stale_evict.fetch_add(1, Ordering::Relaxed);
                state.evict_generation(connection.generation);
            }

            if state
                .connecting
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.metrics.pool_miss.fetch_add(1, Ordering::Relaxed);
                // The guard releases `connecting` + notifies on any exit, including cancellation of
                // this future mid-handshake; without it an aborted leader would wedge the key.
                let _flight = SingleFlightGuard { state };
                return self.connect_and_store(state, config).await;
            }

            let _ = tokio::time::timeout(RELAY_QUIC_ACQUIRE_POLL_INTERVAL, notified.as_mut()).await;
        }
    }

    async fn connect_and_store(
        &self,
        state: &PerKeyState,
        config: &RelayClientQuicConfig,
    ) -> Result<Arc<PooledConnection>, RelayQuicRequestError> {
        let client_config = relay_quic_pool_client_config(
            &config.ca_cert,
            self.config.timeouts.idle,
            self.config.timeouts.keepalive,
        )
        .map_err(map_client_config_error)?;
        let bind_addr = relay_client_quic_bind_addr(config.peer_addr);
        let client = QuicGatewayClient::connect_pooled(
            bind_addr,
            config.peer_addr,
            &config.server_name,
            client_config,
            self.config.timeouts.connect_handshake,
            self.config.timeouts.request,
        )
        .await
        .map_err(map_connect_phase)?;
        let generation = state.generation.fetch_add(1, Ordering::AcqRel) + 1;
        if generation <= 1 {
            self.metrics.connect.fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics.reconnect.fetch_add(1, Ordering::Relaxed);
        }
        let connection = Arc::new(PooledConnection { client: Arc::new(client), generation });
        state.connection.store(Some(Arc::clone(&connection)));
        Ok(connection)
    }

    #[cfg(test)]
    fn debug_connecting(&self, key: &RelayQuicPoolKey) -> bool {
        self.keys.load().get(key).is_some_and(|state| state.connecting.load(Ordering::SeqCst))
    }

    #[cfg(test)]
    fn debug_in_flight(&self, key: &RelayQuicPoolKey) -> usize {
        self.keys.load().get(key).map_or(0, |state| state.in_flight.load(Ordering::SeqCst))
    }
}

/// Maps a structured connect phase to the pool's typed error. A non-timeout handshake failure is
/// reported uniformly as `Handshake` (quinn does not expose a stable peer-auth-vs-transport
/// distinction; see [`QuicConnectPhase`]); only client-config/CA-material construction errors, which
/// the pool detects before any handshake, become `PeerAuth`/`Config`.
fn map_connect_phase(phase: QuicConnectPhase) -> RelayQuicRequestError {
    match phase {
        QuicConnectPhase::Setup(message) => RelayQuicRequestError::Connect(message),
        QuicConnectPhase::HandshakeTimeout => RelayQuicRequestError::Handshake(
            "handshake did not complete before deadline".to_owned(),
        ),
        QuicConnectPhase::HandshakeFailed(message) => RelayQuicRequestError::Handshake(message),
    }
}

fn map_request_phase(phase: QuicRequestPhase) -> RelayQuicRequestError {
    match phase {
        QuicRequestPhase::RequestTimeout => RelayQuicRequestError::RequestTimeout(
            "no complete application response before deadline".to_owned(),
        ),
        QuicRequestPhase::ConnectionLost(message) => RelayQuicRequestError::ConnectionLost(message),
        QuicRequestPhase::Protocol(message) => RelayQuicRequestError::Protocol(message),
    }
}

/// Client-config build failure. CA/TLS material problems are `PeerAuth` (the connection could never
/// authenticate the peer); anything else is a `Config` error.
fn map_client_config_error(error: TransportError) -> RelayQuicRequestError {
    match error {
        TransportError::Tls(message) => RelayQuicRequestError::PeerAuth(message),
        other => RelayQuicRequestError::Config(other.to_string()),
    }
}

// Compile-time proof that the pool and its cached client are shareable across tasks/threads, so
// T24-A2 can hold a `RelayQuicPool` behind shared account state and A1 never needs a global.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RelayQuicPool>();
    assert_send_sync::<Arc<QuicGatewayClient>>();
    assert_send_sync::<RelayQuicRequestError>();
};

#[cfg(test)]
mod tests {
    use super::{
        PerKeyState, RelayQuicBindFamily, RelayQuicCapacity, RelayQuicPoolConfig, RelayQuicPoolKey,
        RelayQuicPoolMetrics, RelayQuicRequestError, RelayQuicTimeouts, SingleFlightGuard,
        map_connect_phase, map_request_phase,
    };
    use crate::{QuicConnectPhase, QuicRequestPhase};
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn pool_key_differs_on_ca_content_not_path() {
        let base =
            RelayQuicPoolKey::for_test(addr(7001), "relay", [1_u8; 32], RelayQuicBindFamily::V4);
        let other_ca =
            RelayQuicPoolKey::for_test(addr(7001), "relay", [2_u8; 32], RelayQuicBindFamily::V4);
        let other_peer =
            RelayQuicPoolKey::for_test(addr(7002), "relay", [1_u8; 32], RelayQuicBindFamily::V4);
        let other_name =
            RelayQuicPoolKey::for_test(addr(7001), "relay-b", [1_u8; 32], RelayQuicBindFamily::V4);
        let other_family =
            RelayQuicPoolKey::for_test(addr(7001), "relay", [1_u8; 32], RelayQuicBindFamily::V6);
        assert_ne!(base, other_ca, "different CA content must be a different key");
        assert_ne!(base, other_peer, "different peer must be a different key");
        assert_ne!(base, other_name, "different server name must be a different key");
        assert_ne!(base, other_family, "different bind family must be a different key");
        assert_eq!(
            base,
            RelayQuicPoolKey::for_test(addr(7001), "relay", [1_u8; 32], RelayQuicBindFamily::V4),
            "identical identity must be the same key"
        );
    }

    #[test]
    fn timeouts_reject_zero_and_bad_order() {
        assert!(
            RelayQuicTimeouts::new(
                Duration::ZERO,
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(
            RelayQuicTimeouts::new(
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .is_err(),
            "keepalive == idle must be rejected"
        );
        assert!(
            RelayQuicTimeouts::new(
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(1),
            )
            .is_ok()
        );
    }

    #[test]
    fn capacity_rejects_zero_bounds() {
        assert!(RelayQuicCapacity::new(0, 1).is_err());
        assert!(RelayQuicCapacity::new(1, 0).is_err());
        assert!(RelayQuicCapacity::new(1, 1).is_ok());
    }

    #[test]
    fn functional_default_is_valid() {
        assert!(RelayQuicPoolConfig::functional_default().is_ok());
    }

    #[test]
    fn request_phase_maps_to_typed_error_without_string_parsing() {
        // These assert the mapping from the *structured* phase (not from parsing quinn text): a
        // timeout is reconnect-retryable, a connection loss is reconnect-retryable, a protocol
        // (complete-but-invalid frame) is not.
        let timeout = map_request_phase(QuicRequestPhase::RequestTimeout);
        assert!(matches!(timeout, RelayQuicRequestError::RequestTimeout(_)));
        assert!(timeout.is_reconnect_retryable());

        let lost = map_request_phase(QuicRequestPhase::ConnectionLost("reset".to_owned()));
        assert!(matches!(lost, RelayQuicRequestError::ConnectionLost(_)));
        assert!(lost.is_reconnect_retryable());

        let protocol = map_request_phase(QuicRequestPhase::Protocol("bad frame".to_owned()));
        assert!(matches!(protocol, RelayQuicRequestError::Protocol(_)));
        assert!(
            !protocol.is_reconnect_retryable(),
            "a complete-but-invalid response is not a reconnect-retry situation"
        );
    }

    #[test]
    fn connect_phase_maps_to_typed_error_without_string_parsing() {
        assert!(matches!(
            map_connect_phase(QuicConnectPhase::HandshakeTimeout),
            RelayQuicRequestError::Handshake(_)
        ));
        assert!(matches!(
            map_connect_phase(QuicConnectPhase::HandshakeFailed("tls reject".to_owned())),
            RelayQuicRequestError::Handshake(_)
        ));
        assert!(matches!(
            map_connect_phase(QuicConnectPhase::Setup("bind failed".to_owned())),
            RelayQuicRequestError::Connect(_)
        ));
    }

    #[test]
    fn single_flight_guard_releases_connecting_on_drop() {
        // Simulates a leader that wins the single-flight then is cancelled: the guard's Drop must
        // clear `connecting` so a subsequent leader can proceed (no permanent wedge).
        let state = PerKeyState::default();
        assert!(
            state
                .connecting
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        );
        {
            let _guard = SingleFlightGuard { state: &state };
            assert!(state.connecting.load(Ordering::SeqCst));
        }
        assert!(!state.connecting.load(Ordering::SeqCst), "guard Drop must clear connecting");
    }

    #[test]
    fn safely_reclaimable_requires_no_users_no_in_flight_not_connecting() {
        let state = PerKeyState::default();
        assert!(state.is_safely_reclaimable(), "fresh empty state is reclaimable");
        state.users.fetch_add(1, Ordering::SeqCst);
        assert!(!state.is_safely_reclaimable(), "a leaseholder blocks reclamation");
        state.users.fetch_sub(1, Ordering::SeqCst);
        state.in_flight.fetch_add(1, Ordering::SeqCst);
        assert!(!state.is_safely_reclaimable(), "an in-flight request blocks reclamation");
        state.in_flight.fetch_sub(1, Ordering::SeqCst);
        state.connecting.store(true, Ordering::SeqCst);
        assert!(!state.is_safely_reclaimable(), "a connecting leader blocks reclamation");
    }

    #[test]
    fn in_flight_gauge_tracks_current_and_peak() {
        let metrics = RelayQuicPoolMetrics::default();
        metrics.on_admit();
        metrics.on_admit();
        let peak = metrics.snapshot();
        assert_eq!(peak.in_flight_current, 2);
        assert_eq!(peak.in_flight_peak, 2);
        metrics.on_release();
        let after = metrics.snapshot();
        assert_eq!(after.in_flight_current, 1);
        assert_eq!(after.in_flight_peak, 2, "peak is a high-water mark");
    }
}

/// Live-QUIC tests against an in-process loopback relay echo server built from an rcgen
/// self-signed cert (used as both server certificate and client trust root). These prove
/// connection reuse, CA isolation, stale/reconnect, generation-guarded eviction, business-status
/// pass-through, capacity backpressure, and typed connect failure — all without touching the
/// production relay. Tests build their own multi-thread runtime (the crate does not enable the
/// tokio `macros` feature, so `#[tokio::test]` is unavailable).
#[cfg(test)]
mod live_tests {
    use super::{
        RelayQuicCapacity, RelayQuicPool, RelayQuicPoolConfig, RelayQuicPoolKey,
        RelayQuicRequestError, RelayQuicTimeouts,
    };
    use crate::quic_gateway::{read_quic_raw_frame, write_quic_raw_frame};
    use crate::tls_config::ensure_ring_crypto_provider_installed;
    use crate::{GatewayQuicRequest, GatewayQuicResponse, RelayClientQuicConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::io::Write as _;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::sync::Notify;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const RELAY_SERVER_NAME: &str = "ramflux-relay";

    #[derive(Clone, Copy)]
    struct EchoBehavior {
        status: u16,
        close_after_stream: bool,
        response_delay: Duration,
    }

    impl EchoBehavior {
        fn ok() -> Self {
            Self { status: 200, close_after_stream: false, response_delay: Duration::ZERO }
        }

        fn status(status: u16) -> Self {
            Self { status, close_after_stream: false, response_delay: Duration::ZERO }
        }

        fn close_after_stream() -> Self {
            Self { status: 200, close_after_stream: true, response_delay: Duration::ZERO }
        }

        fn slow(delay: Duration) -> Self {
            Self { status: 200, close_after_stream: false, response_delay: delay }
        }
    }

    struct TestCert {
        cert_der: CertificateDer<'static>,
        key_der: PrivateKeyDer<'static>,
        ca_path: PathBuf,
    }

    fn make_cert(tag: &str) -> Result<TestCert, Box<dyn std::error::Error>> {
        let certified = rcgen::generate_simple_self_signed(vec![RELAY_SERVER_NAME.to_owned()])?;
        let cert_der = CertificateDer::from(certified.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()));
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let ca_path = std::env::temp_dir()
            .join(format!("ramflux-relay-pool-ca-{tag}-{}-{nanos}.pem", std::process::id()));
        let mut file = std::fs::File::create(&ca_path)?;
        file.write_all(certified.cert.pem().as_bytes())?;
        Ok(TestCert { cert_der, key_der, ca_path })
    }

    fn multi_thread_runtime() -> Result<tokio::runtime::Runtime, Box<dyn std::error::Error>> {
        Ok(tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?)
    }

    fn relay_config(
        addr: SocketAddr,
        ca_path: &std::path::Path,
    ) -> Result<RelayClientQuicConfig, Box<dyn std::error::Error>> {
        Ok(RelayClientQuicConfig::new(&addr.to_string(), RELAY_SERVER_NAME, ca_path)?)
    }

    fn get_request() -> GatewayQuicRequest {
        GatewayQuicRequest {
            method: "GET".to_owned(),
            path: "/relay/v1/object/get_chunk".to_owned(),
            body: serde_json::Value::Null,
        }
    }

    /// Spawns a loopback QUIC echo server; returns its address and a live-connection counter.
    /// Must be called from within a tokio runtime (it uses `tokio::spawn`); it does not itself
    /// await, so it is a plain synchronous constructor.
    fn spawn_echo_server(
        cert: &TestCert,
        behavior: EchoBehavior,
    ) -> Result<(SocketAddr, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
        ensure_ring_crypto_provider_installed();
        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert.cert_der.clone()],
            cert.key_der.clone_key(),
        )?;
        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
        let addr = endpoint.local_addr()?;
        let connects = Arc::new(AtomicUsize::new(0));
        let connects_task = Arc::clone(&connects);
        tokio::spawn(async move {
            while let Some(connecting) = endpoint.accept().await {
                connects_task.fetch_add(1, Ordering::Relaxed);
                let Ok(connection) = connecting.await else {
                    continue;
                };
                tokio::spawn(async move {
                    loop {
                        let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                            break;
                        };
                        if read_quic_raw_frame(&mut recv).await.is_err() {
                            break;
                        }
                        if !behavior.response_delay.is_zero() {
                            tokio::time::sleep(behavior.response_delay).await;
                        }
                        let response = GatewayQuicResponse {
                            status: behavior.status,
                            body: serde_json::json!({ "echo": true }),
                        };
                        let Ok(body) = serde_json::to_vec(&response) else {
                            break;
                        };
                        if write_quic_raw_frame(&mut send, &body).await.is_err() {
                            break;
                        }
                        let _ = quinn::SendStream::finish(&mut send);
                        if behavior.close_after_stream {
                            // Let the finished response flush to the client before abruptly
                            // closing, so the *first* request reads a clean 200 and only a
                            // *subsequent* request observes the dead connection.
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            connection.close(quinn::VarInt::from_u32(0), b"echo-close");
                            break;
                        }
                    }
                });
            }
        });
        Ok((addr, connects))
    }

    #[test]
    fn same_key_reuses_a_single_handshake() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert = make_cert("reuse")?;
            let (addr, connects) = spawn_echo_server(&cert, EchoBehavior::ok())?;
            let config = relay_config(addr, &cert.ca_path)?;
            let pool = RelayQuicPool::new(RelayQuicPoolConfig::functional_default()?);

            let first = pool.request_once(&config, &get_request()).await?;
            let second = pool.request_once(&config, &get_request()).await?;
            assert_eq!(first.status, 200);
            assert_eq!(second.status, 200);

            assert_eq!(connects.load(Ordering::Relaxed), 1, "two requests, one handshake");
            let metrics = pool.metrics_snapshot();
            assert_eq!(metrics.connect, 1);
            assert_eq!(metrics.pool_miss, 1);
            assert_eq!(metrics.pool_hit, 1);
            assert_eq!(metrics.reconnect, 0);
            assert_eq!(pool.tracked_keys(), 1);
            Ok(())
        })
    }

    #[test]
    fn concurrent_misses_open_a_single_connection() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert = make_cert("concurrent")?;
            let (addr, connects) = spawn_echo_server(&cert, EchoBehavior::ok())?;
            let config = relay_config(addr, &cert.ca_path)?;
            let pool = Arc::new(RelayQuicPool::new(RelayQuicPoolConfig::functional_default()?));

            let mut handles = Vec::new();
            for _index in 0..16 {
                let pool = Arc::clone(&pool);
                let config = config.clone();
                handles.push(tokio::spawn(async move {
                    pool.request_once(&config, &get_request()).await.map(|response| response.status)
                }));
            }
            for handle in handles {
                assert_eq!(handle.await??, 200);
            }
            assert_eq!(
                connects.load(Ordering::Relaxed),
                1,
                "single-flight: concurrent misses share one connection"
            );
            let metrics = pool.metrics_snapshot();
            assert_eq!(metrics.connect, 1);
            assert_eq!(metrics.pool_miss, 1);
            assert_eq!(metrics.in_flight_current, 0, "all requests released");
            Ok(())
        })
    }

    #[test]
    fn different_ca_content_is_isolated_and_cross_ca_fails() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert_a = make_cert("iso-a")?;
            let cert_b = make_cert("iso-b")?;
            let (addr_a, connects_a) = spawn_echo_server(&cert_a, EchoBehavior::ok())?;
            let (addr_b, connects_b) = spawn_echo_server(&cert_b, EchoBehavior::ok())?;
            let config_a = relay_config(addr_a, &cert_a.ca_path)?;
            let config_b = relay_config(addr_b, &cert_b.ca_path)?;
            let pool = RelayQuicPool::new(RelayQuicPoolConfig::functional_default()?);

            assert_eq!(pool.request_once(&config_a, &get_request()).await?.status, 200);
            assert_eq!(pool.request_once(&config_b, &get_request()).await?.status, 200);
            assert_eq!(pool.tracked_keys(), 2, "distinct CA content -> distinct keys");
            assert_eq!(connects_a.load(Ordering::Relaxed), 1);
            assert_eq!(connects_b.load(Ordering::Relaxed), 1);

            // Server A trusted only under CA-A: reaching A with CA-B must fail peer auth, not reuse.
            let cross = relay_config(addr_a, &cert_b.ca_path)?;
            let error = pool.request_once(&cross, &get_request()).await.err();
            assert!(
                matches!(
                    error,
                    Some(RelayQuicRequestError::PeerAuth(_) | RelayQuicRequestError::Handshake(_))
                ),
                "cross-CA connect must fail closed: {error:?}"
            );
            Ok(())
        })
    }

    #[test]
    fn invalidate_forces_reconnect_and_guards_old_generation() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert = make_cert("invalidate")?;
            let (addr, connects) = spawn_echo_server(&cert, EchoBehavior::ok())?;
            let config = relay_config(addr, &cert.ca_path)?;
            let pool = RelayQuicPool::new(RelayQuicPoolConfig::functional_default()?);
            let key = RelayQuicPoolKey::from_config(&config)?;

            assert_eq!(pool.request_once(&config, &get_request()).await?.status, 200);
            assert_eq!(connects.load(Ordering::Relaxed), 1);

            // Evict generation 1 -> next request reconnects as generation 2.
            pool.invalidate(&key, 1);
            assert_eq!(pool.request_once(&config, &get_request()).await?.status, 200);
            assert_eq!(connects.load(Ordering::Relaxed), 2, "reconnect after invalidate");
            assert_eq!(pool.metrics_snapshot().reconnect, 1);

            // A stale invalidate for the old generation 1 must NOT remove the live generation 2.
            pool.invalidate(&key, 1);
            assert_eq!(pool.request_once(&config, &get_request()).await?.status, 200);
            assert_eq!(
                connects.load(Ordering::Relaxed),
                2,
                "stale-generation invalidate must not drop the newer connection"
            );
            assert_eq!(pool.metrics_snapshot().reconnect, 1, "no extra reconnect");
            Ok(())
        })
    }

    #[test]
    fn server_close_is_detected_and_triggers_reconnect() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert = make_cert("stale")?;
            let (addr, connects) = spawn_echo_server(&cert, EchoBehavior::close_after_stream())?;
            let config = relay_config(addr, &cert.ca_path)?;
            let pool = RelayQuicPool::new(RelayQuicPoolConfig::functional_default()?);

            assert_eq!(pool.request_once(&config, &get_request()).await?.status, 200);
            assert_eq!(connects.load(Ordering::Relaxed), 1);

            // The server closed the connection after the first stream. The next request must
            // detect the stale connection and reconnect (bounded retry to absorb close latency).
            let mut reconnected = false;
            for _attempt in 0..50 {
                let status = pool.request_once(&config, &get_request()).await.map(|r| r.status);
                if connects.load(Ordering::Relaxed) >= 2 {
                    reconnected = true;
                    assert_eq!(status.unwrap_or(0), 200);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(reconnected, "stale connection must be evicted and reconnected");
            // The dead connection is evicted either at acquire time (is_live == false) or on the
            // failing request; both converge on a fresh handshake. Assert the observable outcome.
            let metrics = pool.metrics_snapshot();
            assert!(metrics.reconnect >= 1, "a fresh connection must have been established");
            assert!(
                metrics.stale_evict >= 1 || metrics.reconnect >= 1,
                "the dead connection must have been evicted"
            );
            Ok(())
        })
    }

    #[test]
    fn business_error_status_is_returned_ok_and_not_evicted() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert = make_cert("status")?;
            let (addr, connects) = spawn_echo_server(&cert, EchoBehavior::status(404))?;
            let config = relay_config(addr, &cert.ca_path)?;
            let pool = RelayQuicPool::new(RelayQuicPoolConfig::functional_default()?);

            let response = pool.request_once(&config, &get_request()).await?;
            assert_eq!(response.status, 404, "pool returns the business status verbatim");
            // A complete 404 is not a transport failure: the connection stays pooled and reused.
            assert_eq!(pool.request_once(&config, &get_request()).await?.status, 404);
            assert_eq!(connects.load(Ordering::Relaxed), 1, "no eviction on business status");
            assert_eq!(pool.metrics_snapshot().pool_hit, 1);
            Ok(())
        })
    }

    #[test]
    fn max_keys_capacity_rejects_with_backpressure() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert_a = make_cert("cap-a")?;
            let cert_b = make_cert("cap-b")?;
            let (addr_a, _connects_a) = spawn_echo_server(&cert_a, EchoBehavior::ok())?;
            let (addr_b, _connects_b) = spawn_echo_server(&cert_b, EchoBehavior::ok())?;
            let config_a = relay_config(addr_a, &cert_a.ca_path)?;
            let config_b = relay_config(addr_b, &cert_b.ca_path)?;
            let config = RelayQuicPoolConfig::new(
                RelayQuicTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(10),
                    Duration::from_secs(20),
                    Duration::from_secs(5),
                )?,
                RelayQuicCapacity::new(1, 64)?,
            );
            let pool = RelayQuicPool::new(config);

            // First key occupies the single slot with a live connection.
            assert_eq!(pool.request_once(&config_a, &get_request()).await?.status, 200);
            // Second, distinct key cannot evict a live+idle key -> backpressure.
            let error = pool.request_once(&config_b, &get_request()).await.err();
            assert!(
                matches!(error, Some(RelayQuicRequestError::Backpressure { capacity: 1, .. })),
                "max_keys=1 must reject a second live key: {error:?}"
            );
            assert!(pool.metrics_snapshot().backpressure >= 1);
            Ok(())
        })
    }

    #[test]
    fn max_in_flight_capacity_rejects_second_concurrent_stream() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert = make_cert("inflight")?;
            let (addr, _connects) =
                spawn_echo_server(&cert, EchoBehavior::slow(Duration::from_millis(400)))?;
            let config = relay_config(addr, &cert.ca_path)?;
            let config_owned = config.clone();
            let pool = Arc::new(RelayQuicPool::new(RelayQuicPoolConfig::new(
                RelayQuicTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(10),
                    Duration::from_secs(20),
                    Duration::from_secs(5),
                )?,
                RelayQuicCapacity::new(8, 1)?,
            )));

            // First request occupies the single in-flight slot for ~400ms (slow server).
            let pool_bg = Arc::clone(&pool);
            let slow = tokio::spawn(async move {
                pool_bg.request_once(&config_owned, &get_request()).await.map(|r| r.status)
            });
            // Give the first request time to establish + occupy the slot.
            tokio::time::sleep(Duration::from_millis(120)).await;
            let contended = pool.request_once(&config, &get_request()).await.err();
            assert!(
                matches!(contended, Some(RelayQuicRequestError::Backpressure { capacity: 1, .. })),
                "second concurrent stream over max_in_flight=1 must be rejected: {contended:?}"
            );
            assert_eq!(slow.await??, 200, "the first request still completes");
            Ok(())
        })
    }

    #[test]
    fn connect_failure_is_typed_and_not_cached() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert = make_cert("deadport")?;
            // A CA file that exists but points at a port with no server: connect must fail typed.
            let dead: SocketAddr = "127.0.0.1:1".parse()?;
            let config = relay_config(dead, &cert.ca_path)?;
            let pool = RelayQuicPool::new(RelayQuicPoolConfig::new(
                RelayQuicTimeouts::new(
                    Duration::from_millis(300),
                    Duration::from_secs(1),
                    Duration::from_secs(20),
                    Duration::from_secs(5),
                )?,
                RelayQuicCapacity::new(8, 8)?,
            ));

            let error = pool.request_once(&config, &get_request()).await.err();
            assert!(
                matches!(
                    error,
                    Some(
                        RelayQuicRequestError::Handshake(_)
                            | RelayQuicRequestError::Connect(_)
                            | RelayQuicRequestError::PeerAuth(_)
                    )
                ),
                "dead-port connect must be a typed connect/handshake failure: {error:?}"
            );
            // No successful connection was cached (connect metric stays 0).
            assert_eq!(pool.metrics_snapshot().connect, 0);
            assert!(pool.metrics_snapshot().pool_miss >= 1);
            Ok(())
        })
    }

    // ---- CTRL-054 cancellation-safety closure tests ----
    // Deterministic (JoinHandle::abort + Notify barriers + real-state polling; no sleep-guessing of
    // timing windows). They prove that a cancelled rfd/bus future never wedges the pool.

    /// A gate a barrier server's stream handlers wait on before responding, so a test can hold a
    /// request in-flight and then release it deterministically (an `AtomicBool` condition + a
    /// `Notify`, not a timing window). `received` fires once per stream after the request is read.
    struct ServerGate {
        received: Notify,
        open: std::sync::atomic::AtomicBool,
        release: Notify,
    }

    impl ServerGate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                received: Notify::new(),
                open: std::sync::atomic::AtomicBool::new(false),
                release: Notify::new(),
            })
        }

        fn open_gate(&self) {
            self.open.store(true, Ordering::SeqCst);
            self.release.notify_waiters();
        }

        async fn wait_open(&self) {
            loop {
                let notified = self.release.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.open.load(Ordering::SeqCst) {
                    return;
                }
                notified.await;
            }
        }
    }

    /// A server that, per bidirectional stream (each in its own task, so streams never block each
    /// other), signals `received` after reading the request, waits for the gate to open, then
    /// responds 200.
    fn spawn_barrier_server(
        cert: &TestCert,
        gate: Arc<ServerGate>,
    ) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        ensure_ring_crypto_provider_installed();
        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert.cert_der.clone()],
            cert.key_der.clone_key(),
        )?;
        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
        let addr = endpoint.local_addr()?;
        tokio::spawn(async move {
            while let Some(connecting) = endpoint.accept().await {
                let Ok(connection) = connecting.await else {
                    continue;
                };
                let gate = Arc::clone(&gate);
                tokio::spawn(async move {
                    loop {
                        let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                            break;
                        };
                        let gate = Arc::clone(&gate);
                        tokio::spawn(async move {
                            if read_quic_raw_frame(&mut recv).await.is_err() {
                                return;
                            }
                            gate.received.notify_one();
                            gate.wait_open().await;
                            let response = GatewayQuicResponse {
                                status: 200,
                                body: serde_json::json!({ "echo": true }),
                            };
                            let Ok(body) = serde_json::to_vec(&response) else {
                                return;
                            };
                            if write_quic_raw_frame(&mut send, &body).await.is_err() {
                                return;
                            }
                            let _ = quinn::SendStream::finish(&mut send);
                        });
                    }
                });
            }
        });
        Ok(addr)
    }

    async fn poll_until<F: Fn() -> bool>(predicate: F, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        predicate()
    }

    #[test]
    fn connect_leader_abort_releases_single_flight_and_next_request_proceeds() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert = make_cert("leader-abort")?;
            // 192.0.2.0/24 (TEST-NET-1) is unroutable: the handshake stalls until timeout, so the
            // leader is reliably mid-connect when we abort it.
            let blackhole: SocketAddr = "192.0.2.1:9".parse()?;
            let config = relay_config(blackhole, &cert.ca_path)?;
            let pool = Arc::new(RelayQuicPool::new(RelayQuicPoolConfig::new(
                RelayQuicTimeouts::new(
                    Duration::from_secs(2),
                    Duration::from_secs(5),
                    Duration::from_secs(20),
                    Duration::from_secs(5),
                )?,
                RelayQuicCapacity::new(8, 8)?,
            )));
            let key = RelayQuicPoolKey::from_config(&config)?;

            let pool_leader = Arc::clone(&pool);
            let config_leader = config.clone();
            let leader = tokio::spawn(async move {
                pool_leader.request_once(&config_leader, &get_request()).await.map(|_r| ())
            });

            // Wait until the leader is actually mid-connect (real state, not a guessed sleep).
            assert!(
                poll_until(|| pool.debug_connecting(&key), Duration::from_secs(5)).await,
                "leader should become the single-flight connector"
            );
            leader.abort();
            // The single-flight guard must clear `connecting` on cancellation; without it this
            // would stay true forever and the next request would poll-loop indefinitely.
            assert!(
                poll_until(|| !pool.debug_connecting(&key), Duration::from_secs(5)).await,
                "aborted leader must release the single-flight guard"
            );

            // A subsequent request must be able to proceed (become leader) and return a *typed*
            // failure within a bounded time rather than hanging on a wedged key.
            let Ok(inner) = tokio::time::timeout(
                Duration::from_secs(6),
                pool.request_once(&config, &get_request()),
            )
            .await
            else {
                return Err("next request must not hang on a wedged single-flight".into());
            };
            assert!(matches!(
                inner.err(),
                Some(RelayQuicRequestError::Handshake(_) | RelayQuicRequestError::Connect(_))
            ));
            Ok(())
        })
    }

    #[test]
    fn request_abort_releases_in_flight_and_next_request_not_backpressured() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert = make_cert("req-abort")?;
            let gate = ServerGate::new();
            let addr = spawn_barrier_server(&cert, Arc::clone(&gate))?;
            let config = relay_config(addr, &cert.ca_path)?;
            // max_in_flight_per_key = 1: a leaked slot would permanently backpressure the key.
            let pool = Arc::new(RelayQuicPool::new(RelayQuicPoolConfig::new(
                RelayQuicTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(10),
                    Duration::from_secs(20),
                    Duration::from_secs(5),
                )?,
                RelayQuicCapacity::new(8, 1)?,
            )));
            let key = RelayQuicPoolKey::from_config(&config)?;

            let pool_a = Arc::clone(&pool);
            let config_a = config.clone();
            let request_a = tokio::spawn(async move {
                pool_a.request_once(&config_a, &get_request()).await.map(|_r| ())
            });
            // Deterministically wait until the server has the request (A occupies the slot).
            gate.received.notified().await;
            assert_eq!(pool.debug_in_flight(&key), 1, "request A holds the only in-flight slot");

            // Abort A mid-request: the admission guard's Drop must return the slot + gauge.
            request_a.abort();
            assert!(
                poll_until(|| pool.debug_in_flight(&key) == 0, Duration::from_secs(5)).await,
                "aborted request must release its in-flight slot"
            );
            assert_eq!(pool.metrics_snapshot().in_flight_current, 0, "gauge released on cancel");

            // The next request must not be backpressured by the leaked slot.
            gate.open_gate();
            let next = pool.request_once(&config, &get_request()).await;
            assert!(
                matches!(&next, Ok(response) if response.status == 200),
                "next request must succeed, not hit a leaked-slot backpressure: {next:?}"
            );
            Ok(())
        })
    }

    #[test]
    fn active_key_is_not_evicted_under_max_keys_pressure() -> TestResult {
        let runtime = multi_thread_runtime()?;
        runtime.block_on(async {
            let cert_a = make_cert("active-a")?;
            let cert_b = make_cert("active-b")?;
            let gate = ServerGate::new();
            let addr_a = spawn_barrier_server(&cert_a, Arc::clone(&gate))?;
            let (addr_b, _connects_b) = spawn_echo_server(&cert_b, EchoBehavior::ok())?;
            let config_a = relay_config(addr_a, &cert_a.ca_path)?;
            let config_b = relay_config(addr_b, &cert_b.ca_path)?;
            // max_keys = 1: key B may only be admitted by reclaiming key A — which must be refused
            // while A is actively in use (leased + in-flight).
            let pool = Arc::new(RelayQuicPool::new(RelayQuicPoolConfig::new(
                RelayQuicTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(10),
                    Duration::from_secs(20),
                    Duration::from_secs(5),
                )?,
                RelayQuicCapacity::new(1, 8)?,
            )));

            let pool_a = Arc::clone(&pool);
            let config_a_owned = config_a.clone();
            let request_a = tokio::spawn(async move {
                pool_a.request_once(&config_a_owned, &get_request()).await.map(|r| r.status)
            });
            gate.received.notified().await; // A is now leased + in-flight on the single key slot.

            // B cannot evict the active key A -> backpressure (never a second key, never orphaned).
            let error = pool.request_once(&config_b, &get_request()).await.err();
            assert!(
                matches!(error, Some(RelayQuicRequestError::Backpressure { capacity: 1, .. })),
                "an active key must not be evicted under max_keys pressure: {error:?}"
            );
            assert_eq!(pool.tracked_keys(), 1, "no second key was inserted");

            gate.open_gate();
            assert_eq!(request_a.await??, 200, "request A still completes");
            Ok(())
        })
    }
}
