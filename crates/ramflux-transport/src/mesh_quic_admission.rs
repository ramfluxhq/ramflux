// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant admission candidate. Production listeners do not construct this driver.
//! Protocol entries, including closing entries, are capped using Quinn's endpoint
//! accounting. Source holds provide fairness only. Quinn 0.11.11's raw packet
//! event queues remain an upstream risk; flow-control windows do not bound them.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::mesh_quic::{MeshQuicConnection, quinn_peer_spiffe_uri};
use crate::tls_config::{MeshRootPemProvider, admission::server_config};
use crate::{MeshTlsConfig, TransportError};

/// Explicit candidate ceilings. Lower operator settings are preserved.
#[derive(Clone, Copy, Debug)]
pub struct MeshQuicAdmissionLimits {
    pub handshakes: usize,
    pub per_source: usize,
    pub protocol_entries: usize,
    pub ready: usize,
    pub ready_per_source: usize,
    pub deadline: Duration,
    /// Best-effort source fairness hold, never a protocol retirement guarantee.
    pub idle_timeout: Duration,
    pub bidi_streams: u32,
    pub receive_window: u32,
    pub stream_receive_window: u32,
    pub send_window: u64,
}

impl Default for MeshQuicAdmissionLimits {
    fn default() -> Self {
        Self {
            handshakes: 64,
            per_source: 4,
            protocol_entries: 64,
            ready: 16,
            ready_per_source: 4,
            deadline: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            bidi_streams: 64,
            receive_window: 16 * 1024 * 1024,
            stream_receive_window: 1024 * 1024,
            send_window: 16 * 1024 * 1024,
        }
    }
}

impl MeshQuicAdmissionLimits {
    #[must_use]
    pub fn bounded(mut self) -> Self {
        self.handshakes = self.handshakes.clamp(1, 64);
        self.per_source = self.per_source.clamp(1, 4);
        self.protocol_entries = self.protocol_entries.clamp(1, 64);
        self.ready = self.ready.clamp(1, 16);
        self.ready_per_source = self.ready_per_source.clamp(1, 4);
        self.deadline = self.deadline.clamp(Duration::from_millis(1), Duration::from_secs(10));
        self.idle_timeout =
            self.idle_timeout.clamp(Duration::from_millis(1), Duration::from_secs(30));
        self.bidi_streams = self.bidi_streams.clamp(1, 64);
        self.receive_window = self.receive_window.clamp(1, 16 * 1024 * 1024);
        self.stream_receive_window = self.stream_receive_window.clamp(1, 1024 * 1024);
        self.send_window = self.send_window.clamp(1, 16 * 1024 * 1024);
        self
    }
}

/// Refusal counters have no source-address labels.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MeshQuicHandshakeSnapshot {
    pub listener_cap: u64,
    pub source_cap: u64,
    pub ready_cap: u64,
    pub timeout: u64,
    pub peer_error: u64,
    pub cancelled: u64,
    pub handshaking: usize,
    pub ready: usize,
    pub sources: usize,
    pub reservations: usize,
    pub protocol_entries: usize,
}

#[derive(Clone)]
pub struct MeshQuicHandshakeMetrics(Arc<Mutex<Accounting>>);

impl MeshQuicHandshakeMetrics {
    #[must_use]
    pub fn snapshot(&self) -> MeshQuicHandshakeSnapshot {
        let state = lock(&self.0);
        let mut result = state.counters;
        result.reservations = state.entries.len();
        result.handshaking =
            state.entries.values().filter(|entry| entry.phase == Phase::Handshake).count();
        result.ready = state.entries.values().filter(|entry| entry.phase == Phase::Ready).count();
        let mut sources = std::collections::HashSet::new();
        for entry in state.entries.values() {
            sources.insert(entry.ip);
        }
        result.sources = sources.len();
        result
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Handshake,
    Ready,
    Holding,
}
struct Entry {
    ip: IpAddr,
    phase: Phase,
    release_at: Option<Instant>,
    connection: Option<MeshQuicConnection>,
}
#[derive(Default)]
struct Accounting {
    entries: HashMap<u64, Entry>,
    next: u64,
    counters: MeshQuicHandshakeSnapshot,
    stopping: bool,
}

fn lock(state: &Mutex<Accounting>) -> MutexGuard<'_, Accounting> {
    state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn normalized(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip @ IpAddr::V4(_) => ip,
    }
}

struct Reservation {
    id: u64,
    metrics: MeshQuicHandshakeMetrics,
    hold: Duration,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(entry) = lock(&self.metrics.0).entries.get_mut(&self.id) {
            entry.phase = Phase::Holding;
            entry.release_at = Some(Instant::now() + self.hold);
        }
    }
}

/// A bounded ready result retains its phase/source reservation until dispatch.
/// Dropping an undispatched result closes its connection.
pub struct MeshQuicReadyConnection {
    reservation: Reservation,
}

impl MeshQuicReadyConnection {
    /// Transfer authenticated ownership to the established-session owner.
    /// # Errors
    /// Refuses dispatch after the driver has started cancellation.
    pub fn into_connection(self) -> Result<MeshQuicConnection, TransportError> {
        let mut state = lock(&self.reservation.metrics.0);
        if state.stopping {
            return Err(TransportError::Quic("mesh admission cancelled".into()));
        }
        state
            .entries
            .remove(&self.reservation.id)
            .and_then(|entry| entry.connection)
            .ok_or_else(|| TransportError::Quic("missing ready connection".into()))
    }
}

impl Drop for MeshQuicReadyConnection {
    fn drop(&mut self) {
        if let Some(connection) = lock(&self.reservation.metrics.0)
            .entries
            .get_mut(&self.reservation.id)
            .and_then(|entry| entry.connection.take())
        {
            connection.connection.close(0_u32.into(), b"undispatched");
        }
    }
}

/// Exclusive incoming owner: only this task calls `Incoming::accept` on its endpoint.
/// Quinn's connection drivers run independently of handshake/application tasks.
pub struct MeshQuicHandshakeDriver {
    endpoint: quinn::Endpoint,
    limits: MeshQuicAdmissionLimits,
    allowed: Arc<Vec<String>>,
    metrics: MeshQuicHandshakeMetrics,
    ready: mpsc::Sender<MeshQuicReadyConnection>,
}

impl MeshQuicHandshakeDriver {
    /// Build an explicitly bounded, dormant mesh listener candidate.
    /// # Errors
    /// Returns TLS/configuration or socket binding errors.
    pub fn bind(
        addr: SocketAddr,
        tls: &MeshTlsConfig,
        roots: MeshRootPemProvider,
        allowed: Vec<String>,
        limits: MeshQuicAdmissionLimits,
    ) -> Result<(Self, mpsc::Receiver<MeshQuicReadyConnection>), TransportError> {
        let limits = limits.bounded();
        let endpoint = quinn::Endpoint::server(server_config(tls, roots, limits)?, addr)?;
        let (ready, receiver) = mpsc::channel(limits.ready);
        Ok((
            Self {
                endpoint,
                limits,
                allowed: Arc::new(allowed),
                metrics: MeshQuicHandshakeMetrics(Arc::default()),
                ready,
            },
            receiver,
        ))
    }

    /// # Errors
    /// Returns an error if the underlying socket address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    #[cfg(test)]
    pub(crate) fn test_endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    #[must_use]
    pub fn metrics(&self) -> MeshQuicHandshakeMetrics {
        self.metrics.clone()
    }

    fn reserve(&self, incoming: &quinn::Incoming) -> Option<Reservation> {
        let mut state = lock(&self.metrics.0);
        state.entries.retain(|_, entry| entry.release_at.is_none_or(|at| at > Instant::now()));
        state.counters.protocol_entries = self.endpoint.open_connections();
        // Atomic with respect to accepts: this task is the endpoint's sole incoming owner.
        if state.counters.protocol_entries >= self.limits.protocol_entries
            || state.entries.len() >= self.limits.handshakes
        {
            state.counters.listener_cap += 1;
            return None;
        }
        let ip = normalized(incoming.remote_address().ip());
        if state.entries.values().filter(|entry| entry.ip == ip).count() >= self.limits.per_source {
            state.counters.source_cap += 1;
            return None;
        }
        let id = state.next;
        state.next = state.next.wrapping_add(1);
        state
            .entries
            .insert(id, Entry { ip, phase: Phase::Handshake, release_at: None, connection: None });
        Some(Reservation { id, metrics: self.metrics.clone(), hold: self.limits.idle_timeout })
    }

    /// Run until shutdown, then close the endpoint, cancel/join every handshake,
    /// and wait for actual protocol retirement. Caller must retain/join this future.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut tasks = JoinSet::new();
        let mut maintenance = tokio::time::interval(Duration::from_millis(10));
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = maintenance.tick() => {
                    let mut state = lock(&self.metrics.0);
                    state.entries.retain(|_, entry| entry.release_at.is_none_or(|at| at > Instant::now()));
                    state.counters.protocol_entries = self.endpoint.open_connections();
                },
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok(Some(result))) = result {
                        if *shutdown.borrow() { drop(result); break; }
                        if self.ready.try_send(result).is_err() {
                            lock(&self.metrics.0).counters.ready_cap += 1;
                        }
                    }
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break; };
                    // Check protocol accounting even on unvalidated attempts, before Retry.
                    if self.endpoint.open_connections() >= self.limits.protocol_entries {
                        lock(&self.metrics.0).counters.listener_cap += 1;
                        incoming.refuse();
                        continue;
                    }
                    if !incoming.remote_address_validated() {
                        if let Err(error) = incoming.retry() { error.into_incoming().refuse(); }
                        continue;
                    }
                    let Some(reservation) = self.reserve(&incoming) else { incoming.refuse(); continue; };
                    let deadline = Instant::now() + self.limits.deadline;
                    let allowed = self.allowed.clone();
                    let limits = self.limits;
                    let Ok(connecting) = incoming.accept() else {
                        lock(&self.metrics.0).counters.peer_error += 1;
                        continue;
                    };
                    tasks.spawn(async move { complete(connecting, reservation, deadline, allowed, limits).await });
                }
            }
            lock(&self.metrics.0).counters.protocol_entries = self.endpoint.open_connections();
        }
        {
            let mut state = lock(&self.metrics.0);
            state.stopping = true;
            state.counters.cancelled += u64::try_from(state.entries.len()).unwrap_or(u64::MAX);
        }
        self.endpoint.close(0_u32.into(), b"shutdown");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        self.endpoint.wait_idle().await;
        let mut state = lock(&self.metrics.0);
        state.entries.clear();
        state.counters.protocol_entries = 0;
    }
}

async fn complete(
    connecting: quinn::Connecting,
    reservation: Reservation,
    deadline: Instant,
    allowed: Arc<Vec<String>>,
    limits: MeshQuicAdmissionLimits,
) -> Option<MeshQuicReadyConnection> {
    let connection = match tokio::time::timeout_at(deadline, connecting).await {
        Ok(Ok(connection)) => connection,
        result => {
            let mut state = lock(&reservation.metrics.0);
            if result.is_err() {
                state.counters.timeout += 1;
            } else {
                state.counters.peer_error += 1;
            }
            return None;
        }
    };
    if Instant::now() >= deadline {
        connection.close(0_u32.into(), b"handshake deadline");
        lock(&reservation.metrics.0).counters.timeout += 1;
        return None;
    }
    let identity = quinn_peer_spiffe_uri(&connection).ok().flatten();
    if identity.as_ref().is_none_or(|identity| !allowed.contains(identity)) {
        connection.close(0_u32.into(), b"mesh identity refused");
        lock(&reservation.metrics.0).counters.peer_error += 1;
        return None;
    }
    {
        let mut state = lock(&reservation.metrics.0);
        let ip = state.entries.get(&reservation.id)?.ip;
        if state.stopping
            || state.entries.values().filter(|entry| entry.phase == Phase::Ready).count()
                >= limits.ready
            || state
                .entries
                .values()
                .filter(|entry| entry.ip == ip && entry.phase == Phase::Ready)
                .count()
                >= limits.ready_per_source
        {
            state.counters.ready_cap += 1;
            connection.close(0_u32.into(), b"ready capacity");
            return None;
        }
        let entry = state.entries.get_mut(&reservation.id)?;
        entry.phase = Phase::Ready;
        entry.connection = Some(MeshQuicConnection { connection, peer_spiffe_uri: identity });
    }
    Some(MeshQuicReadyConnection { reservation })
}
