// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client connection policy shared by every native host: which gateway carriers are dialed,
//! in which order, with which start offsets, and what is remembered per network.
//!
//! This module is pure: it opens no socket and reads no clock of its own. The dialer in
//! `gateway_dial` executes a [`DialPlan`]; hosts feed [`PathMemory`] with a caller clock.
//!
//! Every carrier named here ends in the same TLS 1.3 session to the gateway, verified against
//! the same pinned CA, and exposes that session's exporter for the custody binding. A fallback
//! therefore changes the carrier, never a security property. There is deliberately no plaintext,
//! "insecure", user-trusted-root or binding-free carrier variant to fall back to.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Start offset between consecutive legs of the `Auto` race.
pub const AUTO_RACE_STAGGER: Duration = Duration::from_millis(300);
/// How long a winning carrier is remembered for one network.
pub const PATH_MEMORY_TTL: Duration = Duration::from_secs(600);
/// Upper bound on remembered networks; the oldest entry is evicted first.
pub const PATH_MEMORY_MAX_NETWORKS: usize = 32;
/// QUIC idle timeout advertised by the client for a gateway session.
pub const SESSION_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// QUIC transport keep-alive while a session is open.
pub const SESSION_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(25);
/// Application heartbeat period on stream carriers (TCP+TLS, WebSocket).
pub const STREAM_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);
/// Missed heartbeat replies after which a stream carrier is declared dead.
pub const STREAM_HEARTBEAT_MISSED_LIMIT: u32 = 2;
/// Deadline for the single heartbeat sent after an OS network-change notification.
pub const NETWORK_CHANGE_PROBE_DEADLINE: Duration = Duration::from_secs(3);

const _: () = assert!(SESSION_KEEP_ALIVE_INTERVAL.as_secs() < SESSION_MAX_IDLE_TIMEOUT.as_secs());
// The keep-alive must also hold a path whose peer still runs the 30 s transport default.
const _: () = assert!(SESSION_KEEP_ALIVE_INTERVAL.as_secs() < 30);

/// A gateway carrier. Each one carries the same frames inside TLS 1.3 to the gateway.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CarrierKind {
    /// QUIC over UDP.
    Quic,
    /// Length-prefixed frames over TCP + TLS.
    TcpTls,
    /// One binary WebSocket message per frame over TCP + TLS.
    WebSocketTls,
}

impl CarrierKind {
    /// Stable name for logs and diagnostics. It is not an `Open.transport_kind` wire value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::TcpTls => "tcp_tls",
            Self::WebSocketTls => "websocket_tls",
        }
    }

    /// Whether the carrier needs a UDP path to the gateway.
    #[must_use]
    pub const fn needs_udp(self) -> bool {
        matches!(self, Self::Quic)
    }

    /// Whether the carrier can run inside an HTTP CONNECT tunnel.
    #[must_use]
    pub const fn tunnels_through_http_proxy(self) -> bool {
        !self.needs_udp()
    }

    /// Every carrier terminates TLS 1.3 at the gateway and exposes its exporter.
    #[must_use]
    pub const fn provides_tls13_exporter(self) -> bool {
        match self {
            Self::Quic | Self::TcpTls | Self::WebSocketTls => true,
        }
    }
}

/// One leg of a dial plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DialLeg {
    pub carrier: CarrierKind,
    /// Offset from the start of the dial at which this leg begins.
    pub start_after: Duration,
}

/// What the host knows before dialing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DialInputs {
    /// The carrier that last completed a handshake on this network, if still fresh.
    pub remembered: Option<CarrierKind>,
    /// An HTTP proxy is configured for this connection.
    pub http_proxy: bool,
    /// The node profile names a WebSocket endpoint for native devices.
    pub websocket_available: bool,
}

/// Ordered legs of one `Auto` dial. The first leg to complete its TLS handshake wins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DialPlan {
    legs: Vec<DialLeg>,
}

impl DialPlan {
    /// Build the `Auto` plan.
    ///
    /// - No memory: QUIC at 0, TCP+TLS one stagger later, WebSocket one stagger after that.
    /// - QUIC remembered: the same race. `Auto` never dials QUIC alone, because UDP can be
    ///   blocked at any time.
    /// - A stream carrier remembered: UDP was blocked or slow on this network, so QUIC is left
    ///   out until the memory expires. The expiry is the QUIC re-probe.
    /// - HTTP proxy configured: QUIC is never dialed.
    #[must_use]
    pub fn auto(inputs: DialInputs) -> Self {
        let mut carriers = Vec::with_capacity(3);
        let quic_allowed = !inputs.http_proxy
            && !matches!(inputs.remembered, Some(CarrierKind::TcpTls | CarrierKind::WebSocketTls));
        if quic_allowed {
            carriers.push(CarrierKind::Quic);
        }
        let websocket_first = inputs.websocket_available
            && matches!(inputs.remembered, Some(CarrierKind::WebSocketTls));
        if websocket_first {
            carriers.push(CarrierKind::WebSocketTls);
            carriers.push(CarrierKind::TcpTls);
        } else {
            carriers.push(CarrierKind::TcpTls);
            if inputs.websocket_available {
                carriers.push(CarrierKind::WebSocketTls);
            }
        }
        let mut legs = Vec::with_capacity(carriers.len());
        let mut start_after = Duration::ZERO;
        for carrier in carriers {
            legs.push(DialLeg { carrier, start_after });
            start_after = start_after.saturating_add(AUTO_RACE_STAGGER);
        }
        Self { legs }
    }

    /// A plan with exactly one carrier, for an explicit non-`Auto` transport kind.
    #[must_use]
    pub fn single(carrier: CarrierKind) -> Self {
        Self { legs: vec![DialLeg { carrier, start_after: Duration::ZERO }] }
    }

    #[must_use]
    pub fn legs(&self) -> &[DialLeg] {
        &self.legs
    }

    #[must_use]
    pub fn contains(&self, carrier: CarrierKind) -> bool {
        self.legs.iter().any(|leg| leg.carrier == carrier)
    }
}

/// Opaque identity of one network, supplied by the host. The memory never stores the host's
/// label, only this digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NetworkDigest([u8; 32]);

impl NetworkDigest {
    const DOMAIN: &'static str = "ramflux.transport.network_key.v1";

    /// Digest a host label (interface kind, network handle). The label is not retained.
    #[must_use]
    pub fn from_host_label(label: &[u8]) -> Self {
        Self(blake3::derive_key(Self::DOMAIN, label))
    }

    /// The key used when the host cannot tell networks apart.
    #[must_use]
    pub fn unknown() -> Self {
        Self::from_host_label(b"unknown")
    }
}

#[derive(Clone, Copy, Debug)]
struct RememberedPath {
    carrier: CarrierKind,
    recorded_at: Instant,
}

/// Last working carrier per network, with expiry. Not persisted: a restart re-races.
#[derive(Clone, Debug, Default)]
pub struct PathMemory {
    entries: HashMap<NetworkDigest, RememberedPath>,
}

impl PathMemory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The remembered carrier for `network`, or `None` when absent or older than the TTL.
    #[must_use]
    pub fn remembered(&self, network: NetworkDigest, now: Instant) -> Option<CarrierKind> {
        let entry = self.entries.get(&network)?;
        let age = now.saturating_duration_since(entry.recorded_at);
        (age < PATH_MEMORY_TTL).then_some(entry.carrier)
    }

    /// Record the carrier that completed a handshake on `network`.
    pub fn record_success(&mut self, network: NetworkDigest, carrier: CarrierKind, now: Instant) {
        self.evict_expired(now);
        if !self.entries.contains_key(&network) && self.entries.len() >= PATH_MEMORY_MAX_NETWORKS {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.recorded_at)
                .map(|(network, _)| *network);
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(network, RememberedPath { carrier, recorded_at: now });
    }

    /// Forget `network` when its remembered carrier stopped working, so the next dial re-races.
    pub fn record_failure(&mut self, network: NetworkDigest, carrier: CarrierKind) {
        if self.entries.get(&network).is_some_and(|entry| entry.carrier == carrier) {
            self.entries.remove(&network);
        }
    }

    /// Drop every entry at or past the TTL.
    pub fn evict_expired(&mut self, now: Instant) {
        self.entries
            .retain(|_, entry| now.saturating_duration_since(entry.recorded_at) < PATH_MEMORY_TTL);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Pick the local bind address for a destination: a configured address of the wrong family
/// cannot reach the peer, so the unspecified address of the peer's family is used instead.
#[must_use]
pub fn bind_addr_for_peer(
    configured: std::net::SocketAddr,
    peer: std::net::SocketAddr,
) -> std::net::SocketAddr {
    if configured.is_ipv4() == peer.is_ipv4() {
        return configured;
    }
    if peer.is_ipv4() {
        std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
    } else {
        std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn carriers(plan: &DialPlan) -> Vec<CarrierKind> {
        plan.legs().iter().map(|leg| leg.carrier).collect()
    }

    #[test]
    fn auto_without_memory_races_quic_then_tcp_after_300_ms() {
        let plan = DialPlan::auto(DialInputs::default());
        assert_eq!(carriers(&plan), vec![CarrierKind::Quic, CarrierKind::TcpTls]);
        assert_eq!(plan.legs()[0].start_after, Duration::ZERO);
        assert_eq!(plan.legs()[1].start_after, Duration::from_millis(300));
    }

    #[test]
    fn auto_adds_websocket_as_a_staggered_leg_when_the_profile_names_it() {
        let plan = DialPlan::auto(DialInputs { websocket_available: true, ..DialInputs::default() });
        assert_eq!(
            carriers(&plan),
            vec![CarrierKind::Quic, CarrierKind::TcpTls, CarrierKind::WebSocketTls]
        );
        assert_eq!(plan.legs()[2].start_after, Duration::from_millis(600));
    }

    #[test]
    fn auto_never_dials_quic_alone_even_when_quic_is_remembered() {
        let plan = DialPlan::auto(DialInputs {
            remembered: Some(CarrierKind::Quic),
            ..DialInputs::default()
        });
        assert_eq!(carriers(&plan), vec![CarrierKind::Quic, CarrierKind::TcpTls]);
    }

    #[test]
    fn remembered_stream_carrier_skips_quic_until_expiry() {
        let plan = DialPlan::auto(DialInputs {
            remembered: Some(CarrierKind::TcpTls),
            ..DialInputs::default()
        });
        assert_eq!(carriers(&plan), vec![CarrierKind::TcpTls]);
        assert_eq!(plan.legs()[0].start_after, Duration::ZERO);
    }

    #[test]
    fn remembered_websocket_goes_first_and_keeps_tcp_tls_as_a_leg() {
        let plan = DialPlan::auto(DialInputs {
            remembered: Some(CarrierKind::WebSocketTls),
            websocket_available: true,
            http_proxy: false,
        });
        assert_eq!(carriers(&plan), vec![CarrierKind::WebSocketTls, CarrierKind::TcpTls]);
    }

    #[test]
    fn http_proxy_removes_quic_from_every_auto_plan() {
        for remembered in [None, Some(CarrierKind::Quic), Some(CarrierKind::TcpTls)] {
            for websocket_available in [false, true] {
                let plan =
                    DialPlan::auto(DialInputs { remembered, http_proxy: true, websocket_available });
                assert!(!plan.contains(CarrierKind::Quic));
                assert!(plan.legs().iter().all(|leg| leg.carrier.tunnels_through_http_proxy()));
            }
        }
    }

    #[test]
    fn every_planned_carrier_keeps_the_tls13_exporter() {
        for remembered in
            [None, Some(CarrierKind::Quic), Some(CarrierKind::TcpTls), Some(CarrierKind::WebSocketTls)]
        {
            for http_proxy in [false, true] {
                for websocket_available in [false, true] {
                    let plan =
                        DialPlan::auto(DialInputs { remembered, http_proxy, websocket_available });
                    assert!(!plan.legs().is_empty());
                    assert!(plan.legs().iter().all(|leg| leg.carrier.provides_tls13_exporter()));
                }
            }
        }
    }

    #[test]
    fn path_memory_expires_after_ten_minutes_and_reprobes_quic() {
        let network = NetworkDigest::from_host_label(b"wifi:1");
        let start = Instant::now();
        let mut memory = PathMemory::new();
        memory.record_success(network, CarrierKind::TcpTls, start);
        let just_before = start + PATH_MEMORY_TTL - Duration::from_secs(1);
        assert_eq!(memory.remembered(network, just_before), Some(CarrierKind::TcpTls));
        let at_expiry = start + PATH_MEMORY_TTL;
        assert_eq!(memory.remembered(network, at_expiry), None);
        let plan = DialPlan::auto(DialInputs {
            remembered: memory.remembered(network, at_expiry),
            ..DialInputs::default()
        });
        assert!(plan.contains(CarrierKind::Quic));
    }

    #[test]
    fn path_memory_is_per_network() {
        let wifi = NetworkDigest::from_host_label(b"wifi:1");
        let cell = NetworkDigest::from_host_label(b"cell:1");
        let now = Instant::now();
        let mut memory = PathMemory::new();
        memory.record_success(wifi, CarrierKind::TcpTls, now);
        assert_eq!(memory.remembered(cell, now), None);
        assert_ne!(wifi, cell);
    }

    #[test]
    fn path_memory_failure_forgets_only_the_failed_carrier() {
        let network = NetworkDigest::unknown();
        let now = Instant::now();
        let mut memory = PathMemory::new();
        memory.record_success(network, CarrierKind::TcpTls, now);
        memory.record_failure(network, CarrierKind::Quic);
        assert_eq!(memory.remembered(network, now), Some(CarrierKind::TcpTls));
        memory.record_failure(network, CarrierKind::TcpTls);
        assert_eq!(memory.remembered(network, now), None);
    }

    #[test]
    fn path_memory_is_bounded() {
        let now = Instant::now();
        let mut memory = PathMemory::new();
        for index in 0..(PATH_MEMORY_MAX_NETWORKS + 8) {
            let label = format!("net:{index}");
            memory.record_success(
                NetworkDigest::from_host_label(label.as_bytes()),
                CarrierKind::Quic,
                now + Duration::from_millis(u64::try_from(index).unwrap_or(u64::MAX)),
            );
        }
        assert_eq!(memory.len(), PATH_MEMORY_MAX_NETWORKS);
    }

    #[test]
    fn bind_address_follows_the_destination_family() {
        let v4_any: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap_or_else(|_| unreachable!());
        let v6_peer: std::net::SocketAddr =
            "[2001:db8::1]:443".parse().unwrap_or_else(|_| unreachable!());
        let v4_peer: std::net::SocketAddr = "192.0.2.1:443".parse().unwrap_or_else(|_| unreachable!());
        assert!(bind_addr_for_peer(v4_any, v6_peer).is_ipv6());
        assert_eq!(bind_addr_for_peer(v4_any, v4_peer), v4_any);
    }
}
