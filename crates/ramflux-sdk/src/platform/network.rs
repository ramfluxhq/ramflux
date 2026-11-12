// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host network-change seam and per-network path memory, neutral across platforms.
//!
//! The host creates one [`NetworkMonitor`], forwards the operating system's default-network
//! callback to [`NetworkMonitor::on_network_changed`], and hands clones to the gateway
//! session configuration. The monitor opens no socket and contacts no service; it only
//! records what the host reports.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use ramflux_transport::{CarrierKind, DialInputs, DialPlan, NetworkDigest, PathMemory};

use crate::SdkError;

/// Opaque label of one network. Keys the last-working-transport memory and nothing else.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NetworkKey(NetworkDigest);

impl NetworkKey {
    /// Derive a key from a host label such as the interface kind plus a network handle.
    /// The label is hashed and not retained, so it never reaches a log or the disk.
    #[must_use]
    pub fn from_host_label(label: &[u8]) -> Self {
        Self(NetworkDigest::from_host_label(label))
    }

    /// The key to use when the host cannot tell networks apart.
    #[must_use]
    pub fn unknown() -> Self {
        Self(NetworkDigest::unknown())
    }

    pub(crate) const fn digest(self) -> NetworkDigest {
        self.0
    }
}

/// What the operating system reported about the default network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkChangeKind {
    /// A usable default network appeared after start or after [`Self::Lost`].
    Available(NetworkKey),
    /// The default interface, address or prefix changed while a network stayed available.
    Changed(NetworkKey),
    /// There is no default network.
    Lost,
}

impl NetworkChangeKind {
    /// The network this report names, if any.
    #[must_use]
    pub const fn network(self) -> Option<NetworkKey> {
        match self {
            Self::Available(network) | Self::Changed(network) => Some(network),
            Self::Lost => None,
        }
    }
}

/// The latest report and a counter that increases with every report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkSnapshot {
    pub generation: u64,
    pub kind: NetworkChangeKind,
}

/// What the session owner does after a network change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkChangeOutcome {
    /// The connection answered the probe. Keep it; do not open a second session.
    Survived,
    /// The connection did not answer in time. Drop it and open a new one with `Resume`.
    Reconnect,
}

struct MonitorState {
    reports: tokio::sync::watch::Sender<NetworkSnapshot>,
    memory: Mutex<PathMemory>,
}

/// Shared handle between the host's network callback and the gateway session owner.
#[derive(Clone)]
pub struct NetworkMonitor {
    state: Arc<MonitorState>,
}

impl std::fmt::Debug for NetworkMonitor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("NetworkMonitor").field("snapshot", &self.snapshot()).finish()
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkMonitor {
    /// A monitor that starts on an unknown, available network.
    #[must_use]
    pub fn new() -> Self {
        let initial = NetworkSnapshot {
            generation: 0,
            kind: NetworkChangeKind::Available(NetworkKey::unknown()),
        };
        let (reports, _receiver) = tokio::sync::watch::channel(initial);
        Self { state: Arc::new(MonitorState { reports, memory: Mutex::new(PathMemory::new()) }) }
    }

    /// Record an operating-system network report. Never blocks, never fails, needs no
    /// runtime, and may be called from any thread. A repeated identical report still
    /// advances the generation, so a subscriber probes again.
    pub fn on_network_changed(&self, kind: NetworkChangeKind) {
        self.state.reports.send_modify(|snapshot| {
            snapshot.generation = snapshot.generation.saturating_add(1);
            snapshot.kind = kind;
        });
    }

    /// The latest report.
    #[must_use]
    pub fn snapshot(&self) -> NetworkSnapshot {
        *self.state.reports.borrow()
    }

    /// Subscribe to reports. The receiver observes the latest report only.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<NetworkSnapshot> {
        self.state.reports.subscribe()
    }

    /// The key path memory uses right now. While the network is lost, the unknown key.
    #[must_use]
    pub fn current_network(&self) -> NetworkKey {
        self.snapshot().kind.network().unwrap_or_else(NetworkKey::unknown)
    }

    fn with_memory<T>(&self, action: impl FnOnce(&mut PathMemory) -> T) -> T {
        // The memory is advisory; a poisoned lock still holds a usable map.
        let mut memory = self.state.memory.lock().unwrap_or_else(PoisonError::into_inner);
        action(&mut memory)
    }

    /// The `Auto` plan for the current network at `now`.
    pub(crate) fn auto_plan(&self, http_proxy: bool, now: Instant) -> (NetworkKey, DialPlan) {
        let network = self.current_network();
        let remembered = self.with_memory(|memory| memory.remembered(network.digest(), now));
        let plan = DialPlan::auto(DialInputs { remembered, http_proxy, websocket_available: false });
        (network, plan)
    }

    pub(crate) fn record_success(&self, network: NetworkKey, carrier: CarrierKind, now: Instant) {
        self.with_memory(|memory| memory.record_success(network.digest(), carrier, now));
    }

    /// Forget whatever is remembered for `network` so the next dial races every carrier.
    pub(crate) fn record_dial_failure(&self, network: NetworkKey) {
        self.with_memory(|memory| {
            for carrier in [CarrierKind::Quic, CarrierKind::TcpTls, CarrierKind::WebSocketTls] {
                memory.record_failure(network.digest(), carrier);
            }
        });
    }

    /// The carrier remembered for the current network, for diagnostics and tests.
    #[must_use]
    pub fn remembered_carrier_label(&self) -> Option<&'static str> {
        let network = self.current_network();
        self.with_memory(|memory| memory.remembered(network.digest(), Instant::now()))
            .map(CarrierKind::label)
    }
}

/// True when a connect failed because the peer that answered is not the pinned gateway: a
/// captive portal or an intercepting middlebox. The host shows "network blocked". It must not
/// offer to trust the certificate and must not install an additional root.
#[must_use]
pub fn is_network_blocked(error: &SdkError) -> bool {
    matches!(error, SdkError::Transport(transport) if transport.is_tls_failure())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn reports_advance_the_generation_and_replace_the_kind() {
        let monitor = NetworkMonitor::new();
        assert_eq!(monitor.snapshot().generation, 0);
        let wifi = NetworkKey::from_host_label(b"wifi:en0");
        monitor.on_network_changed(NetworkChangeKind::Changed(wifi));
        monitor.on_network_changed(NetworkChangeKind::Changed(wifi));
        let snapshot = monitor.snapshot();
        assert_eq!(snapshot.generation, 2);
        assert_eq!(snapshot.kind, NetworkChangeKind::Changed(wifi));
        assert_eq!(monitor.current_network(), wifi);
    }

    #[test]
    fn clones_share_reports_and_memory() {
        let host = NetworkMonitor::new();
        let session = host.clone();
        let cell = NetworkKey::from_host_label(b"cell:pdp_ip0");
        host.on_network_changed(NetworkChangeKind::Available(cell));
        assert_eq!(session.current_network(), cell);
        session.record_success(cell, CarrierKind::TcpTls, Instant::now());
        assert_eq!(host.remembered_carrier_label(), Some("tcp_tls"));
    }

    #[test]
    fn lost_network_falls_back_to_the_unknown_key() {
        let monitor = NetworkMonitor::new();
        monitor.on_network_changed(NetworkChangeKind::Lost);
        assert_eq!(monitor.current_network(), NetworkKey::unknown());
        assert_eq!(NetworkChangeKind::Lost.network(), None);
    }

    #[test]
    fn udp_blocked_outcome_is_remembered_per_network_and_expires() {
        let monitor = NetworkMonitor::new();
        let office = NetworkKey::from_host_label(b"wifi:office");
        let home = NetworkKey::from_host_label(b"wifi:home");
        let start = Instant::now();
        monitor.on_network_changed(NetworkChangeKind::Available(office));
        monitor.record_success(office, CarrierKind::TcpTls, start);
        let (_, plan) = monitor.auto_plan(false, start + Duration::from_secs(60));
        assert!(!plan.contains(CarrierKind::Quic));
        assert!(plan.contains(CarrierKind::TcpTls));
        let (_, expired) = monitor.auto_plan(false, start + Duration::from_secs(600));
        assert!(expired.contains(CarrierKind::Quic));
        monitor.on_network_changed(NetworkChangeKind::Changed(home));
        let (network, other) = monitor.auto_plan(false, start + Duration::from_secs(60));
        assert_eq!(network, home);
        assert!(other.contains(CarrierKind::Quic));
    }

    #[test]
    fn dial_failure_forgets_the_network_so_the_next_dial_races_again() {
        let monitor = NetworkMonitor::new();
        let network = monitor.current_network();
        let now = Instant::now();
        monitor.record_success(network, CarrierKind::TcpTls, now);
        monitor.record_dial_failure(network);
        let (_, plan) = monitor.auto_plan(false, now);
        assert!(plan.contains(CarrierKind::Quic));
    }

    #[test]
    fn the_sdk_never_plans_the_websocket_carrier_for_a_native_device() {
        let monitor = NetworkMonitor::new();
        for http_proxy in [false, true] {
            let (_, plan) = monitor.auto_plan(http_proxy, Instant::now());
            assert!(!plan.contains(CarrierKind::WebSocketTls));
            assert_eq!(plan.contains(CarrierKind::Quic), !http_proxy);
        }
    }

    #[test]
    fn a_pinned_ca_failure_is_network_blocked_and_a_timeout_is_not() {
        let portal = SdkError::Transport(ramflux_transport::TransportError::Tls(
            "invalid peer certificate: UnknownIssuer".to_owned(),
        ));
        assert!(is_network_blocked(&portal));
        let timeout = SdkError::Transport(ramflux_transport::TransportError::Quic(
            "handshake timed out".to_owned(),
        ));
        assert!(!is_network_blocked(&timeout));
    }
}
