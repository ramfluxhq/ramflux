// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Android connectivity callbacks reduced to the three network events the session reacts to.
//!
//! The host registers one `ConnectivityManager.registerDefaultNetworkCallback` and forwards
//! each callback here unchanged. It must not call synchronous `ConnectivityManager` getters
//! inside a callback; the capabilities and link properties arrive as their own callbacks,
//! which is why a network becomes usable here only once its capabilities were delivered.
//!
//! The process always uses the default network and never binds a specific `Network`. A VPN
//! that drops UDP while passing TCP is handled by the `Auto` transport, not by routing
//! around the VPN. This module owns no socket and no reconnect logic: it only reports.

use std::sync::{Arc, Mutex};

use crate::platform::network::{NetworkChangeKind, NetworkKey, NetworkMonitor};
use crate::{ConnectionRace, GatewaySessionConfig, GatewaySessionTransportKind};

/// `NetworkCapabilities.TRANSPORT_*` values the host passes as a bit set (`1 << value`).
pub mod transport {
    pub const CELLULAR: u32 = 1 << 0;
    pub const WIFI: u32 = 1 << 1;
    pub const BLUETOOTH: u32 = 1 << 2;
    pub const ETHERNET: u32 = 1 << 3;
    pub const VPN: u32 = 1 << 4;
}

/// The capabilities of the default network that the connection policy cares about, read by
/// the host from the `NetworkCapabilities` argument of `onCapabilitiesChanged`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AndroidNetworkCapabilities {
    /// Bit set of [`transport`] values present on the network.
    pub transports: u32,
    /// `NET_CAPABILITY_INTERNET`.
    pub internet: bool,
    /// `NET_CAPABILITY_VALIDATED`. False behind a captive portal.
    pub validated: bool,
    /// `NET_CAPABILITY_NOT_METERED`.
    pub not_metered: bool,
    /// `NET_CAPABILITY_NOT_VPN` is absent, or `TRANSPORT_VPN` is present.
    pub vpn: bool,
}

/// What changed for the session. Mirrors the platform-neutral network change kinds; the
/// label is the opaque input for the per-network transport memory and is never logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AndroidNetworkEvent {
    /// A usable default network appeared after none, or after start.
    Available(NetworkLabel),
    /// The default network, its transport, or its addresses changed while connected.
    Changed(NetworkLabel),
    /// There is no usable default network.
    Lost,
}

/// Opaque per-network label: the `Network.getNetworkHandle()` value and the transport bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkLabel(Vec<u8>);

impl NetworkLabel {
    fn new(handle: i64, transports: u32) -> Self {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&handle.to_be_bytes());
        bytes.extend_from_slice(&transports.to_be_bytes());
        Self(bytes)
    }

    /// Bytes to hash into the platform-neutral network key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Receives the reduced events. The call must not block.
pub trait AndroidNetworkSink: Send + Sync {
    fn on_network_event(&self, event: AndroidNetworkEvent);
}

/// The platform-neutral monitor is the production sink: every Android event becomes one
/// `on_network_changed` report, and the label only ever leaves this module as a hash.
impl AndroidNetworkSink for NetworkMonitor {
    fn on_network_event(&self, event: AndroidNetworkEvent) {
        let kind = match event {
            AndroidNetworkEvent::Available(label) => {
                NetworkChangeKind::Available(NetworkKey::from_host_label(label.as_bytes()))
            }
            AndroidNetworkEvent::Changed(label) => {
                NetworkChangeKind::Changed(NetworkKey::from_host_label(label.as_bytes()))
            }
            AndroidNetworkEvent::Lost => NetworkChangeKind::Lost,
        };
        self.on_network_changed(kind);
    }
}

/// How a session should connect on the current network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AndroidConnectionPolicy {
    /// Always `Auto`: QUIC raced against TCP+TLS on 443, so a network that drops UDP still
    /// connects.
    pub transport: GatewaySessionTransportKind,
    /// Always `Raced`: TCP+TLS starts 300 ms after QUIC and the first handshake wins.
    pub race: ConnectionRace,
    /// Always false: the process stays on the default network, including under a VPN.
    pub bind_to_network: bool,
    /// The network is metered: defer bulk transfers the user did not ask for.
    pub metered: bool,
    /// Traffic leaves through a VPN.
    pub vpn: bool,
    /// The platform has not validated internet access (captive portal or no uplink). The
    /// session still tries; a failure is reported as "network blocked", never as a prompt to
    /// trust a certificate.
    pub unvalidated: bool,
}

/// Give a gateway session configuration the phone connection policy: the raced `Auto`
/// order and the host's shared network monitor, so the remembered transport follows the
/// network Android reports. The configuration must have been built with the `Auto`
/// transport kind; an explicit QUIC or TCP configuration ignores the race.
#[must_use]
pub fn mobile_session_config(
    config: GatewaySessionConfig,
    monitor: &NetworkMonitor,
) -> GatewaySessionConfig {
    config.with_connection_race(ConnectionRace::Raced).with_network_monitor(monitor.clone())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Current {
    handle: i64,
    capabilities: Option<AndroidNetworkCapabilities>,
    link_fingerprint: Option<[u8; 32]>,
    blocked: bool,
    announced: bool,
}

#[derive(Default)]
struct State {
    current: Option<Current>,
    idle: bool,
    /// Whether the session was last told a network is usable.
    up: bool,
}

/// Turns `ConnectivityManager.NetworkCallback` calls into [`AndroidNetworkEvent`]s.
///
/// Every method is cheap, non-blocking and safe to call from the callback thread.
pub struct AndroidNetworkTracker {
    sink: Arc<dyn AndroidNetworkSink>,
    state: Mutex<State>,
}

impl AndroidNetworkTracker {
    #[must_use]
    pub fn new(sink: Arc<dyn AndroidNetworkSink>) -> Self {
        Self { sink, state: Mutex::new(State::default()) }
    }

    fn update(&self, change: impl FnOnce(&mut State) -> Option<AndroidNetworkEvent>) {
        // A poisoned lock means a sink panicked while holding nothing of ours; the state is
        // still consistent, so keep reporting.
        let event = {
            let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            change(&mut state)
        };
        if let Some(event) = event {
            self.sink.on_network_event(event);
        }
    }

    /// `onAvailable(network)`: a new default network. It is not usable yet; the capabilities
    /// callback that always follows on API 26 and later announces it.
    pub fn on_available(&self, handle: i64) {
        self.update(|state| {
            state.current = Some(Current {
                handle,
                capabilities: None,
                link_fingerprint: None,
                blocked: false,
                announced: false,
            });
            None
        });
    }

    /// `onCapabilitiesChanged(network, capabilities)`.
    pub fn on_capabilities_changed(&self, handle: i64, capabilities: AndroidNetworkCapabilities) {
        self.update(|state| {
            let current = state.current.as_mut().filter(|current| current.handle == handle)?;
            let previous = current.capabilities.replace(capabilities);
            let transports_changed =
                previous.is_some_and(|previous| previous.transports != capabilities.transports);
            Self::reconcile(state, transports_changed)
        });
    }

    /// `onLinkPropertiesChanged(network, linkProperties)`. `link_description` is the
    /// interface name followed by the link addresses and the NAT64 prefix, in the order the
    /// platform lists them; only its hash is kept.
    pub fn on_link_properties_changed(&self, handle: i64, link_description: &[u8]) {
        self.update(|state| {
            let current = state.current.as_mut().filter(|current| current.handle == handle)?;
            let fingerprint = *blake3::hash(link_description).as_bytes();
            let previous = current.link_fingerprint.replace(fingerprint);
            let changed = previous.is_some_and(|previous| previous != fingerprint);
            Self::reconcile(state, changed)
        });
    }

    /// `onBlockedStatusChanged(network, blocked)`: Data Saver, Doze or a firewall rule.
    pub fn on_blocked_status_changed(&self, handle: i64, blocked: bool) {
        self.update(|state| {
            let current = state.current.as_mut().filter(|current| current.handle == handle)?;
            current.blocked = blocked;
            Self::reconcile(state, false)
        });
    }

    /// `onLost(network)`. For a default-network callback this means no network satisfies
    /// the request any more; a loss reported for an older network is ignored.
    pub fn on_lost(&self, handle: i64) {
        self.update(|state| {
            if state.current.as_ref().is_some_and(|current| current.handle == handle) {
                state.current = None;
            }
            Self::reconcile(state, false)
        });
    }

    /// `PowerManager.isDeviceIdleMode()` changed. Doze suspends network access, so the
    /// socket dying is normal: report the network lost instead of letting the session spend
    /// its retry budget, and report it again when the device leaves Doze.
    pub fn on_device_idle_changed(&self, idle: bool) {
        self.update(|state| {
            state.idle = idle;
            Self::reconcile(state, false)
        });
    }

    /// Compare what the session was told with what is true now and produce at most one event.
    fn reconcile(state: &mut State, same_network_changed: bool) -> Option<AndroidNetworkEvent> {
        let idle = state.idle;
        let usable = state.current.as_ref().and_then(|current| {
            let capabilities = current.capabilities?;
            (capabilities.internet && !current.blocked && !idle)
                .then(|| NetworkLabel::new(current.handle, capabilities.transports))
        });
        match (usable, state.up) {
            (None, true) => {
                state.up = false;
                if let Some(current) = state.current.as_mut() {
                    current.announced = false;
                }
                Some(AndroidNetworkEvent::Lost)
            }
            (None, false) => None,
            (Some(label), false) => {
                state.up = true;
                if let Some(current) = state.current.as_mut() {
                    current.announced = true;
                }
                Some(AndroidNetworkEvent::Available(label))
            }
            (Some(label), true) => {
                let current = state.current.as_mut()?;
                // A handover replaces the default network without an `onLost` in between.
                let handover = !current.announced;
                current.announced = true;
                (handover || same_network_changed).then_some(AndroidNetworkEvent::Changed(label))
            }
        }
    }

    /// The connection policy for the current default network, or `None` without one.
    #[must_use]
    pub fn connection_policy(&self) -> Option<AndroidConnectionPolicy> {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let capabilities = state.current.as_ref()?.capabilities?;
        Some(AndroidConnectionPolicy {
            transport: GatewaySessionTransportKind::Auto,
            race: ConnectionRace::Raced,
            bind_to_network: false,
            metered: !capabilities.not_metered,
            vpn: capabilities.vpn || capabilities.transports & transport::VPN != 0,
            unvalidated: !capabilities.validated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<AndroidNetworkEvent>>);

    impl AndroidNetworkSink for Recorder {
        fn on_network_event(&self, event: AndroidNetworkEvent) {
            self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(event);
        }
    }

    impl Recorder {
        fn take(&self) -> Vec<AndroidNetworkEvent> {
            std::mem::take(&mut *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
        }
    }

    fn tracker() -> (Arc<Recorder>, AndroidNetworkTracker) {
        let recorder = Arc::new(Recorder::default());
        let sink: Arc<dyn AndroidNetworkSink> = recorder.clone();
        (recorder, AndroidNetworkTracker::new(sink))
    }

    const fn wifi() -> AndroidNetworkCapabilities {
        AndroidNetworkCapabilities {
            transports: transport::WIFI,
            internet: true,
            validated: true,
            not_metered: true,
            vpn: false,
        }
    }

    const fn cellular() -> AndroidNetworkCapabilities {
        AndroidNetworkCapabilities {
            transports: transport::CELLULAR,
            internet: true,
            validated: true,
            not_metered: false,
            vpn: false,
        }
    }

    #[test]
    fn network_is_available_only_after_its_capabilities_arrive() {
        let (recorder, tracker) = tracker();
        tracker.on_available(100);
        assert!(recorder.take().is_empty());
        tracker.on_capabilities_changed(100, wifi());
        tracker.on_link_properties_changed(100, b"wlan0 192.0.2.10/24");
        assert_eq!(
            recorder.take(),
            vec![AndroidNetworkEvent::Available(NetworkLabel::new(100, transport::WIFI))]
        );
    }

    #[test]
    fn handover_without_loss_is_one_change() {
        let (recorder, tracker) = tracker();
        tracker.on_available(100);
        tracker.on_capabilities_changed(100, wifi());
        recorder.take();
        tracker.on_available(200);
        tracker.on_capabilities_changed(200, cellular());
        tracker.on_link_properties_changed(200, b"rmnet0 198.51.100.7/32");
        // The loss of the old network arrives late and must not drop the new one.
        tracker.on_lost(100);
        assert_eq!(
            recorder.take(),
            vec![AndroidNetworkEvent::Changed(NetworkLabel::new(200, transport::CELLULAR))]
        );
    }

    #[test]
    fn address_change_is_a_change_and_repeats_are_silent() {
        let (recorder, tracker) = tracker();
        tracker.on_available(100);
        tracker.on_capabilities_changed(100, wifi());
        tracker.on_link_properties_changed(100, b"wlan0 192.0.2.10/24");
        recorder.take();
        tracker.on_link_properties_changed(100, b"wlan0 192.0.2.10/24");
        tracker.on_capabilities_changed(100, wifi());
        assert!(recorder.take().is_empty());
        tracker.on_link_properties_changed(100, b"wlan0 192.0.2.99/24 64:ff9b::/96");
        assert_eq!(
            recorder.take(),
            vec![AndroidNetworkEvent::Changed(NetworkLabel::new(100, transport::WIFI))]
        );
    }

    #[test]
    fn metered_flag_alone_updates_policy_without_an_event() {
        let (recorder, tracker) = tracker();
        tracker.on_available(100);
        tracker.on_capabilities_changed(100, wifi());
        recorder.take();
        let mut metered = wifi();
        metered.not_metered = false;
        tracker.on_capabilities_changed(100, metered);
        assert!(recorder.take().is_empty());
        assert_eq!(tracker.connection_policy().map(|policy| policy.metered), Some(true));
    }

    #[test]
    fn loss_block_and_doze_report_lost_once_and_recover() {
        let (recorder, tracker) = tracker();
        tracker.on_available(100);
        tracker.on_capabilities_changed(100, wifi());
        recorder.take();

        tracker.on_device_idle_changed(true);
        tracker.on_device_idle_changed(true);
        assert_eq!(recorder.take(), vec![AndroidNetworkEvent::Lost]);
        tracker.on_device_idle_changed(false);
        assert_eq!(
            recorder.take(),
            vec![AndroidNetworkEvent::Available(NetworkLabel::new(100, transport::WIFI))]
        );

        tracker.on_blocked_status_changed(100, true);
        assert_eq!(recorder.take(), vec![AndroidNetworkEvent::Lost]);
        tracker.on_blocked_status_changed(100, false);
        assert_eq!(recorder.take().len(), 1);

        tracker.on_lost(100);
        tracker.on_lost(100);
        assert_eq!(recorder.take(), vec![AndroidNetworkEvent::Lost]);
        assert_eq!(tracker.connection_policy(), None);
    }

    #[test]
    fn vpn_keeps_the_default_network_and_the_auto_transport() {
        let (_recorder, tracker) = tracker();
        tracker.on_available(300);
        let mut vpn = wifi();
        vpn.transports |= transport::VPN;
        vpn.validated = false;
        tracker.on_capabilities_changed(300, vpn);
        let policy = tracker.connection_policy();
        assert_eq!(
            policy,
            Some(AndroidConnectionPolicy {
                transport: GatewaySessionTransportKind::Auto,
                race: ConnectionRace::Raced,
                bind_to_network: false,
                metered: false,
                vpn: true,
                unvalidated: true,
            })
        );
    }

    #[test]
    fn android_callbacks_drive_the_neutral_network_monitor() {
        let monitor = NetworkMonitor::new();
        let sink: Arc<dyn AndroidNetworkSink> = Arc::new(monitor.clone());
        let tracker = AndroidNetworkTracker::new(sink);
        let start = monitor.snapshot().generation;

        tracker.on_available(100);
        tracker.on_capabilities_changed(100, wifi());
        let wifi_key =
            NetworkKey::from_host_label(NetworkLabel::new(100, transport::WIFI).as_bytes());
        assert_eq!(monitor.snapshot().kind, NetworkChangeKind::Available(wifi_key));
        assert_eq!(monitor.snapshot().generation, start + 1);

        tracker.on_available(200);
        tracker.on_capabilities_changed(200, cellular());
        let cell_key =
            NetworkKey::from_host_label(NetworkLabel::new(200, transport::CELLULAR).as_bytes());
        assert_ne!(wifi_key, cell_key);
        assert_eq!(monitor.snapshot().kind, NetworkChangeKind::Changed(cell_key));
        assert_eq!(monitor.current_network(), cell_key);

        tracker.on_lost(200);
        assert_eq!(monitor.snapshot().kind, NetworkChangeKind::Lost);
        assert_eq!(monitor.snapshot().generation, start + 3);
    }

    #[test]
    fn callbacks_for_a_stale_network_are_ignored() {
        let (recorder, tracker) = tracker();
        tracker.on_available(100);
        tracker.on_capabilities_changed(100, wifi());
        recorder.take();
        tracker.on_capabilities_changed(999, cellular());
        tracker.on_link_properties_changed(999, b"rmnet0");
        tracker.on_blocked_status_changed(999, true);
        assert!(recorder.take().is_empty());
    }
}
