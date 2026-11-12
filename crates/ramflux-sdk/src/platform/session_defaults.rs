// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-wide gateway session defaults for hosts whose process is the supervisor.
//!
//! A phone has one supervisor per process and one network monitor fed by the operating
//! system. Installing that monitor here makes every gateway session configuration built
//! afterwards use the raced `Auto` order and share the monitor, so the transport remembered
//! for a network follows what the host reports. Nothing installs it by default: a process
//! that never calls [`install_mobile_session_defaults`] keeps the serial order and a
//! private monitor per configuration, exactly as before.

use std::sync::OnceLock;

use super::network::NetworkMonitor;
use crate::ConnectionRace;

static MOBILE_MONITOR: OnceLock<NetworkMonitor> = OnceLock::new();

/// Make `monitor` the shared network monitor of every gateway session configuration built
/// from now on, and select the raced `Auto` order for them. The first call wins.
///
/// Returns `false` when defaults were already installed; the earlier monitor stays.
pub fn install_mobile_session_defaults(monitor: NetworkMonitor) -> bool {
    MOBILE_MONITOR.set(monitor).is_ok()
}

/// The race and monitor for a new configuration given the installed monitor, if any.
pub(crate) fn defaults_from(
    installed: Option<&NetworkMonitor>,
) -> (ConnectionRace, NetworkMonitor) {
    installed.map_or_else(
        || (ConnectionRace::default(), NetworkMonitor::new()),
        |monitor| (ConnectionRace::Raced, monitor.clone()),
    )
}

/// The race and monitor a new gateway session configuration starts with.
pub(crate) fn session_defaults() -> (ConnectionRace, NetworkMonitor) {
    defaults_from(MOBILE_MONITOR.get())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::network::NetworkChangeKind;

    #[test]
    fn without_an_installed_monitor_sessions_keep_the_serial_default() {
        let (race, monitor) = defaults_from(None);
        assert_eq!(race, ConnectionRace::Serial);
        // A private monitor: a report to another monitor is not visible here.
        NetworkMonitor::new().on_network_changed(NetworkChangeKind::Lost);
        assert_ne!(monitor.snapshot().kind, NetworkChangeKind::Lost);
    }

    #[test]
    fn an_installed_monitor_is_shared_and_selects_the_race() {
        let host = NetworkMonitor::new();
        let (race, monitor) = defaults_from(Some(&host));
        assert_eq!(race, ConnectionRace::Raced);
        host.on_network_changed(NetworkChangeKind::Lost);
        assert_eq!(monitor.snapshot().kind, NetworkChangeKind::Lost);
    }
}
