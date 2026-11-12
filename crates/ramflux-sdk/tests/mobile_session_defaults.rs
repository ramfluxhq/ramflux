// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-wide phone session defaults, in a process of their own because they are global.
//!
//! After a phone host installs its network monitor, a gateway session configuration built
//! the way the supervisor builds one uses the raced `Auto` order and observes the host's
//! network reports.

use std::path::PathBuf;

use ramflux_sdk::{
    ConnectionRace, GatewayQuicEndpointConfig, GatewaySessionConfig, NetworkChangeKind, NetworkKey,
    NetworkMonitor, install_mobile_session_defaults,
};

fn endpoint() -> Result<GatewayQuicEndpointConfig, std::net::AddrParseError> {
    Ok(GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse()?,
        // TEST-NET-1 (RFC 5737) is never routed.
        gateway_addr: "192.0.2.1:443".parse()?,
        server_name: "gateway.invalid".to_owned(),
        ca_cert: PathBuf::from("/nonexistent/ca.pem"),
        principal_id: "principal_test".to_owned(),
        device_id: "device_test".to_owned(),
        target_delivery_id: "target_test".to_owned(),
        prekey_http_url: None,
    })
}

#[test]
fn installed_monitor_reaches_every_new_session_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let before = GatewaySessionConfig::auto(endpoint()?);
    assert_eq!(before.connection_race, ConnectionRace::Serial);

    let host = NetworkMonitor::new();
    assert!(install_mobile_session_defaults(host.clone()));
    // A second installation is refused and does not replace the first monitor.
    assert!(!install_mobile_session_defaults(NetworkMonitor::new()));

    let config = GatewaySessionConfig::auto(endpoint()?);
    assert_eq!(config.connection_race, ConnectionRace::Raced);

    let cellular = NetworkKey::from_host_label(b"android-network-handle-and-transport");
    host.on_network_changed(NetworkChangeKind::Changed(cellular));
    assert_eq!(config.network_monitor.current_network(), cellular);
    host.on_network_changed(NetworkChangeKind::Lost);
    assert_eq!(config.network_monitor.snapshot().kind, NetworkChangeKind::Lost);

    // The configuration built before the installation kept its private monitor.
    assert_ne!(before.network_monitor.snapshot().kind, NetworkChangeKind::Lost);
    Ok(())
}
