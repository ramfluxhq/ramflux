// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-authentication admission uses transport-observed source buckets.

use std::net::{IpAddr, Ipv4Addr};

/// Preserve the node's IPv6 /64 and IPv4-mapped policy. The well-known NAT64
/// prefix (`64:ff9b::/96`) represents the same source as its embedded IPv4 address;
/// network-specific translation prefixes are not inferred from arbitrary IPv6.
#[must_use]
pub(crate) fn source_key(peer: IpAddr) -> String {
    let source = match peer {
        IpAddr::V6(ip) if ip.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0] => {
            let octets = ip.octets();
            IpAddr::V4(Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]))
        }
        source => source,
    };
    ramflux_node_core::source_ip_hash(&source.to_string())
}

#[cfg(test)]
#[path = "pre_auth_tests.rs"]
pub(crate) mod tests;

/// Configure before pruning, persistence, or opening a public listener.
pub(crate) fn configure(
    state: &mut ramflux_node_core::GatewayState,
    config: Option<&ramflux_node_core::GatewayConfig>,
) -> anyhow::Result<()> {
    if let Some(config) = config.and_then(|config| config.pre_auth.as_ref()) {
        state.configure_pre_auth_policy(config)?;
    }
    if state.pre_auth_policy().enabled {
        let path =
            ramflux_node_core::environment::var_os("RAMFLUX_GATEWAY_PRE_AUTH_COOKIE_KEY_FILE")
                .ok_or(ramflux_node_core::NodeCoreError::PreAuthConfigInvalid)?;
        state.configure_pre_auth_cookie_key(std::path::Path::new(&path))?;
    }
    state.validate_pre_auth_configuration()?;
    if state.pre_auth_migration_required() {
        crate::ingress_log::record(crate::ingress_log::Event::LegacyMigration);
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
pub(crate) fn admit(
    peer: IpAddr,
    cookie: Option<&str>,
    state: &std::sync::Arc<std::sync::Mutex<ramflux_node_core::GatewayState>>,
    store: &ramflux_node_core::GatewayRedbStore,
) -> anyhow::Result<Option<ramflux_node_core::GatewayPreAuthChallengeResponse>> {
    admit_with_clock(&source_key(peer), cookie, state, store, std::time::SystemTime::now)
}

pub(crate) fn admit_with_clock(
    source: &str,
    cookie: Option<&str>,
    state: &std::sync::Arc<std::sync::Mutex<ramflux_node_core::GatewayState>>,
    store: &ramflux_node_core::GatewayRedbStore,
    clock: impl FnOnce() -> std::time::SystemTime,
) -> anyhow::Result<Option<ramflux_node_core::GatewayPreAuthChallengeResponse>> {
    let mut gateway = crate::gateway_state(state)?;
    let decision = gateway.check_pre_auth_system_time(source, cookie, clock());
    store.save_pre_auth_hot(&gateway)?;
    Ok(match decision? {
        ramflux_node_core::GatewayPreAuthDecision::Accepted => None,
        ramflux_node_core::GatewayPreAuthDecision::Challenge(challenge) => Some(challenge),
    })
}

/// Public decoder errors may contain source hints, cookies or other Open fields.
pub(crate) fn record_ingress_failure(_carrier: &'static str) {
    crate::ingress_log::record(crate::ingress_log::Event::Failure);
}
