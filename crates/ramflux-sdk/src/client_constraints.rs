// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Build-level guarantees every client host inherits.
//!
//! The client talks to the user's own node, gateway and relay, whose addresses come from the
//! account's node profile at run time. It has no central project service to contact: no
//! analytics, update, configuration or discovery endpoint is compiled in. Core messaging
//! needs neither an application store nor a vendor push service; push is an optional route
//! the host may register, and its absence only means no notifications.
//!
//! `tests/no_central_endpoints.rs` scans the client sources and manifests and fails when a
//! compiled-in endpoint or a vendor dependency appears.

/// Who a client connection may be addressed to. Every variant is named by the user's node
/// profile; there is no variant for a project-operated service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundPeer {
    /// The user's home node (identity, prekeys, custody).
    Node,
    /// The gateway of the user's node (the session).
    Gateway,
    /// A relay named by the user's node (objects, calls).
    Relay,
}

/// Central project endpoints compiled into the client. Empty, and asserted empty at compile
/// time: adding an entry fails the build.
pub const CENTRAL_SERVICE_ENDPOINTS: [&str; 0] = [];

/// Core send and receive never wait for a vendor push service.
pub const VENDOR_PUSH_REQUIRED: bool = false;

/// The client needs no application store to install, update or run.
pub const APPLICATION_STORE_REQUIRED: bool = false;

const _: () = assert!(CENTRAL_SERVICE_ENDPOINTS.is_empty());
const _: () = assert!(!VENDOR_PUSH_REQUIRED);
const _: () = assert!(!APPLICATION_STORE_REQUIRED);

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::gateway::{GatewayQuicEndpointConfig, GatewaySessionConfig};
    use std::path::PathBuf;

    #[test]
    fn a_default_session_needs_no_push_route() {
        let config = GatewaySessionConfig::auto(GatewayQuicEndpointConfig {
            bind_addr: "0.0.0.0:0".parse().expect("bind addr"),
            gateway_addr: "192.0.2.1:443".parse().expect("gateway addr"),
            server_name: "gateway.invalid".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: "principal_test".to_owned(),
            device_id: "device_test".to_owned(),
            target_delivery_id: "target_test".to_owned(),
            prekey_http_url: None,
        });
        assert!(config.push_route.is_none());
        assert!(!config.push_route_clear_pending);
    }
}
