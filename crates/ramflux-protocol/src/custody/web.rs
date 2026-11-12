// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Web-ingress wire names: the `web_origin_bound` binding context and its listener advertisement.
//!
//! A browser cannot obtain a TLS exporter, so a web device signs a digest of the
//! gateway-authored context below instead. The mode is accepted only on the dedicated
//! web listener and only for a device whose branch certificate carries both web markers.

use serde::{Deserialize, Serialize};

/// The only WebSocket subprotocol the web listener accepts.
pub const WEB_SESSION_SUBPROTOCOL: &str = "ramflux.gateway_session.v1";
/// The only request target the web listener answers.
pub const WEB_SESSION_PATH: &str = "/v1/session";
/// Schema of [`WebOriginBindingV1`] and domain tag of its digest.
pub const WEB_ORIGIN_BINDING_SCHEMA: &str = "ramflux.web_origin_binding.v1";
/// `Open.transport_kind` accepted on the web listener and refused on every native listener.
pub const TRANSPORT_KIND_WEBSOCKET: &str = "websocket";
/// Reserved for a later listener; refused everywhere today.
pub const TRANSPORT_KIND_WEBTRANSPORT: &str = "webtransport";
/// Branch-certificate capability marking a linked secondary web device.
pub const CAPABILITY_WEB_SECONDARY: &str = "web_secondary";
/// Prefix of the capability that pins a web device to one page origin.
pub const CAPABILITY_WEB_ORIGIN_PREFIX: &str = "web_origin.";
/// Lifetime of one binding context, in seconds.
pub const WEB_ORIGIN_BINDING_LIFETIME_SECONDS: u64 = 300;
/// Advertisement limits of a node identity record.
pub const MAX_WEB_LISTENERS: usize = 4;
pub const MAX_WEB_LISTENER_ORIGINS: usize = 8;

/// Gateway-authored connection context that a web device commits to in its branch proof.
///
/// Every field comes from the gateway's own configuration or connection state. The
/// `origin` is the `Origin` header value that already matched the allow-list exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebOriginBindingV1 {
    pub schema: String,
    pub version: u32,
    pub node_id: String,
    pub listener_url: String,
    pub origin: String,
    pub transport_kind: String,
    pub gateway_nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl WebOriginBindingV1 {
    /// Structural rules shared by the signer and both verifiers.
    #[must_use]
    pub fn well_formed(&self) -> bool {
        self.schema == WEB_ORIGIN_BINDING_SCHEMA
            && self.version == 1
            && self.transport_kind == TRANSPORT_KIND_WEBSOCKET
            && self.expires_at.checked_sub(self.issued_at)
                == Some(WEB_ORIGIN_BINDING_LIFETIME_SECONDS)
            && crate::decode_base64url(&self.gateway_nonce).is_ok_and(|nonce| nonce.len() == 32)
            && is_canonical_web_listener_url(&self.listener_url)
            && is_canonical_web_origin(&self.origin, true)
    }
}

/// One web listener a node advertises in its signed identity record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebListener {
    pub url: String,
    pub origins: Vec<String>,
}

fn canonical_authority(authority: &str, default_port: &str) -> bool {
    let (host, port) = match authority.rsplit_once(':') {
        // A bracketed IPv6 literal contains colons that are not a port separator.
        Some((host, port)) if !port.contains(']') => (host, Some(port)),
        _ => (authority, None),
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b'[' | b']' | b':')
        });
    let port_ok = port.is_none_or(|port| {
        !port.is_empty()
            && port.len() <= 5
            && !port.starts_with('0')
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port != default_port
            && port.parse::<u16>().is_ok()
    });
    host_ok && port_ok
}

/// `wss://<lowercase authority>/v1/session`: no userinfo, query, fragment, default port or
/// trailing slash.
#[must_use]
pub fn is_canonical_web_listener_url(url: &str) -> bool {
    url.strip_prefix("wss://")
        .and_then(|rest| rest.strip_suffix(WEB_SESSION_PATH))
        .is_some_and(|authority| canonical_authority(authority, "443"))
}

/// The authority (`host[:port]`) of a canonical listener URL.
#[must_use]
pub fn web_listener_authority(url: &str) -> Option<&str> {
    if !is_canonical_web_listener_url(url) {
        return None;
    }
    url.strip_prefix("wss://")?.strip_suffix(WEB_SESSION_PATH)
}

/// A serialized `https` origin. Loopback `http` origins are accepted only when
/// `allow_dev_loopback` is set; `null` and wildcards never are.
#[must_use]
pub fn is_canonical_web_origin(origin: &str, allow_dev_loopback: bool) -> bool {
    if let Some(authority) = origin.strip_prefix("https://") {
        return canonical_authority(authority, "443");
    }
    if allow_dev_loopback && let Some(authority) = origin.strip_prefix("http://") {
        let host = authority.rsplit_once(':').map_or(authority, |(host, _)| host);
        return matches!(host, "localhost" | "127.0.0.1") && canonical_authority(authority, "80");
    }
    false
}
