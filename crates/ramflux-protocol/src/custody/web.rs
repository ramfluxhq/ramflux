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

#[cfg(test)]
mod tests {
    use super::{
        WebListener, is_canonical_web_listener_url, is_canonical_web_origin, web_listener_authority,
    };
    use crate::custody::{BindingMode, NodeIdentityRecord};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn record(web_listeners: Vec<WebListener>) -> NodeIdentityRecord {
        NodeIdentityRecord {
            schema: "ramflux.identity.node_record.v1".to_owned(),
            version: 1,
            node_id: "node".to_owned(),
            node_signing_public_key: "key".to_owned(),
            client_tls_certificate_sha256: None,
            epoch: 1,
            previous_record_hash: None,
            issued_at: 1,
            receipt_keys: Vec::new(),
            revoked_receipt_key_ids: Vec::new(),
            proxy_keys: Vec::new(),
            revoked_proxy_key_ids: Vec::new(),
            channel_binding_modes: vec![BindingMode::HomeRelayReceipt],
            web_listeners,
        }
    }

    #[test]
    fn node_record_without_web_listeners_keeps_its_canonical_hash() -> TestResult {
        let bytes = crate::canonical_json_bytes(&record(Vec::new()))?;
        let text = String::from_utf8(bytes)?;
        assert!(!text.contains("web_listeners"));
        // A record written before the field existed still decodes, and re-encodes equal.
        let decoded: NodeIdentityRecord = crate::custody::decode(text.as_bytes(), 4096)?;
        assert_eq!(crate::canonical_json_bytes(&decoded)?, text.as_bytes());
        // An explicit empty list is not the canonical form and is refused.
        let explicit = text.replacen('{', r#"{"web_listeners":[],"#, 1);
        assert!(crate::custody::decode::<NodeIdentityRecord>(explicit.as_bytes(), 4096).is_err());
        Ok(())
    }

    #[test]
    fn web_binding_mode_and_listener_use_the_contract_wire_names() -> TestResult {
        assert_eq!(serde_json::to_string(&BindingMode::WebOriginBound)?, r#""web_origin_bound""#);
        let listed = record(vec![WebListener {
            url: "wss://gw.example.org/v1/session".to_owned(),
            origins: vec!["https://app.example.org".to_owned()],
        }]);
        let value = serde_json::to_value(&listed)?;
        assert_eq!(value["web_listeners"][0]["url"], "wss://gw.example.org/v1/session");
        assert_eq!(value["web_listeners"][0]["origins"][0], "https://app.example.org");
        Ok(())
    }

    #[test]
    fn listener_url_and_origin_canonical_forms() {
        assert!(is_canonical_web_listener_url("wss://gw.example.org/v1/session"));
        assert!(is_canonical_web_listener_url("wss://gw.example.org:8443/v1/session"));
        assert_eq!(
            web_listener_authority("wss://gw.example.org:8443/v1/session"),
            Some("gw.example.org:8443")
        );
        for url in [
            "wss://gw.example.org:443/v1/session",
            "wss://GW.example.org/v1/session",
            "wss://gw.example.org/v1/session/",
            "wss://gw.example.org/v1/session?x",
            "wss://user@gw.example.org/v1/session",
            "ws://gw.example.org/v1/session",
            "wss:///v1/session",
        ] {
            assert!(!is_canonical_web_listener_url(url), "{url}");
        }
        assert!(is_canonical_web_origin("https://app.example.org", false));
        assert!(is_canonical_web_origin("http://localhost:5173", true));
        for origin in ["null", "*", "https://app.example.org/", "http://app.example.org", ""] {
            assert!(!is_canonical_web_origin(origin, true), "{origin}");
        }
        assert!(!is_canonical_web_origin("http://localhost:5173", false));
    }
}
