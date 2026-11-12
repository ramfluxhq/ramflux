// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Web wire contract v0: constants, the origin-binding context and the frames a browser sends
//! and accepts before the gateway session exists.
//!
//! The frame shapes are byte-identical to the native custody frames. They are declared here with
//! a string `binding_mode` because the browser accepts exactly one mode and refuses every other
//! value before it parses anything else.

use ramflux_protocol::custody::{CustodyProofAction, DeviceRef, Envelope};
use ramflux_protocol::{canonical_json_bytes, encode_base64url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::WebError;

pub const WEB_SESSION_SUBPROTOCOL: &str = "ramflux.gateway_session.v1";
pub const WEB_SESSION_PATH: &str = "/v1/session";
pub const WEB_ORIGIN_BINDING_SCHEMA: &str = "ramflux.web_origin_binding.v1";
pub const TRANSPORT_KIND_WEBSOCKET: &str = "websocket";
pub const CAPABILITY_WEB_SECONDARY: &str = "web_secondary";
pub const CAPABILITY_WEB_ORIGIN_PREFIX: &str = "web_origin.";
pub const BINDING_MODE_WEB_ORIGIN_BOUND: &str = "web_origin_bound";

/// Largest frame body on an established session.
pub const MAX_GATEWAY_FRAME_BYTES: usize = 1_048_576;
/// Largest frame body before the gateway `session_established`.
pub const WEB_PRE_SESSION_FRAME_MAX_BYTES: usize = 65_536;
/// Exact lifetime of a binding context.
pub const WEB_BINDING_WINDOW_SECS: u64 = 300;
/// Allowed distance between the local clock and `issued_at`.
pub const WEB_CLOCK_SKEW_SECS: u64 = 300;
/// The gateway clamps the windows to these values on the web listener.
pub const WEB_DOWNSTREAM_WINDOW_ENTRIES: u32 = 16;
pub const WEB_UPSTREAM_WINDOW_ENTRIES: u32 = 4;
/// No new `submit` is written while `bufferedAmount` is above this.
pub const WEB_SEND_BUFFER_HIGH_WATER_BYTES: u32 = 1_048_576;
/// Application heartbeat period while the page is visible.
pub const WEB_HEARTBEAT_INTERVAL_MS: u32 = 25_000;
/// Longest proof lifetime.
pub const WEB_PROOF_MAX_LIFETIME_SECS: u64 = 300;

const BRANCH_PROOF_VERSION: u32 = 3;

/// The connection facts a web branch proof commits to.
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
    /// `base64url(SHA-256("ramflux.web_origin_binding.v1" || 0x00 || canonical_json(self)))`.
    ///
    /// # Errors
    /// Returns [`WebError::Encoding`] when canonical serialization fails.
    pub fn transport_binding(&self) -> Result<String, WebError> {
        let mut hasher = Sha256::new();
        hasher.update(WEB_ORIGIN_BINDING_SCHEMA.as_bytes());
        hasher.update([0_u8]);
        hasher.update(canonical_json_bytes(self)?);
        Ok(encode_base64url(hasher.finalize()))
    }
}

/// The capability a web certificate carries for `origin`.
#[must_use]
pub fn web_origin_capability(origin: &str) -> String {
    format!("{CAPABILITY_WEB_ORIGIN_PREFIX}{}", encode_base64url(Sha256::digest(origin.as_bytes())))
}

/// Whether `url` is a canonical listener URL: `wss`, lowercase host, no default port, the fixed
/// path, and no query, fragment or userinfo.
#[must_use]
pub fn is_canonical_listener_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("wss://") else { return false };
    let Some(authority) = rest.strip_suffix(WEB_SESSION_PATH) else { return false };
    !authority.is_empty()
        && !authority.ends_with(":443")
        && authority
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

/// Whether `origin` is a serialized secure origin the contract allows.
#[must_use]
pub fn is_serialized_origin(origin: &str) -> bool {
    let Some(host) = origin.strip_prefix("https://") else { return false };
    !host.is_empty()
        && !host.ends_with(":443")
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

/// Verifier state for the proof, as sent by the node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebBranchChallenge {
    pub challenge_nonce: String,
    pub action_hash: String,
    pub audience: String,
    pub binding_mode: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// `BranchProofV3` with the web binding mode. Field names and order match the native body, so the
/// canonical bytes and therefore the signature are the ones the node verifies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebBranchProof {
    pub schema: String,
    pub version: u32,
    pub device_ref: DeviceRef,
    pub certificate_hash: String,
    pub record_hash: String,
    pub proof_id: String,
    pub challenge_nonce: String,
    pub action_hash: String,
    pub audience: String,
    pub binding_mode: String,
    pub transport_binding: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl WebBranchProof {
    #[must_use]
    pub const fn version() -> u32 {
        BRANCH_PROOF_VERSION
    }
}

/// `GatewayOpenFrame`, field for field. The browser always sends `transport_kind = "websocket"`
/// and null for the two deprecated admission fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebOpenFrame {
    pub protocol_version: String,
    pub transport_kind: String,
    pub client_instance_id: String,
    pub device_id: String,
    pub target_delivery_id: String,
    pub stream_nonce: String,
    pub previous_session_id: Option<String>,
    pub resume_token_hash: Option<String>,
    pub last_seen_inbox_seq: Option<u64>,
    pub max_inflight_downstream: u32,
    pub max_inflight_upstream: u32,
    pub pre_auth_cookie: Option<String>,
    pub pre_auth_now: Option<u64>,
    pub source_ip_hash: Option<String>,
}

/// Frames the browser sends until the gateway session exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "frame_type", rename_all = "snake_case")]
pub enum WebClientFrame {
    CustodyOpen { binding_mode: String },
    Challenge { device_ref: DeviceRef, action: CustodyProofAction },
    Prove { action: CustodyProofAction, proof: Box<Envelope<WebBranchProof>> },
    GatewayHandoff { session_id: String },
    Open { open: WebOpenFrame },
    Auth { auth: Value },
    Heartbeat { now: u64 },
}

impl WebClientFrame {
    /// One binary WebSocket message: the canonical JSON body, no length prefix.
    ///
    /// # Errors
    /// Returns [`WebError::Protocol`] when the body exceeds `cap`.
    pub fn encode(&self, cap: usize) -> Result<Vec<u8>, WebError> {
        let bytes = canonical_json_bytes(self)?;
        if bytes.len() > cap {
            return Err(WebError::Protocol("outbound frame exceeds the frame cap"));
        }
        Ok(bytes)
    }
}

/// Frames the browser accepts until the gateway session exists. Anything else closes.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "frame_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebServerFrame {
    NodeIdentity {
        record: Box<Envelope<Value>>,
        audience: String,
        binding_mode: String,
        proxy_key_custody: Option<String>,
    },
    WebBinding {
        context: WebOriginBindingV1,
    },
    Challenge {
        challenge: WebBranchChallenge,
    },
    /// Reply to the device's own first prekey registration.
    Registered {
        device_ref: DeviceRef,
        target_delivery_id: String,
    },
    /// Sent twice: first the custody session, then the gateway session.
    SessionEstablished {
        session: Value,
    },
    Refused {
        code: Value,
        #[serde(default)]
        capacity: Option<Value>,
        #[serde(default)]
        retry: Option<Value>,
    },
    Closed,
}

impl WebServerFrame {
    /// Parse one binary message under the pre-session size cap.
    ///
    /// # Errors
    /// Returns [`WebError::Protocol`] for an oversized or unparseable frame.
    pub fn decode(bytes: &[u8], cap: usize) -> Result<Self, WebError> {
        if bytes.len() > cap {
            return Err(WebError::Protocol("inbound frame exceeds the frame cap"));
        }
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> WebOriginBindingV1 {
        WebOriginBindingV1 {
            schema: WEB_ORIGIN_BINDING_SCHEMA.to_owned(),
            version: 1,
            node_id: "node-a".to_owned(),
            listener_url: "wss://gw.example.org/v1/session".to_owned(),
            origin: "https://app.example.org".to_owned(),
            transport_kind: TRANSPORT_KIND_WEBSOCKET.to_owned(),
            gateway_nonce: encode_base64url([7_u8; 32]),
            issued_at: 1_794_500_000,
            expires_at: 1_794_500_300,
        }
    }

    #[test]
    fn transport_binding_is_a_canonical_32_byte_digest() {
        let binding = context().transport_binding().unwrap_or_default();
        assert_eq!(binding.len(), 43);
        assert_eq!(binding, context().transport_binding().unwrap_or_default());
    }

    #[test]
    fn transport_binding_changes_with_every_bound_field() {
        let base = context().transport_binding().unwrap_or_default();
        let mut other = context();
        other.origin = "https://evil.example.org".to_owned();
        assert_ne!(base, other.transport_binding().unwrap_or_default());
        let mut other = context();
        other.gateway_nonce = encode_base64url([8_u8; 32]);
        assert_ne!(base, other.transport_binding().unwrap_or_default());
        let mut other = context();
        other.listener_url = "wss://gw2.example.org/v1/session".to_owned();
        assert_ne!(base, other.transport_binding().unwrap_or_default());
    }

    /// The vector published with the wire contract. A mismatch is a contract defect to report,
    /// never something to adjust here.
    #[test]
    fn matches_the_published_binding_vector() {
        let nonce: Vec<u8> = (0_u8..32).collect();
        let context = WebOriginBindingV1 {
            schema: WEB_ORIGIN_BINDING_SCHEMA.to_owned(),
            version: 1,
            node_id: "node-test-1".to_owned(),
            listener_url: "wss://gw.example.org/v1/session".to_owned(),
            origin: "https://app.example.org".to_owned(),
            transport_kind: TRANSPORT_KIND_WEBSOCKET.to_owned(),
            gateway_nonce: encode_base64url(nonce),
            issued_at: 1_794_500_000,
            expires_at: 1_794_500_300,
        };
        assert_eq!(context.gateway_nonce, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");
        assert_eq!(canonical_json_bytes(&context).unwrap_or_default().len(), 300);
        assert_eq!(
            context.transport_binding().unwrap_or_default(),
            "CKlX68oOgKaKA1Ge--x80MJRhxwqiB4o5NeJDQ-nW9w"
        );
        assert_eq!(
            web_origin_capability("https://app.example.org"),
            "web_origin.487C9TSCgR2-ucQeh7narsodVJyxrDUqvu46Ghtt9Js"
        );
    }

    #[test]
    fn origin_capability_has_43_characters_after_the_dot() {
        let capability = web_origin_capability("https://app.example.org");
        assert_eq!(capability.len(), CAPABILITY_WEB_ORIGIN_PREFIX.len() + 43);
    }

    #[test]
    fn rejects_noncanonical_listener_urls() {
        assert!(is_canonical_listener_url("wss://gw.example.org/v1/session"));
        for bad in [
            "ws://gw.example.org/v1/session",
            "wss://gw.example.org:443/v1/session",
            "wss://GW.example.org/v1/session",
            "wss://gw.example.org/v1/session/",
            "wss://gw.example.org/v1/session?x=1",
            "wss://user@gw.example.org/v1/session",
        ] {
            assert!(!is_canonical_listener_url(bad), "{bad}");
        }
    }

    #[test]
    fn custody_open_is_the_exact_contract_bytes() {
        let frame =
            WebClientFrame::CustodyOpen { binding_mode: BINDING_MODE_WEB_ORIGIN_BOUND.to_owned() };
        let bytes = frame.encode(WEB_PRE_SESSION_FRAME_MAX_BYTES).unwrap_or_default();
        assert_eq!(
            bytes,
            br#"{"binding_mode":"web_origin_bound","frame_type":"custody_open"}"#.to_vec()
        );
    }

    #[test]
    fn unknown_server_frame_is_refused() {
        let result = WebServerFrame::decode(br#"{"frame_type":"peer","peer":{}}"#, 65_536);
        assert!(result.is_err());
    }
}
