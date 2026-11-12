// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The tab carrier: local-bus frames over a `MessagePort`.
//!
//! The mapping onto the socket carrier is one to one. On the Unix socket a frame is a four-byte
//! length followed by the canonical JSON body; on a port the message boundary replaces the
//! length, and one message carries exactly one body as an `ArrayBuffer`. Everything else is the
//! same admission path: the 1 MiB cap, the depth and value limits, a bounded number of requests
//! in flight per port, and credit for updates. A carrier never implements a method.

use serde::{Deserialize, Serialize};

use crate::WebError;
use crate::role::is_forbidden_method;

/// Same cap as the socket carrier.
pub const MAX_CARRIER_FRAME_BYTES: usize = 1024 * 1024;
/// Parser limits of the admission path.
pub const MAX_CARRIER_JSON_DEPTH: usize = 32;
pub const MAX_CARRIER_JSON_VALUES: usize = 4096;
/// Requests one port may have unanswered.
pub const MAX_PORT_REQUESTS_IN_FLIGHT: u32 = 64;
/// Updates the core may send a port before the port returns credit.
pub const INITIAL_UPDATE_CREDIT: u32 = 256;
/// Attachment chunks above this size travel in the transfer list instead of being copied.
pub const TRANSFER_LIST_THRESHOLD_BYTES: usize = 512 * 1024;
/// Lock name of the single writer.
pub const WRITER_LOCK_NAME: &str = "ramflux.writer.v1";
/// Discovery channel. It carries [`Discovery`] only: never user data, never a port.
pub const DISCOVERY_CHANNEL_NAME: &str = "ramflux.presence.v1";

/// Kind of a local-bus frame, as on the socket carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    Request,
    Response,
    Event,
    Error,
}

/// The routing fields of a local-bus frame. The body is not parsed by the carrier.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FrameHead {
    pub bus_protocol: String,
    pub frame_id: String,
    pub kind: FrameKind,
    pub request_id: String,
    pub method: String,
    #[serde(default)]
    pub sdk_api: String,
    #[serde(default)]
    pub operation_id: Option<String>,
}

/// Protocol label used when a frame was refused before its own label could be read.
pub const CARRIER_BUS_PROTOCOL: &str = "ramflux.local_bus.web";

/// The error frame for a refused request, in the local-bus frame shape. `head` is absent when
/// the frame could not be parsed.
#[must_use]
pub fn refusal_frame(head: Option<&FrameHead>, code: &str, message: &str) -> Vec<u8> {
    let frame = serde_json::json!({
        "bus_protocol": head.map_or(CARRIER_BUS_PROTOCOL, |h| h.bus_protocol.as_str()),
        "frame_id": head.map_or("", |h| h.frame_id.as_str()),
        "kind": "error",
        "request_id": head.map_or("", |h| h.request_id.as_str()),
        "account_id": null,
        "sdk_api": head.map_or("", |h| h.sdk_api.as_str()),
        "method": head.map_or("", |h| h.method.as_str()),
        "body": null,
        "trace_id": null,
        "ok": false,
        "error": { "code": code, "message": message, "retry_after_ms": null },
    });
    ramflux_protocol::canonical_json_bytes(&frame).unwrap_or_default()
}

/// The response frame for a request the web host answered itself.
#[must_use]
pub fn response_frame(head: &FrameHead, body: &serde_json::Value) -> Vec<u8> {
    let frame = serde_json::json!({
        "bus_protocol": head.bus_protocol,
        "frame_id": head.frame_id,
        "kind": "response",
        "request_id": head.request_id,
        "account_id": null,
        "sdk_api": head.sdk_api,
        "method": head.method,
        "body": body,
        "trace_id": null,
        "ok": true,
    });
    ramflux_protocol::canonical_json_bytes(&frame).unwrap_or_default()
}

/// The only thing the discovery channel may carry: no user data, no identifiers, no ports.
/// `tab` is a random value per page; `build` is the release id, so a tab from another build
/// shows "reload" and does not attach.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub t: DiscoveryKind,
    pub tab: String,
    pub visible: bool,
    pub build: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryKind {
    Leader,
    Hello,
    Bye,
}

/// Control messages on a port, beside frames. Sent as structured-clone objects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortControl {
    /// First message on a port, both directions.
    Hello { carrier: u32 },
    /// The page returns update credit.
    Credit { updates: u32 },
    /// The page reports its visibility.
    Visibility { visible: bool },
    /// Liveness probe and its answer.
    Ping { id: u32 },
    Pong { id: u32 },
    /// The leader is draining: no further request is admitted on this port.
    Draining,
    /// The port is done.
    Bye,
}

/// Version of the port carrier.
pub const CARRIER_VERSION: u32 = 1;

/// Why a frame was refused before dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    TooLarge,
    TooDeep,
    TooManyValues,
    Malformed,
    NotARequest,
    TooManyInFlight,
    Draining,
    /// The method does not exist in a browser build.
    CustodyVaultUnavailable,
}

impl Refusal {
    /// Stable code placed in the error frame.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "frame_too_large",
            Self::TooDeep | Self::TooManyValues | Self::Malformed => "frame_malformed",
            Self::NotARequest => "frame_not_request",
            Self::TooManyInFlight => "backpressure",
            Self::Draining => "leader_draining",
            Self::CustodyVaultUnavailable => "custody_vault_unavailable",
        }
    }
}

impl From<Refusal> for WebError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::CustodyVaultUnavailable => {
                Self::CustodyVaultUnavailable("the method does not exist in a browser build")
            }
            other => Self::Carrier(other.code()),
        }
    }
}

/// Check the size, depth and value-count limits without building a document.
///
/// # Errors
/// Returns the first limit the frame exceeds.
pub fn scan_limits(bytes: &[u8]) -> Result<(), Refusal> {
    if bytes.len() > MAX_CARRIER_FRAME_BYTES {
        return Err(Refusal::TooLarge);
    }
    let mut depth = 0_usize;
    let mut values = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_scalar = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                in_scalar = false;
                values += 1;
            }
            b'{' | b'[' => {
                in_scalar = false;
                depth += 1;
                values += 1;
                if depth > MAX_CARRIER_JSON_DEPTH {
                    return Err(Refusal::TooDeep);
                }
            }
            b'}' | b']' => {
                in_scalar = false;
                depth = depth.checked_sub(1).ok_or(Refusal::Malformed)?;
            }
            b',' | b':' | b' ' | b'\n' | b'\r' | b'\t' => in_scalar = false,
            _ => {
                if !in_scalar {
                    in_scalar = true;
                    values += 1;
                }
            }
        }
        // Object keys are counted as strings, so the bound is conservative.
        if values > 2 * MAX_CARRIER_JSON_VALUES {
            return Err(Refusal::TooManyValues);
        }
    }
    if depth != 0 || in_string {
        return Err(Refusal::Malformed);
    }
    Ok(())
}

/// Per-port admission state held by the leader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortAdmission {
    in_flight: u32,
    update_credit: u32,
    draining: bool,
}

impl Default for PortAdmission {
    fn default() -> Self {
        Self { in_flight: 0, update_credit: INITIAL_UPDATE_CREDIT, draining: false }
    }
}

impl PortAdmission {
    /// Admit one request frame from a page.
    ///
    /// # Errors
    /// Returns the refusal to place in the error frame. A refused frame never reaches dispatch.
    pub fn admit_request(&mut self, bytes: &[u8]) -> Result<FrameHead, Refusal> {
        scan_limits(bytes)?;
        let head: FrameHead = serde_json::from_slice(bytes).map_err(|_| Refusal::Malformed)?;
        if head.kind != FrameKind::Request {
            return Err(Refusal::NotARequest);
        }
        if is_forbidden_method(&head.method) {
            return Err(Refusal::CustodyVaultUnavailable);
        }
        if self.draining {
            return Err(Refusal::Draining);
        }
        if self.in_flight >= MAX_PORT_REQUESTS_IN_FLIGHT {
            return Err(Refusal::TooManyInFlight);
        }
        self.in_flight += 1;
        Ok(head)
    }

    /// A response or error frame for an admitted request was posted.
    pub const fn complete_request(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Whether one more update may be posted; consumes credit when it may.
    pub const fn take_update_credit(&mut self) -> bool {
        if self.update_credit == 0 {
            return false;
        }
        self.update_credit -= 1;
        true
    }

    /// The page returned credit. The total never exceeds the initial window.
    pub fn add_update_credit(&mut self, updates: u32) {
        self.update_credit = self.update_credit.saturating_add(updates).min(INITIAL_UPDATE_CREDIT);
    }

    /// Stop admitting. Requests already in flight finish or fail.
    pub const fn drain(&mut self) {
        self.draining = true;
    }

    #[must_use]
    pub const fn in_flight(&self) -> u32 {
        self.in_flight
    }
}

/// Whether a `MessageEvent` on the worker may attach a port: same origin only.
#[must_use]
pub fn port_origin_allowed(event_origin: &str, own_origin: &str) -> bool {
    // A dedicated worker receives an empty origin for messages from its own page.
    event_origin.is_empty() || event_origin == own_origin
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str) -> Vec<u8> {
        format!(
            r#"{{"bus_protocol":"1","frame_id":"f","kind":"request","request_id":"r","account_id":null,"sdk_api":"1","method":"{method}","body":{{}},"trace_id":null}}"#
        )
        .into_bytes()
    }

    #[test]
    fn admits_a_request_and_counts_it() {
        let mut port = PortAdmission::default();
        assert_eq!(port.admit_request(&request("message.submit")).map(|h| h.method), Ok("message.submit".to_owned()));
        assert_eq!(port.in_flight(), 1);
        port.complete_request();
        assert_eq!(port.in_flight(), 0);
    }

    #[test]
    fn refuses_account_creation_and_recovery_before_dispatch() {
        let mut port = PortAdmission::default();
        for method in ["account.create", "recovery.initiate", "device.pair.approve", "device.migrate"] {
            assert_eq!(port.admit_request(&request(method)), Err(Refusal::CustodyVaultUnavailable));
        }
        assert_eq!(port.in_flight(), 0);
    }

    #[test]
    fn refuses_oversized_deep_and_unbalanced_frames() {
        assert_eq!(scan_limits(&vec![b' '; MAX_CARRIER_FRAME_BYTES + 1]), Err(Refusal::TooLarge));
        assert_eq!(scan_limits("[".repeat(33).as_bytes()), Err(Refusal::TooDeep));
        assert_eq!(scan_limits(b"{\"a\":1"), Err(Refusal::Malformed));
        assert_eq!(scan_limits(b"{\"a\":\"}\"}"), Ok(()));
    }

    #[test]
    fn refuses_more_values_than_the_parser_bound() {
        let many = format!("[{}]", vec!["1"; 2 * MAX_CARRIER_JSON_VALUES + 2].join(","));
        assert_eq!(scan_limits(many.as_bytes()), Err(Refusal::TooManyValues));
    }

    #[test]
    fn bounds_requests_in_flight_and_update_credit() {
        let mut port = PortAdmission::default();
        for _ in 0..MAX_PORT_REQUESTS_IN_FLIGHT {
            assert!(port.admit_request(&request("message.submit")).is_ok());
        }
        assert_eq!(port.admit_request(&request("message.submit")), Err(Refusal::TooManyInFlight));
        for _ in 0..INITIAL_UPDATE_CREDIT {
            assert!(port.take_update_credit());
        }
        assert!(!port.take_update_credit());
        port.add_update_credit(u32::MAX);
        assert!(port.take_update_credit());
    }

    #[test]
    fn a_draining_port_admits_nothing() {
        let mut port = PortAdmission::default();
        port.drain();
        assert_eq!(port.admit_request(&request("message.submit")), Err(Refusal::Draining));
    }

    #[test]
    fn discovery_messages_cannot_carry_user_data() {
        let plain = r#"{"t":"leader","tab":"n","visible":true,"build":"b"}"#;
        assert!(serde_json::from_str::<Discovery>(plain).is_ok());
        let extra = r#"{"t":"leader","tab":"n","visible":true,"build":"b","body":"hello"}"#;
        assert!(serde_json::from_str::<Discovery>(extra).is_err());
    }

    #[test]
    fn a_foreign_origin_cannot_attach_a_port() {
        assert!(port_origin_allowed("https://app.example.org", "https://app.example.org"));
        assert!(!port_origin_allowed("https://evil.example.org", "https://app.example.org"));
    }
}
