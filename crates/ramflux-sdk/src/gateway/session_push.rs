// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Decoders for negotiated (capable) session-push server frames.
//!
//! Server frames are decode-only in the SDK. The types mirror the gateway wire shapes, and
//! every grammar and coupling rule the gateway guarantees is enforced here, so a frame that
//! the gateway can never produce is refused at decode time. Nothing is wired yet.
#![allow(dead_code)]

use super::{GatewayCursor, GatewayInboxEntry, GatewayServerFrame};
use serde::{Deserialize, Serialize};

mod client;
#[allow(unused_imports)]
pub(crate) use client::{CapableClientFrame, ClientFrameError};
#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod negotiation_tests;
#[cfg(test)]
mod routing_tests;
#[cfg(test)]
mod server_tests;

/// A 32-character lowercase hexadecimal inbox incarnation identifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "String")]
pub(crate) struct IncarnationId(String);

impl IncarnationId {
    fn valid(id: &str) -> bool {
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for IncarnationId {
    type Error = &'static str;
    fn try_from(id: String) -> Result<Self, Self::Error> {
        if Self::valid(&id) { Ok(Self(id)) } else { Err("invalid inbox incarnation id") }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct PageEntryRecord {
    pub(crate) entry: GatewayInboxEntry,
    pub(crate) retain_until: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PageReason {
    Expired,
    AckWindowOverflow,
    Nacked,
    Aborted,
}

/// `Unknown` is valid only for a point read of a vanished entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EntryGoneReason {
    Expired,
    AckWindowOverflow,
    Nacked,
    Aborted,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(try_from = "RawKnownLoss")]
pub(crate) struct KnownLoss {
    pub(crate) from_seq: u64,
    pub(crate) to_seq: u64,
    pub(crate) reason: PageReason,
}

#[derive(Deserialize)]
struct RawKnownLoss {
    from_seq: u64,
    to_seq: u64,
    reason: PageReason,
}

impl TryFrom<RawKnownLoss> for KnownLoss {
    type Error = &'static str;
    fn try_from(raw: RawKnownLoss) -> Result<Self, Self::Error> {
        if raw.from_seq > raw.to_seq {
            return Err("known loss from_seq exceeds to_seq");
        }
        Ok(Self { from_seq: raw.from_seq, to_seq: raw.to_seq, reason: raw.reason })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AckOutcome {
    Acked,
    AlreadySettled,
    NotFound,
    InvalidSeq,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(try_from = "RawAckResult")]
pub(crate) struct AckResult {
    pub(crate) inbox_seq: u64,
    pub(crate) outcome: AckOutcome,
    pub(crate) reason: Option<String>,
}

#[derive(Deserialize)]
struct RawAckResult {
    inbox_seq: u64,
    outcome: AckOutcome,
    reason: Option<String>,
}

impl TryFrom<RawAckResult> for AckResult {
    type Error = &'static str;
    fn try_from(raw: RawAckResult) -> Result<Self, Self::Error> {
        match (raw.outcome, raw.reason.as_deref()) {
            (
                AckOutcome::Acked
                | AckOutcome::AlreadySettled
                | AckOutcome::NotFound
                | AckOutcome::InvalidSeq,
                None,
            )
            | (AckOutcome::Rejected, Some("ack_backpressure_retry" | "invalid_seq")) => {}
            (AckOutcome::Rejected, _) => return Err("rejected ack reason is not allowed"),
            _ => return Err("ack reason must be null for this outcome"),
        }
        Ok(Self { inbox_seq: raw.inbox_seq, outcome: raw.outcome, reason: raw.reason })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResyncReason {
    QueueFull,
    NotPushed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PushNackReason {
    IncarnationMismatch,
    InvalidSeq,
    InvalidLimit,
    CursorAhead,
    PayloadTooLarge,
    AckBackpressureRetry,
    GatewayRequestInvalid,
    InvalidResumeToken,
    Busy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionEstablished {
    pub(crate) session_id: String,
    pub(crate) gateway_id: String,
    pub(crate) accepted_cursor: Option<GatewayCursor>,
    pub(crate) resume_token: String,
    pub(crate) resume_window_seconds: u64,
    pub(crate) capabilities: Vec<String>,
    pub(crate) inbox_incarnation_id: IncarnationId,
}

/// One negotiated server frame. Unknown tags and unknown fields are refused.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "frame_type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CapableServerFrame {
    SessionEstablished {
        session: SessionEstablished,
    },
    Deliver {
        entry: GatewayInboxEntry,
        incarnation_id: IncarnationId,
        retain_until: i64,
    },
    SubmitAccepted {
        incarnation_id: IncarnationId,
        envelope_id: String,
        target_delivery_id: String,
        inbox_seq: u64,
    },
    ResumePage {
        target_delivery_id: String,
        incarnation_id: IncarnationId,
        after_inbox_seq: u64,
        covered_through_seq: u64,
        issued_inbox_seq: u64,
        settled_through_seq: u64,
        entries: Vec<PageEntryRecord>,
        known_losses: Vec<KnownLoss>,
        oversize_next: Option<u64>,
        more: bool,
    },
    Entry {
        incarnation_id: IncarnationId,
        record: Box<PageEntryRecord>,
    },
    EntryTooLarge {
        incarnation_id: IncarnationId,
        inbox_seq: u64,
        retain_until: i64,
    },
    EntryGone {
        incarnation_id: IncarnationId,
        inbox_seq: u64,
        observed_issued_inbox_seq: u64,
        reason: EntryGoneReason,
    },
    AckBatch {
        incarnation_id: IncarnationId,
        cursor: GatewayCursor,
        results: Vec<AckResult>,
    },
    Ack {
        incarnation_id: IncarnationId,
        cursor: GatewayCursor,
    },
    Cursor {
        incarnation_id: IncarnationId,
        cursor: Option<GatewayCursor>,
    },
    Resync {
        incarnation_id: IncarnationId,
        target_delivery_id: String,
        after_inbox_seq: u64,
        reason: ResyncReason,
    },
    Nack {
        reason: PushNackReason,
        incarnation_id: Option<IncarnationId>,
    },
}

/// Decodes one capable server frame from its wire bytes.
///
/// # Errors
/// Returns the decode error for malformed JSON, unknown tags or fields, missing fields,
/// grammar violations and coupling violations.
pub(crate) fn decode_server_frame(bytes: &[u8]) -> Result<CapableServerFrame, serde_json::Error> {
    serde_json::from_slice(bytes)
}
/// How a session was negotiated. Frozen at establishment; a reconnect negotiates again.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SessionMode {
    /// The capability was not advertised and nothing was echoed.
    Legacy,
    /// The capability was advertised but the gateway did not echo it.
    Compat,
    /// Advertised, echoed and accompanied by a valid inbox incarnation.
    Push { incarnation: IncarnationId },
}

/// The second decode of the establishment frame bytes.
#[derive(Debug, Deserialize)]
struct EchoFrame {
    session: EchoSession,
}

#[derive(Debug, Deserialize)]
struct EchoSession {
    #[serde(default)]
    capabilities: Option<Vec<String>>,
    #[serde(default)]
    inbox_incarnation_id: Option<String>,
}

/// What the gateway echoed on `session_established`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct EstablishmentEcho {
    capabilities: Option<Vec<String>>,
    inbox_incarnation_id: Option<String>,
}

impl EstablishmentEcho {
    /// # Errors
    /// Refuses establishment bytes whose echo fields have the wrong JSON types.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, crate::SdkError> {
        let frame: EchoFrame =
            serde_json::from_slice(bytes).map_err(|_| refused("echo is malformed"))?;
        Ok(Self {
            capabilities: frame.session.capabilities,
            inbox_incarnation_id: frame.session.inbox_incarnation_id,
        })
    }
}

fn refused(why: &str) -> crate::SdkError {
    crate::SdkError::GatewaySessionRejected(format!("session push negotiation refused: {why}"))
}

/// Push needs all three operands: advertised, echoed, and a valid incarnation.
///
/// # Errors
/// Refuses an echo of anything that was not advertised, an incarnation without an echo, an
/// echo without an incarnation, and a malformed incarnation.
pub(crate) fn negotiate(
    advertised: bool,
    echo: &EstablishmentEcho,
) -> Result<SessionMode, crate::SdkError> {
    let capabilities = echo.capabilities.as_deref().unwrap_or(&[]);
    if capabilities.iter().any(|capability| {
        !(advertised && capability == ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY)
    }) {
        return Err(refused("echo names a capability that was not advertised"));
    }
    match (capabilities.is_empty(), &echo.inbox_incarnation_id) {
        (true, Some(_)) => Err(refused("incarnation without an echoed capability")),
        (true, None) => Ok(if advertised { SessionMode::Compat } else { SessionMode::Legacy }),
        (false, None) => Err(refused("echo without an inbox incarnation")),
        (false, Some(id)) => IncarnationId::try_from(id.clone())
            .map(|incarnation| SessionMode::Push { incarnation })
            .map_err(|_| refused("invalid inbox incarnation")),
    }
}

impl CapableServerFrame {
    /// Events carry no request; every other capable frame is a reply.
    pub(crate) const fn is_event(&self) -> bool {
        matches!(self, Self::Deliver { .. } | Self::Resync { .. })
    }
}

/// Where the raw bytes of one frame go.
#[derive(Debug)]
pub(crate) enum Routed {
    Legacy(Box<GatewayServerFrame>),
    Capable(Box<CapableServerFrame>),
}

/// Why a frame could not be routed. Everything except `Legacy` retires the session.
#[derive(Debug)]
pub(crate) enum RouteError {
    /// The frame is not allowed in this mode; the text names the arm.
    Retire(&'static str),
    /// A capable frame failed its strict decode. It is never re-read as legacy.
    Capable(serde_json::Error),
    /// A legacy frame failed to decode, exactly as before routing existed.
    Legacy(serde_json::Error),
}

/// Frames only a negotiated gateway sends; each always carries `incarnation_id`.
const CAPABLE_ONLY: [&str; 7] = [
    "resume_page",
    "entry",
    "entry_too_large",
    "entry_gone",
    "ack_batch",
    "submit_accepted",
    "resync",
];
/// Tags shared by both protocols; the `incarnation_id` key selects the shape.
const SHARED: [&str; 4] = ["deliver", "ack", "cursor", "nack"];

fn legacy(bytes: &[u8]) -> Result<Routed, RouteError> {
    serde_json::from_slice(bytes)
        .map(|frame| Routed::Legacy(Box::new(frame)))
        .map_err(RouteError::Legacy)
}

fn capable(bytes: &[u8]) -> Result<Routed, RouteError> {
    decode_server_frame(bytes)
        .map(|frame| Routed::Capable(Box::new(frame)))
        .map_err(RouteError::Capable)
}

/// Routes one raw frame from its `frame_type` and the presence of `incarnation_id`.
///
/// # Errors
/// See [`RouteError`]. A capable decode failure never falls back to legacy decoding.
pub(crate) fn route(bytes: &[u8], mode: &SessionMode) -> Result<Routed, RouteError> {
    let peek = match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(serde_json::Value::Object(map)) => map
            .get("frame_type")
            .and_then(serde_json::Value::as_str)
            .map(|tag| (tag.to_owned(), map.contains_key("incarnation_id"))),
        _ => None,
    };
    let Some((tag, keyed)) = peek else { return legacy(bytes) };
    let capable_only = CAPABLE_ONLY.contains(&tag.as_str());
    let shared = SHARED.contains(&tag.as_str());
    if matches!(mode, SessionMode::Push { .. }) {
        return match (tag.as_str(), keyed) {
            _ if capable_only || (shared && keyed) => capable(bytes),
            ("deliver" | "ack", false) => {
                Err(RouteError::Retire("keyless shape in a push session"))
            }
            ("resume", _) => Err(RouteError::Retire("legacy resume in a push session")),
            // Keyless `nack`/`cursor` (submit refusals, legacy cursor) and every other tag.
            _ => legacy(bytes),
        };
    }
    if capable_only || (shared && keyed) {
        return Err(RouteError::Retire("capable frame on an unnegotiated session"));
    }
    legacy(bytes)
}
