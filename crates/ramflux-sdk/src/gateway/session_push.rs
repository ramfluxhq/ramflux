// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Decoders for negotiated (capable) session-push server frames.
//!
//! Server frames are decode-only in the SDK. The types mirror the gateway wire shapes, and
//! every grammar and coupling rule the gateway guarantees is enforced here, so a frame that
//! the gateway can never produce is refused at decode time. Nothing is wired yet.
#![allow(dead_code)]

use super::{GatewayCursor, GatewayInboxEntry};
use serde::Deserialize;

#[cfg(test)]
mod server_tests;

/// A 32-character lowercase hexadecimal inbox incarnation identifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
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
