// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Negotiated session frames, separate from the legacy public literal types.
use serde::{Deserialize, Serialize};
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "frame_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionPushClientFrame {
    Resume { resume: crate::GatewayResumeFrame, incarnation_id: String },
    FetchEntry { incarnation_id: String, inbox_seq: u64 },
    AckBatch { incarnation_id: String, inbox_seqs: Vec<u64> },
    Ack { incarnation_id: String, ack: ramflux_protocol::Ack },
    Nack { incarnation_id: String, nack: ramflux_protocol::Nack },
}
#[derive(Debug, Serialize)]
pub struct SessionPushEstablishedFrame {
    #[serde(flatten)]
    pub session: crate::GatewaySessionEstablishedFrame,
    pub capabilities: Vec<String>,
    pub inbox_incarnation_id: String,
}
#[derive(Debug, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "frame_type", rename_all = "snake_case")]
pub enum SessionPushServerFrame {
    SessionEstablished {
        session: SessionPushEstablishedFrame,
    },
    Deliver {
        entry: crate::InboxEntry,
        incarnation_id: String,
        retain_until: i64,
    },
    SubmitAccepted {
        incarnation_id: String,
        envelope_id: String,
        target_delivery_id: String,
        inbox_seq: u64,
    },
    ResumePage {
        target_delivery_id: String,
        incarnation_id: String,
        after_inbox_seq: u64,
        covered_through_seq: u64,
        issued_inbox_seq: u64,
        settled_through_seq: u64,
        entries: Vec<crate::PageEntryRecord>,
        known_losses: Vec<crate::KnownLoss>,
        oversize_next: Option<u64>,
        more: bool,
    },
    Entry {
        incarnation_id: String,
        record: Box<crate::PageEntryRecord>,
    },
    EntryTooLarge {
        incarnation_id: String,
        inbox_seq: u64,
        retain_until: i64,
    },
    EntryGone {
        incarnation_id: String,
        inbox_seq: u64,
        observed_issued_inbox_seq: u64,
        reason: crate::EntryGoneReason,
    },
    AckBatch {
        incarnation_id: String,
        cursor: crate::InboxCursorResponse,
        results: Vec<crate::SessionAckResult>,
    },
    Ack {
        incarnation_id: String,
        cursor: crate::InboxCursorResponse,
    },
    Cursor {
        incarnation_id: String,
        cursor: Option<crate::InboxCursorResponse>,
    },
    Resync {
        incarnation_id: String,
        target_delivery_id: String,
        after_inbox_seq: u64,
        reason: SessionPushResyncReason,
    },
    Nack {
        reason: SessionPushNackReason,
        incarnation_id: Option<String>,
    },
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPushResyncReason {
    QueueFull,
    NotPushed,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPushNackReason {
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
/// Validate the wire incarnation grammar before sending an untrusted request to the router.
#[must_use]
pub fn valid_inbox_incarnation(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
