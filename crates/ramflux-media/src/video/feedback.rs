// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Video feedback (PT113 payload, V2.1): the frozen 64-byte report, its
//! stale-report refusal, and coalesced IDR (keyframe) requests.
//!
//! Layout, network order, all reserved bits zero (frozen by the V1V3 card):
//!
//! | offset | size | field |
//! |---:|---:|---|
//! | 0 | 1 | version (1) |
//! | 1 | 1 | flags (no bits defined yet; must be zero) |
//! | 2 | 2 | `reserved` |
//! | 4 | 4 | `track_revision` |
//! | 8 | 8 | `report_seq` |
//! | 16 | 8 | `highest_video_counter` |
//! | 24 | 8 | `received_packets` |
//! | 32 | 8 | `missing_packets` |
//! | 40 | 8 | `received_bytes` |
//! | 48 | 4 | `delay_delta_us` (i32) |
//! | 52 | 4 | `keyframe_request_revision` |
//! | 56 | 4 | `keyframe_ack_revision` |
//! | 60 | 4 | `reserved` |
//!
//! Counters are cumulative per track. Feedback grants no authority: it only
//! adjusts rate and asks for keyframes within negotiated caps.

use std::time::{Duration, Instant};

/// RTP payload type of feedback (PT113), on the video SFrame key.
pub const FEEDBACK_PAYLOAD_TYPE: u8 = 113;
/// Largest feedback datagram (RTP header, SFrame header, report, tag).
pub const MAX_FEEDBACK_DATAGRAM: usize = 160;
/// Exact length of a feedback report.
pub const FEEDBACK_LEN: usize = 64;
/// The only feedback version defined.
pub const FEEDBACK_VERSION: u8 = 1;
/// Flag bits defined so far: none.
pub const FLAGS_DEFINED: u8 = 0;
/// Minimum spacing of keyframe requests while one is pending.
pub const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_secs(1);

/// Why a report is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Not exactly 64 bytes.
    #[error("video feedback must be exactly 64 bytes")]
    Length,
    /// Unknown version, undefined flags or a non-zero reserved field.
    #[error("malformed video feedback")]
    Malformed,
    /// The report belongs to another track revision.
    #[error("video feedback for another track revision")]
    Revision,
    /// The report is not newer than the last accepted one, or its counters went backwards.
    #[error("stale video feedback")]
    Stale,
    /// A keyframe revision is out of range (never requested, or regressing).
    #[error("keyframe acknowledgement outside the requested revisions")]
    Acknowledgement,
    /// The revision counter would wrap.
    #[error("keyframe revision would wrap")]
    Wrap,
}

/// One decoded feedback report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feedback {
    /// Track revision the counters belong to.
    pub track_revision: u32,
    /// Monotonic report number.
    pub report_seq: u64,
    /// Highest extended PT112 sequence seen (video counter stream).
    pub highest_video_counter: u64,
    /// Packets received, cumulative.
    pub received_packets: u64,
    /// Packets missing (from extended PT112 sequences), cumulative.
    pub missing_packets: u64,
    /// Bytes received, cumulative.
    pub received_bytes: u64,
    /// Relative delay trend in microseconds (signed).
    pub delay_delta_us: i32,
    /// Keyframe revision the sender asks for.
    pub keyframe_request_revision: u32,
    /// Keyframe revision the receiver has applied.
    pub keyframe_ack_revision: u32,
}

impl Feedback {
    /// The 64 bytes of the report.
    #[must_use]
    pub fn encode(&self) -> [u8; FEEDBACK_LEN] {
        let mut out = [0_u8; FEEDBACK_LEN];
        out[0] = FEEDBACK_VERSION;
        out[4..8].copy_from_slice(&self.track_revision.to_be_bytes());
        out[8..16].copy_from_slice(&self.report_seq.to_be_bytes());
        out[16..24].copy_from_slice(&self.highest_video_counter.to_be_bytes());
        out[24..32].copy_from_slice(&self.received_packets.to_be_bytes());
        out[32..40].copy_from_slice(&self.missing_packets.to_be_bytes());
        out[40..48].copy_from_slice(&self.received_bytes.to_be_bytes());
        out[48..52].copy_from_slice(&self.delay_delta_us.to_be_bytes());
        out[52..56].copy_from_slice(&self.keyframe_request_revision.to_be_bytes());
        out[56..60].copy_from_slice(&self.keyframe_ack_revision.to_be_bytes());
        out
    }

    /// Reads a report of exactly 64 bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] unless `bytes` is 64 bytes; [`Error::Malformed`] for
    /// an unknown version, undefined flags or a non-zero reserved field.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FEEDBACK_LEN {
            return Err(Error::Length);
        }
        let flags = bytes[1];
        let reserved_zero = bytes[2] == 0 && bytes[3] == 0 && bytes[60..64] == [0, 0, 0, 0];
        if bytes[0] != FEEDBACK_VERSION || flags & !FLAGS_DEFINED != 0 || !reserved_zero {
            return Err(Error::Malformed);
        }
        Ok(Self {
            track_revision: be_u32(bytes, 4),
            report_seq: be_u64(bytes, 8),
            highest_video_counter: be_u64(bytes, 16),
            received_packets: be_u64(bytes, 24),
            missing_packets: be_u64(bytes, 32),
            received_bytes: be_u64(bytes, 40),
            delay_delta_us: i32::from_be_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]),
            keyframe_request_revision: be_u32(bytes, 52),
            keyframe_ack_revision: be_u32(bytes, 56),
        })
    }
}

fn be_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn be_u64(bytes: &[u8], at: usize) -> u64 {
    let mut out = [0_u8; 8];
    out.copy_from_slice(&bytes[at..at + 8]);
    u64::from_be_bytes(out)
}

/// Accepts reports for one track revision, refusing stale or regressing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedbackState {
    track_revision: u32,
    last: Option<Feedback>,
}

impl FeedbackState {
    /// The state for `track_revision`, with no report yet.
    #[must_use]
    pub fn new(track_revision: u32) -> Self {
        Self { track_revision, last: None }
    }

    /// The last accepted report.
    #[must_use]
    pub fn last(&self) -> Option<&Feedback> {
        self.last.as_ref()
    }

    /// The track revision this state accepts reports for.
    #[must_use]
    pub fn track_revision(&self) -> u32 {
        self.track_revision
    }

    /// Accepts `report` if it belongs to this track revision, is newer than
    /// the last one and does not move any cumulative counter backwards.
    ///
    /// # Errors
    ///
    /// [`Error::Revision`] or [`Error::Stale`].
    pub fn accept(&mut self, report: Feedback) -> Result<(), Error> {
        if report.track_revision != self.track_revision {
            return Err(Error::Revision);
        }
        if let Some(last) = self.last {
            let newer = report.report_seq > last.report_seq;
            let monotonic = report.highest_video_counter >= last.highest_video_counter
                && report.received_packets >= last.received_packets
                && report.missing_packets >= last.missing_packets
                && report.received_bytes >= last.received_bytes;
            if !newer || !monotonic {
                return Err(Error::Stale);
            }
        }
        self.last = Some(report);
        Ok(())
    }
}

/// Keyframe requests: revisions only increase, repeat until acknowledged, and
/// go out at most once per [`KEYFRAME_REQUEST_INTERVAL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyframeRequests {
    requested: u32,
    acknowledged: u32,
    last_sent: Option<Instant>,
}

impl KeyframeRequests {
    /// Asks for a keyframe. Several asks before one send coalesce into one revision bump.
    ///
    /// # Errors
    ///
    /// [`Error::Wrap`] when the revision would wrap.
    pub fn request(&mut self) -> Result<u32, Error> {
        self.requested = self.requested.checked_add(1).ok_or(Error::Wrap)?;
        Ok(self.requested)
    }

    /// Records the peer's acknowledgement. Only a revision that was asked for
    /// and is newer than the last acknowledgement is accepted.
    ///
    /// # Errors
    ///
    /// [`Error::Acknowledgement`] for a revision never requested or a regression.
    pub fn acknowledge(&mut self, revision: u32) -> Result<(), Error> {
        if revision > self.requested || revision < self.acknowledged {
            return Err(Error::Acknowledgement);
        }
        self.acknowledged = revision;
        Ok(())
    }

    /// The revision to send now, if one is pending and due; marks it sent.
    pub fn due(&mut self, now: Instant) -> Option<u32> {
        if self.acknowledged >= self.requested {
            return None;
        }
        let due = self
            .last_sent
            .is_none_or(|sent| now.saturating_duration_since(sent) >= KEYFRAME_REQUEST_INTERVAL);
        if !due {
            return None;
        }
        self.last_sent = Some(now);
        Some(self.requested)
    }

    /// Whether a request is still unacknowledged.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.acknowledged < self.requested
    }
}
