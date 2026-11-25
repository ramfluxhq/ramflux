// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Video control state (V2.2a): the receiving side counts the peer's video
//! and reports it back on PT113; the sending side accepts reports about its
//! own track and learns from them. Pure logic: the engine feeds it fragments,
//! accepted reports and clock readings, and sends what it returns.
//!
//! Keyframes: this side asks for an IDR with `keyframe_request_revision`
//! (repeated until the peer acknowledges, at most once per second) and
//! acknowledges the peer's requests with `keyframe_ack_revision`, which only
//! the host sets after it has produced the IDR ([`VideoControl::apply_keyframe`]).

use std::time::{Duration, Instant};

use super::feedback::{Error as FeedbackError, Feedback, FeedbackState, KeyframeRequests};
use super::packet::FragmentHeader;

/// Spacing of reports while video flows (or a keyframe request is pending).
pub const REPORT_INTERVAL: Duration = Duration::from_millis(200);

/// Counters of the peer's video as this side receives it.
#[derive(Debug, Default)]
struct Inbound {
    revision: Option<u32>,
    origin: Option<Instant>,
    highest: Option<u64>,
    received_packets: u64,
    missing_packets: u64,
    received_bytes: u64,
    delay_base_us: Option<i64>,
    delay_delta_us: i32,
}

impl Inbound {
    /// Counts one authenticated fragment. A new track revision restarts the counters.
    fn observe(&mut self, header: &FragmentHeader, extended: Option<u64>, bytes: usize, now: Instant) {
        if self.revision != Some(header.track_revision) {
            *self = Self { revision: Some(header.track_revision), ..Self::default() };
        }
        let origin = *self.origin.get_or_insert(now);
        self.received_packets = self.received_packets.saturating_add(1);
        self.received_bytes = self.received_bytes.saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        if let Some(sequence) = extended {
            self.observe_sequence(sequence);
        }
        let arrival = i64::try_from(now.saturating_duration_since(origin).as_micros()).unwrap_or(i64::MAX);
        let transit = arrival.saturating_sub(i64::try_from(header.pts_us).unwrap_or(i64::MAX));
        let base = *self.delay_base_us.get_or_insert(transit);
        let delta = transit.saturating_sub(base).clamp(i64::from(i32::MIN), i64::from(i32::MAX));
        self.delay_delta_us = i32::try_from(delta).unwrap_or(0);
    }

    /// Missing packets are the gaps in the extended sequence; a late packet
    /// fills one gap.
    fn observe_sequence(&mut self, sequence: u64) {
        match self.highest {
            None => self.highest = Some(sequence),
            Some(high) if sequence > high => {
                self.missing_packets = self.missing_packets.saturating_add(sequence - high - 1);
                self.highest = Some(sequence);
            }
            Some(_) => self.missing_packets = self.missing_packets.saturating_sub(1),
        }
    }
}

/// The video control state of one call.
#[derive(Debug)]
pub struct VideoControl {
    inbound: Inbound,
    report_seq: u64,
    last_report: Option<Instant>,
    outbound: FeedbackState,
    requests: KeyframeRequests,
    requested_on_wire: u32,
    peer_request: u32,
    applied: u32,
}

impl Default for VideoControl {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoControl {
    /// A fresh control state (no reports, no requests).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inbound: Inbound::default(),
            report_seq: 0,
            last_report: None,
            outbound: FeedbackState::new(0),
            requests: KeyframeRequests::default(),
            requested_on_wire: 0,
            peer_request: 0,
            applied: 0,
        }
    }

    /// Counts one authenticated incoming fragment.
    pub fn on_fragment(
        &mut self,
        header: &FragmentHeader,
        extended: Option<u64>,
        bytes: usize,
        now: Instant,
    ) {
        self.inbound.observe(header, extended, bytes, now);
    }

    /// Follows the track revision of this side's outgoing video: reports for
    /// another revision are refused from now on.
    pub fn note_outbound_revision(&mut self, revision: u32) {
        if self.outbound.track_revision() != revision {
            self.outbound = FeedbackState::new(revision);
        }
    }

    /// Accepts a report about this side's outgoing video. A stale or foreign
    /// report is refused and changes nothing. A feedback grants no authority:
    /// it only records the peer's acknowledgement and keyframe request.
    ///
    /// # Errors
    ///
    /// The refusal of [`FeedbackState::accept`].
    pub fn on_feedback(&mut self, report: Feedback) -> Result<(), FeedbackError> {
        self.outbound.accept(report)?;
        // A revision never requested (or regressing) is ignored; the report
        // itself was accepted.
        let _ = self.requests.acknowledge(report.keyframe_ack_revision);
        self.peer_request = self.peer_request.max(report.keyframe_request_revision);
        Ok(())
    }

    /// Asks the peer for a keyframe; several asks coalesce into one revision.
    ///
    /// # Errors
    ///
    /// [`FeedbackError::Wrap`] when the revision would wrap.
    pub fn request_keyframe(&mut self) -> Result<u32, FeedbackError> {
        self.requests.request()
    }

    /// Records that the host produced the keyframe for the peer's request
    /// `revision` (never beyond what the peer asked for).
    pub fn apply_keyframe(&mut self, revision: u32) {
        self.applied = self.applied.max(revision.min(self.peer_request));
    }

    /// The highest keyframe revision the peer asked of this side's outgoing video.
    #[must_use]
    pub fn peer_request(&self) -> u32 {
        self.peer_request
    }

    /// The report to send now, if one is due at `now`.
    pub fn report_due(&mut self, now: Instant) -> Option<Feedback> {
        if self.inbound.revision.is_none() && !self.requests.pending() {
            return None;
        }
        let due = self
            .last_report
            .is_none_or(|at| now.saturating_duration_since(at) >= REPORT_INTERVAL);
        if !due {
            return None;
        }
        if let Some(revision) = self.requests.due(now) {
            self.requested_on_wire = revision;
        }
        self.last_report = Some(now);
        self.report_seq = self.report_seq.saturating_add(1);
        let inbound = &self.inbound;
        Some(Feedback {
            track_revision: inbound.revision.unwrap_or(0),
            report_seq: self.report_seq,
            highest_video_counter: inbound.highest.unwrap_or(0),
            received_packets: inbound.received_packets,
            missing_packets: inbound.missing_packets,
            received_bytes: inbound.received_bytes,
            delay_delta_us: inbound.delay_delta_us,
            keyframe_request_revision: self.requested_on_wire,
            keyframe_ack_revision: self.applied,
        })
    }
}
