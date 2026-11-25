// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Video send path (V2.2a): access units to a bounded queue, packets sealed
//! under the video send key, relay framing, and a byte and packet pacer.
//!
//! The engine's one socket worker calls [`VideoSender::next_datagram`] after
//! each audio turn, so audio keeps its own send order and timing.
//!
//! Queue policy: at most [`QUEUED_ACCESS_UNITS`] access units wait. When a
//! new one finds the queue full, the queue is flushed, and the stream waits
//! for a keyframe: non-IDR units are dropped until an IDR unit arrives. The
//! peer then never sees a unit whose reference was dropped by this side.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::feedback::{FEEDBACK_PAYLOAD_TYPE, Feedback};
use super::packet::{AccessUnit, METADATA_LEN, Packetizer, validate_avcc};
use crate::pipeline::{PipelineError, video_kid_ok};
use crate::relay;
use crate::rtp::RtpHeader;
use crate::session::MediaSession;
use crate::sframe;

/// Access units that may wait to be sent.
pub const QUEUED_ACCESS_UNITS: usize = 2;
/// Pacer rate: video bytes per second on the wire (relay framing included).
pub const BYTES_PER_SECOND: u64 = 240_000;
/// Pacer burst: bytes sent back to back. The engine refills about every 20 ms, so a burst
/// below one keyframe's worth (12 kB) caps throughput near 120 kB/s and the send queue
/// overflows (found in the real run: flushed partial units, loss reports, rate collapse).
pub const BURST_BYTES: u64 = 12_000;
/// Pacer cap: video packets per one-second window.
pub const PACKETS_PER_SECOND: u32 = 340;
/// Datagrams one engine turn may send, so audio never waits long behind video.
pub const MAX_DATAGRAMS_PER_TURN: usize = 8;

/// Micro-bytes per byte: the pacer counts credit exactly, without rounding.
const MICRO: u64 = 1_000_000;

/// What one submission did to the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Submitted {
    /// The access unit was queued.
    pub queued: bool,
    /// Access units dropped by this submission (flushed or refused).
    pub dropped: usize,
}

/// Byte and packet budget of the video track. Credit is kept in micro-bytes
/// so refills stay exact; the packet cap is a fixed one-second window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pacer {
    credit: u64,
    last: Option<Instant>,
    window_start: Option<Instant>,
    window_packets: u32,
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new()
    }
}

impl Pacer {
    /// A full bucket (one burst available at start).
    #[must_use]
    pub fn new() -> Self {
        Self { credit: BURST_BYTES * MICRO, last: None, window_start: None, window_packets: 0 }
    }

    fn refill(&mut self, now: Instant) {
        if let Some(last) = self.last {
            let micros =
                u64::try_from(now.saturating_duration_since(last).as_micros()).unwrap_or(u64::MAX);
            let earned = micros.saturating_mul(BYTES_PER_SECOND);
            self.credit = self.credit.saturating_add(earned).min(BURST_BYTES * MICRO);
        }
        self.last = Some(now);
        let window_open = self
            .window_start
            .is_some_and(|start| now.saturating_duration_since(start) < Duration::from_secs(1));
        if !window_open {
            self.window_start = Some(now);
            self.window_packets = 0;
        }
    }

    /// Whether a datagram of at most `bytes` may leave at `now`.
    pub fn allows(&mut self, now: Instant, bytes: usize) -> bool {
        self.refill(now);
        let cost = u64::try_from(bytes).unwrap_or(u64::MAX).saturating_mul(MICRO);
        self.window_packets < PACKETS_PER_SECOND && self.credit >= cost
    }

    /// Records a datagram of `bytes` that left (after [`Self::allows`]).
    pub fn charge(&mut self, bytes: usize) {
        let cost = u64::try_from(bytes).unwrap_or(u64::MAX).saturating_mul(MICRO);
        self.credit = self.credit.saturating_sub(cost);
        self.window_packets = self.window_packets.saturating_add(1);
    }
}

/// One plaintext packet: its authenticated metadata and its fragment.
#[derive(Debug)]
struct Pending {
    metadata: Vec<u8>,
    body: Vec<u8>,
}

/// One queued access unit: its packets not yet sent, and when it was queued.
#[derive(Debug)]
struct Queued {
    packets: VecDeque<Pending>,
    at: Instant,
}

/// The sending half of the video track: one video send key, one counter stream.
#[derive(Debug)]
pub struct VideoSender {
    packetizer: Packetizer,
    sframe: sframe::Sender,
    token: Zeroizing<Vec<u8>>,
    /// Worst-case bytes `SFrame` adds to a payload: header and AEAD tag.
    sframe_overhead: usize,
    queue: VecDeque<Queued>,
    idr_needed: bool,
    pacer: Pacer,
    ssrc: u32,
    feedback_sequence: u16,
    /// The newest report waiting to be sent (a newer one replaces it).
    feedback: Option<Pending>,
}

impl VideoSender {
    /// The video sender of `session`, taking its video send key once.
    /// `None` when the session negotiated no video.
    ///
    /// # Errors
    ///
    /// An unknown suite, an empty or out-of-range video KID.
    pub fn new(
        session: &mut MediaSession,
        ssrc: u32,
        sequence: u16,
    ) -> Result<Option<Self>, PipelineError> {
        let suite = sframe::suite(session.suite())?;
        let Some(key) = session.take_video_send_key() else {
            return Ok(None);
        };
        if !video_kid_ok(key.kid()) {
            return Err(PipelineError::KidMismatch);
        }
        Ok(Some(Self {
            packetizer: Packetizer::new(ssrc, sequence),
            sframe: sframe::Sender::new(suite, key.kid(), key.base_key().bytes())?,
            token: Zeroizing::new(session.token().to_vec()),
            sframe_overhead: suite.overhead() + sframe::MAX_HEADER_LEN,
            queue: VecDeque::with_capacity(QUEUED_ACCESS_UNITS),
            idr_needed: false,
            pacer: Pacer::new(),
            ssrc,
            feedback_sequence: 0,
            feedback: None,
        }))
    }

    /// Queues one access unit at `now`, applying the queue policy.
    ///
    /// # Errors
    ///
    /// [`PipelineError::Video`] for a malformed access unit (nothing queued).
    pub fn submit(&mut self, au: &AccessUnit, now: Instant) -> Result<Submitted, PipelineError> {
        validate_avcc(&au.data)?;
        if self.idr_needed && !au.idr {
            return Ok(Submitted { queued: false, dropped: 1 });
        }
        let mut dropped = 0;
        if self.queue.len() >= QUEUED_ACCESS_UNITS {
            dropped = self.queue.len();
            self.queue.clear();
            self.idr_needed = true;
            if !au.idr {
                return Ok(Submitted { queued: false, dropped: dropped + 1 });
            }
        }
        let packets = self.packetizer.packetize(au)?;
        self.idr_needed = false;
        let packets = packets.iter().filter_map(|packet| split_packet(packet)).collect();
        self.queue.push_back(Queued { packets, at: now });
        Ok(Submitted { queued: true, dropped })
    }

    /// Drops everything queued and waits for a keyframe (video off, fence).
    pub fn flush(&mut self) {
        self.queue.clear();
        self.feedback = None;
        self.idr_needed = true;
    }

    /// Queues a feedback report (PT113) to send ahead of video. It replaces
    /// a report not yet sent: reports are cumulative, the newest one wins.
    pub fn queue_feedback(&mut self, report: &Feedback) {
        let rtp = RtpHeader {
            marker: false,
            payload_type: FEEDBACK_PAYLOAD_TYPE,
            sequence: self.feedback_sequence,
            timestamp: 0,
            ssrc: self.ssrc,
        };
        self.feedback_sequence = self.feedback_sequence.wrapping_add(1);
        self.feedback =
            Some(Pending { metadata: rtp.encode().to_vec(), body: report.encode().to_vec() });
    }

    /// Whether the stream waits for a keyframe before it sends again.
    #[must_use]
    pub fn idr_needed(&self) -> bool {
        self.idr_needed
    }

    /// Milliseconds the oldest queued access unit has waited (0 when empty).
    #[must_use]
    pub fn queue_age_ms(&self, now: Instant) -> u32 {
        self.queue.front().map_or(0, |au| {
            u32::try_from(now.saturating_duration_since(au.at).as_millis()).unwrap_or(u32::MAX)
        })
    }

    /// The next datagram, if one is waiting and the pacer allows it now.
    ///
    /// # Errors
    ///
    /// [`PipelineError::Sframe`] when the sending counter is exhausted; the
    /// session must then start a fresh call.
    pub fn next_datagram(&mut self, now: Instant) -> Result<Option<Vec<u8>>, PipelineError> {
        let Some(bound) = self.next_bound() else {
            return Ok(None);
        };
        if !self.pacer.allows(now, bound) {
            return Ok(None);
        }
        let Some(packet) = self.pop_front_packet() else {
            return Ok(None);
        };
        let protected = self.sframe.encrypt(&packet.metadata, &packet.body)?;
        let mut wire = packet.metadata;
        wire.extend_from_slice(&protected);
        let datagram = relay::frame(&self.token, &wire);
        self.pacer.charge(datagram.len());
        Ok(Some(datagram))
    }

    /// Worst-case datagram size of the next packet, before sealing.
    fn next_bound(&mut self) -> Option<usize> {
        let relay_overhead =
            if self.token.is_empty() { 0 } else { relay::LENGTH_PREFIX + self.token.len() };
        let overhead = relay_overhead + self.sframe_overhead;
        if let Some(report) = self.feedback.as_ref() {
            return Some(overhead + report.metadata.len() + report.body.len());
        }
        self.front_packet().map(|packet| overhead + packet.metadata.len() + packet.body.len())
    }

    /// The first packet of the oldest unsent access unit; empty units are
    /// removed on the way.
    fn front_packet(&mut self) -> Option<&Pending> {
        while self.queue.front().is_some_and(|au| au.packets.is_empty()) {
            self.queue.pop_front();
        }
        self.queue.front().and_then(|au| au.packets.front())
    }

    fn pop_front_packet(&mut self) -> Option<Pending> {
        if let Some(report) = self.feedback.take() {
            return Some(report);
        }
        self.front_packet()?;
        self.queue.front_mut()?.packets.pop_front()
    }
}

/// Splits `rtp || video header || fragment` into its authenticated metadata
/// and its fragment.
fn split_packet(packet: &[u8]) -> Option<Pending> {
    let (metadata, body) = packet.split_at_checked(METADATA_LEN)?;
    Some(Pending { metadata: metadata.to_vec(), body: body.to_vec() })
}
