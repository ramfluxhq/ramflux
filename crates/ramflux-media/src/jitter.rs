// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An adaptive jitter buffer for 20 ms audio packets.
//!
//! Packets are pushed as they arrive (any order) and played out one per
//! frame. The buffer holds back a target delay that follows the measured
//! interarrival jitter (RFC 3550 §6.4.1 / A.8): about three times the
//! jitter plus one frame, between [`MIN_TARGET`] and [`MAX_TARGET`]
//! frames. Playout:
//!
//! - waits until the target is buffered (at the start, and again after the
//!   stream stalled);
//! - plays the next packet in sequence; a missing one is reported lost,
//!   with the packet after it when that one is here (Opus FEC rebuilds the
//!   lost frame from it), otherwise for concealment;
//! - drops a packet that arrives after its turn (late), or twice
//!   (duplicate);
//! - when it holds more than the target needs, skips one frame to bring
//!   the delay back down.
//!
//! Pure and clock-free: arrival times are passed in, so it is tested
//! deterministically.

use std::collections::BTreeMap;

use crate::codec::{FRAME_MS, FRAME_SAMPLES};

/// Least frames held back.
pub const MIN_TARGET: usize = 2;
/// Most frames held back (200 ms).
pub const MAX_TARGET: usize = 10;
/// Most packets kept (one second); older ones are dropped.
pub const CAPACITY: usize = 50;
/// Lost frames in a row after which playout waits to rebuffer.
pub const STALL_FRAMES: u32 = 5;

/// What a push did with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    /// Kept for playout.
    Accepted,
    /// Its turn has passed.
    Late,
    /// Already held or played.
    Duplicate,
}

/// What to play for the next frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Playout {
    /// Nothing yet (buffering): play silence.
    Wait,
    /// The next packet.
    Packet(Vec<u8>),
    /// The next packet is lost; `next` is the one after it, if here (for
    /// forward error correction).
    Lost {
        /// The following packet.
        next: Option<Vec<u8>>,
    },
}

/// Counters of one buffer.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct JitterStats {
    /// Packets accepted.
    pub received: u64,
    /// Packets that arrived after their turn.
    pub late: u64,
    /// Packets received twice.
    pub duplicates: u64,
    /// Frames played as lost (rebuilt or concealed).
    pub lost: u64,
    /// Frames skipped to bring the delay down.
    pub skipped: u64,
    /// Interarrival jitter estimate, in milliseconds.
    pub jitter_ms: f64,
    /// Current target delay, in milliseconds.
    pub target_ms: u64,
}

/// The jitter buffer of one incoming stream.
#[derive(Debug)]
pub struct JitterBuffer {
    packets: BTreeMap<u64, Vec<u8>>,
    highest: Option<u64>,
    next: Option<u64>,
    playing: bool,
    lost_in_row: u32,
    /// Jitter in 48 kHz samples (RFC 3550 A.8).
    jitter: f64,
    last_transit: Option<i64>,
    target: usize,
    stats: JitterStats,
}

impl Default for JitterBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl JitterBuffer {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            packets: BTreeMap::new(),
            highest: None,
            next: None,
            playing: false,
            lost_in_row: 0,
            jitter: 0.0,
            last_transit: None,
            target: MIN_TARGET,
            stats: JitterStats {
                target_ms: MIN_TARGET as u64 * FRAME_MS,
                ..JitterStats::default()
            },
        }
    }

    /// Counters so far.
    #[must_use]
    pub fn stats(&self) -> JitterStats {
        self.stats
    }

    /// Frames currently held back.
    #[must_use]
    pub fn target_frames(&self) -> usize {
        self.target
    }

    /// Packets held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether no packet is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// The extended (wrap-free) sequence number of `sequence`, relative to
    /// the highest seen so far.
    fn extend(&self, sequence: u16) -> u64 {
        match self.highest {
            // Start high, so packets from before the first one still fit.
            None => (1 << 32) + u64::from(sequence),
            Some(high) => {
                // `high` is an extended sequence. Only its low 16 bits are the RTP number.
                let low = u16::try_from(high & u64::from(u16::MAX)).unwrap_or(0);
                let delta = i64::from(sequence.wrapping_sub(low).cast_signed());
                high.saturating_add_signed(delta)
            }
        }
    }

    /// Adds a packet with its RTP `sequence` and `timestamp`, arrived at
    /// `arrival_ms` (any monotonic clock, in milliseconds).
    pub fn push(
        &mut self,
        sequence: u16,
        timestamp: u32,
        payload: Vec<u8>,
        arrival_ms: u64,
    ) -> Pushed {
        let ext = self.extend(sequence);
        if self.next.is_some_and(|next| ext < next) {
            self.stats.late += 1;
            return Pushed::Late;
        }
        if self.packets.contains_key(&ext) {
            self.stats.duplicates += 1;
            return Pushed::Duplicate;
        }
        self.track_jitter(timestamp, arrival_ms);
        self.packets.insert(ext, payload);
        self.highest = Some(self.highest.map_or(ext, |high| high.max(ext)));
        while self.packets.len() > CAPACITY {
            self.packets.pop_first();
        }
        self.stats.received += 1;
        Pushed::Accepted
    }

    fn track_jitter(&mut self, timestamp: u32, arrival_ms: u64) {
        let rate = (FRAME_SAMPLES as u64) / FRAME_MS;
        let arrival = i64::try_from(arrival_ms.saturating_mul(rate)).unwrap_or(i64::MAX);
        let transit = arrival.wrapping_sub(i64::from(timestamp));
        if let Some(last) = self.last_transit {
            #[allow(
                clippy::cast_precision_loss,
                reason = "RFC 3550 A.8 keeps the interarrival delta in f64; a call's deltas fit the mantissa"
            )]
            let d = transit.wrapping_sub(last).unsigned_abs() as f64;
            self.jitter += (d - self.jitter) / 16.0;
        }
        self.last_transit = Some(transit);
        #[allow(
            clippy::cast_precision_loss,
            reason = "the RTP clock is 48 kHz, inside the f64 mantissa"
        )]
        let jitter_ms = self.jitter / rate as f64;
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            reason = "the frame count is clamped to the buffer target on the next line"
        )]
        let wanted = 1 + (3.0 * jitter_ms / FRAME_MS as f64).ceil() as usize;
        self.target = wanted.clamp(MIN_TARGET, MAX_TARGET);
        self.stats.jitter_ms = jitter_ms;
        self.stats.target_ms = self.target as u64 * FRAME_MS;
    }

    /// What to play for the next 20 ms frame.
    pub fn pop(&mut self) -> Playout {
        if !self.playing {
            if self.packets.len() < self.target {
                return Playout::Wait;
            }
            self.playing = true;
            self.lost_in_row = 0;
            self.next = self.packets.keys().next().copied();
        }
        let Some(mut next) = self.next else { return Playout::Wait };
        // Too far behind: skip one frame to bring the delay down.
        if self.packets.len() > self.target + 2 {
            self.packets.remove(&next);
            next += 1;
            self.stats.skipped += 1;
        }
        // Drop what is older than the next turn (skipped frames).
        while self.packets.first_key_value().is_some_and(|(seq, _)| *seq < next) {
            self.packets.pop_first();
        }
        if let Some(packet) = self.packets.remove(&next) {
            self.next = Some(next + 1);
            self.lost_in_row = 0;
            return Playout::Packet(packet);
        }
        self.lost_in_row += 1;
        if self.packets.is_empty() && self.lost_in_row > STALL_FRAMES {
            // The stream stalled: wait for the target again.
            self.playing = false;
            self.next = None;
            return Playout::Wait;
        }
        self.stats.lost += 1;
        self.next = Some(next + 1);
        Playout::Lost { next: self.packets.get(&(next + 1)).cloned() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(n: u16) -> Vec<u8> {
        n.to_be_bytes().to_vec()
    }

    fn feed(buffer: &mut JitterBuffer, seqs: &[u16]) {
        for &s in seqs {
            buffer.push(s, u32::from(s) * 960, packet(s), u64::from(s) * 20);
        }
    }

    #[test]
    fn waits_for_the_target_then_plays_in_order() {
        let mut buffer = JitterBuffer::new();
        feed(&mut buffer, &[10]);
        assert_eq!(buffer.pop(), Playout::Wait);
        feed(&mut buffer, &[12, 11]);
        assert_eq!(buffer.pop(), Playout::Packet(packet(10)));
        assert_eq!(buffer.pop(), Playout::Packet(packet(11)));
        assert_eq!(buffer.pop(), Playout::Packet(packet(12)));
    }

    #[test]
    fn a_gap_is_lost_with_the_next_packet_for_fec() {
        let mut buffer = JitterBuffer::new();
        feed(&mut buffer, &[1, 2, 4, 5]);
        assert_eq!(buffer.pop(), Playout::Packet(packet(1)));
        assert_eq!(buffer.pop(), Playout::Packet(packet(2)));
        assert_eq!(buffer.pop(), Playout::Lost { next: Some(packet(4)) });
        assert_eq!(buffer.pop(), Playout::Packet(packet(4)));
        // 3 arriving now is late; 5 again is a duplicate of a held one.
        assert_eq!(buffer.push(3, 3 * 960, packet(3), 200), Pushed::Late);
        assert_eq!(buffer.push(5, 5 * 960, packet(5), 200), Pushed::Duplicate);
        assert_eq!(buffer.stats().lost, 1);
        assert_eq!(buffer.stats().late, 1);
    }

    #[test]
    fn sequence_numbers_wrap() {
        let mut buffer = JitterBuffer::new();
        feed(&mut buffer, &[65534, 65535, 0, 1]);
        let played: Vec<Playout> = (0..4).map(|_| buffer.pop()).collect();
        assert_eq!(played, [65534, 65535, 0, 1].map(|s| Playout::Packet(packet(s))).to_vec());
    }

    #[test]
    fn a_stall_rebuffers() {
        let mut buffer = JitterBuffer::new();
        feed(&mut buffer, &[1, 2]);
        buffer.pop();
        buffer.pop();
        for _ in 0..STALL_FRAMES {
            assert_eq!(buffer.pop(), Playout::Lost { next: None });
        }
        assert_eq!(buffer.pop(), Playout::Wait);
        feed(&mut buffer, &[40]);
        assert_eq!(buffer.pop(), Playout::Wait);
        feed(&mut buffer, &[41]);
        assert_eq!(buffer.pop(), Playout::Packet(packet(40)));
    }

    #[test]
    fn jitter_raises_the_target_and_excess_is_skipped() {
        let mut buffer = JitterBuffer::new();
        // Packets every 20 ms of media but arriving in bursts of 100 ms.
        for s in 0_u16..40 {
            let arrival = u64::from(s / 5) * 100 + 100;
            buffer.push(s, u32::from(s) * 960, packet(s), arrival);
        }
        assert!(buffer.target_frames() > MIN_TARGET, "{:?}", buffer.stats());
        assert!(buffer.target_frames() <= MAX_TARGET);
        let mut skipped_to_target = false;
        for _ in 0..40 {
            buffer.pop();
            if buffer.len() <= buffer.target_frames() + 2 {
                skipped_to_target = true;
                break;
            }
        }
        assert!(skipped_to_target);
        assert!(buffer.stats().skipped > 0);
    }
}
