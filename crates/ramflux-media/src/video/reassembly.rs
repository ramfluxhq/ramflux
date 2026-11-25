// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded reassembly of video access units (V2.1).
//!
//! Callers pass only fragments that are already authenticated. Storage is
//! fixed: at most [`MAX_INCOMPLETE`] access units in progress (each sized by its
//! authenticated length, at most 48,000 bytes), and at most [`MAX_READY`]
//! complete units or [`MAX_READY_BYTES`] waiting for the host. Only complete
//! units are delivered, in presentation-time order. An incomplete unit expires
//! [`EXPIRY`] after its first fragment; the caller then requests an IDR.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::packet::{AccessUnit, FragmentHeader, MAX_AU_BYTES, MAX_FRAGMENTS};

/// Access units in progress at once.
pub const MAX_INCOMPLETE: usize = 4;
/// Incomplete access units expire this long after their first fragment.
pub const EXPIRY: Duration = Duration::from_millis(200);
/// Complete access units waiting for the host.
pub const MAX_READY: usize = 2;
/// Bytes of complete access units waiting for the host.
pub const MAX_READY_BYTES: usize = 96_000;

/// Why a fragment is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The fragment lies outside its access unit or its size bounds.
    #[error("video fragment outside its access unit")]
    OutOfBounds,
    /// The fragment overlaps or repeats an index already received.
    #[error("video fragment overlaps or duplicates an earlier one")]
    Overlap,
    /// The fragment's metadata disagrees with the access unit in progress.
    #[error("video fragment metadata disagrees with its access unit")]
    Inconsistent,
    /// The access unit was already delivered, or is already waiting.
    #[error("video access unit is stale or duplicated")]
    Stale,
}

/// What a fragment did to its access unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// Stored; the access unit still needs fragments.
    Pending,
    /// The last fragment arrived; the unit is ready for delivery.
    Complete,
}

struct Slot {
    header: FragmentHeader,
    first_seen: Instant,
    data: Vec<u8>,
    /// `(fragment_index, offset, length)` of each fragment received.
    ranges: Vec<(u16, usize, usize)>,
}

/// The reassembly state of one receive track.
#[derive(Default)]
pub struct Reassembler {
    incomplete: Vec<Slot>,
    ready: VecDeque<AccessUnit>,
    ready_bytes: usize,
    last_delivered_pts: Option<u64>,
    dropped: u64,
}

impl std::fmt::Debug for Reassembler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reassembler")
            .field("incomplete", &self.incomplete.len())
            .field("ready", &self.ready.len())
            .field("dropped", &self.dropped)
            .finish_non_exhaustive()
    }
}

fn same_unit(a: &FragmentHeader, b: &FragmentHeader) -> bool {
    a.idr == b.idr
        && a.config == b.config
        && a.rotation == b.rotation
        && a.track_revision == b.track_revision
        && a.frame_id == b.frame_id
        && a.pts_us == b.pts_us
        && a.au_len == b.au_len
        && a.config_revision == b.config_revision
        && a.fragment_count == b.fragment_count
}

impl Reassembler {
    /// Empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Units dropped so far (evicted, expired, stale or over the ready bound).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Stores one authenticated fragment whose payload is `payload`.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfBounds`], [`Error::Overlap`], [`Error::Inconsistent`] or
    /// [`Error::Stale`]; the state is unchanged except for the eviction of the
    /// oldest unit when a fifth one would start.
    pub fn push(
        &mut self,
        header: &FragmentHeader,
        payload: &[u8],
        now: Instant,
    ) -> Result<Progress, Error> {
        let offset = usize::try_from(header.offset).map_err(|_| Error::OutOfBounds)?;
        let end = offset.checked_add(payload.len()).ok_or(Error::OutOfBounds)?;
        let au_len = usize::try_from(header.au_len).map_err(|_| Error::OutOfBounds)?;
        if payload.is_empty()
            || end > au_len
            || au_len > MAX_AU_BYTES
            || usize::from(header.fragment_count) > MAX_FRAGMENTS
        {
            return Err(Error::OutOfBounds);
        }
        let position =
            match self.incomplete.iter().position(|s| s.header.frame_id == header.frame_id) {
                Some(position) => position,
                None => self.start_slot(header, au_len, now)?,
            };
        let slot = self.incomplete.get_mut(position).ok_or(Error::Inconsistent)?;
        if !same_unit(&slot.header, header) {
            return Err(Error::Inconsistent);
        }
        let collides = slot.ranges.iter().any(|&(index, start, len)| {
            index == header.fragment_index || (start < end && offset < start + len)
        });
        if collides {
            return Err(Error::Overlap);
        }
        let target = slot.data.get_mut(offset..end).ok_or(Error::OutOfBounds)?;
        target.copy_from_slice(payload);
        slot.ranges.push((header.fragment_index, offset, payload.len()));
        if slot.ranges.len() < usize::from(header.fragment_count) {
            return Ok(Progress::Pending);
        }
        let slot = self.incomplete.remove(position);
        let covered: usize = slot.ranges.iter().map(|range| range.2).sum();
        if covered != au_len {
            self.dropped += 1;
            return Err(Error::Inconsistent);
        }
        self.enqueue(AccessUnit {
            frame_id: slot.header.frame_id,
            pts_us: slot.header.pts_us,
            idr: slot.header.idr,
            config: slot.header.config,
            rotation: slot.header.rotation,
            track_revision: slot.header.track_revision,
            config_revision: slot.header.config_revision,
            data: slot.data,
        });
        Ok(Progress::Complete)
    }

    /// Opens a slot for a new access unit, evicting the oldest one when full.
    fn start_slot(
        &mut self,
        header: &FragmentHeader,
        au_len: usize,
        now: Instant,
    ) -> Result<usize, Error> {
        if self.last_delivered_pts.is_some_and(|last| header.pts_us <= last)
            || self.ready.iter().any(|unit| unit.frame_id == header.frame_id)
        {
            return Err(Error::Stale);
        }
        if self.incomplete.len() >= MAX_INCOMPLETE {
            let oldest = self
                .incomplete
                .iter()
                .enumerate()
                .min_by_key(|(_, slot)| slot.first_seen)
                .map(|(index, _)| index);
            if let Some(index) = oldest {
                self.incomplete.remove(index);
                self.dropped += 1;
            }
        }
        self.incomplete.push(Slot {
            header: *header,
            first_seen: now,
            data: vec![0_u8; au_len],
            ranges: Vec::with_capacity(usize::from(header.fragment_count)),
        });
        Ok(self.incomplete.len() - 1)
    }

    /// Queues a complete unit in presentation-time order; under pressure the
    /// oldest waiting unit goes (latest frame wins).
    fn enqueue(&mut self, unit: AccessUnit) {
        self.ready_bytes += unit.data.len();
        let at = self.ready.iter().position(|queued| queued.pts_us > unit.pts_us);
        let at = at.unwrap_or(self.ready.len());
        self.ready.insert(at, unit);
        while (self.ready.len() > MAX_READY || self.ready_bytes > MAX_READY_BYTES)
            && let Some(old) = self.ready.pop_front()
        {
            self.ready_bytes -= old.data.len();
            self.dropped += 1;
        }
    }

    /// Expires incomplete units older than [`EXPIRY`]; returns how many went.
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.incomplete.len();
        self.incomplete.retain(|slot| now.saturating_duration_since(slot.first_seen) < EXPIRY);
        let removed = before - self.incomplete.len();
        self.dropped += u64::try_from(removed).unwrap_or(0);
        removed
    }

    /// The next complete unit in presentation-time order, after expiry.
    pub fn pop_ready(&mut self, now: Instant) -> Option<AccessUnit> {
        self.expire(now);
        let unit = self.ready.pop_front()?;
        self.ready_bytes -= unit.data.len();
        self.last_delivered_pts = Some(unit.pts_us);
        Some(unit)
    }
}
