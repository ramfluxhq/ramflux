// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant reorder admission: durable W0 first, then RAM refs, one gap timer, coalesced catch-up.
use std::collections::BTreeMap;

/// Inclusive RAM reference cap (§7).
pub(crate) const MAX_REFS: usize = 256;
/// Inclusive RAM reference byte cap (§7).
pub(crate) const MAX_REF_BYTES: usize = 8 * 1024 * 1024;
/// Gap wait before one Resume (§7).
pub(crate) const GAP_WAIT_MS: u64 = 500;
/// Catch-up page size and per-turn contiguous bound (§7, P05 L2).
pub(crate) const PAGE_LIMIT: u32 = 64;
/// Catch-up pages before the scheduler yields (§7, P05 L2).
pub(crate) const YIELD_AFTER_PAGES: u32 = 16;

/// Catch-up / Resync / Lagged / retry / Connected / sweep share one in-flight slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatchUpHint {
    GapTimer,
    Resync,
    Lagged,
    Retry,
    Connected,
    SafetySweep,
}

/// Result of admitting one push into the reorder buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub(crate) enum AdmitOutcome {
    ReadyToApply { seq: u64 },
    Buffered { seq: u64, dropped: Option<u64> },
    Duplicate { seq: u64 },
    Refused { seq: u64 },
}

/// Scheduler step. Tests drive this with a virtual clock; never the wall clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub(crate) enum Tick {
    Idle,
    CatchUp { after: u64, page_limit: u32 },
}

/// Protocol fault while advancing coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReorderError {
    Protocol(&'static str),
}

#[derive(Default)]
struct CatchUp {
    in_flight: bool,
    follow_up: bool,
    pending: bool,
    pages: u32,
}

impl CatchUp {
    fn request(&mut self) {
        if self.in_flight {
            self.follow_up = true;
        } else {
            self.pending = true;
        }
    }

    fn start(&mut self) {
        self.in_flight = true;
        self.pending = false;
        self.pages = 0;
    }

    fn finish(&mut self) {
        self.in_flight = false;
        self.pages = 0;
        if self.follow_up {
            self.follow_up = false;
            self.pending = true;
        }
    }
}

/// RAM reorder refs after durable W0. Payload never lives only in this map.
pub(crate) struct ReorderBuffer {
    cursor: u64,
    refs: BTreeMap<u64, usize>,
    bytes: usize,
    gap_started_at: Option<u64>,
    catch_up: CatchUp,
    local_work: bool,
    overflow_acks: u64,
}

impl ReorderBuffer {
    #[must_use]
    pub(crate) fn new(cursor: u64) -> Self {
        Self {
            cursor,
            refs: BTreeMap::new(),
            bytes: 0,
            gap_started_at: None,
            catch_up: CatchUp::default(),
            local_work: false,
            overflow_acks: 0,
        }
    }

    #[must_use]
    pub(crate) fn cursor(&self) -> u64 {
        self.cursor
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.refs.len()
    }

    #[must_use]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    #[must_use]
    pub(crate) fn overflow_acks(&self) -> u64 {
        self.overflow_acks
    }

    #[must_use]
    pub(crate) fn in_flight(&self) -> bool {
        self.catch_up.in_flight
    }

    #[must_use]
    pub(crate) fn follow_up(&self) -> bool {
        self.catch_up.follow_up
    }

    #[must_use]
    pub(crate) fn contains(&self, seq: u64) -> bool {
        self.refs.contains_key(&seq)
    }

    #[must_use]
    pub(crate) fn hole(&self) -> bool {
        self.refs.keys().next().is_some_and(|&seq| seq > self.cursor.saturating_add(1))
    }

    /// Higher pushes require a durable W0 receipt. `seq == C+1` applies directly.
    pub(crate) fn admit(
        &mut self,
        now_ms: u64,
        seq: u64,
        ref_bytes: usize,
        staged: bool,
    ) -> AdmitOutcome {
        if seq == 0 || seq <= self.cursor {
            return AdmitOutcome::Duplicate { seq };
        }
        if seq == self.cursor.saturating_add(1) {
            return AdmitOutcome::ReadyToApply { seq };
        }
        if !staged {
            return AdmitOutcome::Refused { seq };
        }
        if self.refs.contains_key(&seq) {
            return AdmitOutcome::Duplicate { seq };
        }
        self.refs.insert(seq, ref_bytes);
        self.bytes = self.bytes.saturating_add(ref_bytes);
        let dropped = self.evict_highest();
        self.arm_gap(now_ms);
        AdmitOutcome::Buffered { seq, dropped }
    }

    fn evict_highest(&mut self) -> Option<u64> {
        let mut dropped = None;
        while self.refs.len() > MAX_REFS || self.bytes > MAX_REF_BYTES {
            let Some((&seq, &n)) = self.refs.iter().next_back() else {
                break;
            };
            self.refs.remove(&seq);
            self.bytes = self.bytes.saturating_sub(n);
            dropped = Some(seq);
            self.overflow_acks = 0;
            self.catch_up.request();
        }
        dropped
    }

    fn arm_gap(&mut self, now_ms: u64) {
        if self.hole() {
            if self.gap_started_at.is_none() {
                self.gap_started_at = Some(now_ms);
            }
        } else {
            self.gap_started_at = None;
        }
    }

    /// Advances C after a contiguous apply. The RAM ref is dropped; W0 stays on disk until W2.
    ///
    /// # Errors
    /// Returns a protocol error when `seq` is not the next contiguous cursor.
    pub(crate) fn applied(&mut self, seq: u64) -> Result<(), ReorderError> {
        let next = self
            .cursor
            .checked_add(1)
            .ok_or(ReorderError::Protocol("receive reorder cursor overflow"))?;
        if seq != next {
            return Err(ReorderError::Protocol("receive reorder apply is not contiguous"));
        }
        if let Some(n) = self.refs.remove(&seq) {
            self.bytes = self.bytes.saturating_sub(n);
        }
        self.cursor = seq;
        if !self.hole() {
            self.gap_started_at = None;
        }
        Ok(())
    }

    /// Lowest-first contiguous refs, capped at [`PAGE_LIMIT`] per turn.
    #[must_use]
    pub(crate) fn peek_contiguous(&self) -> Vec<u64> {
        let mut out = Vec::new();
        let mut seq = self.cursor;
        while out.len() < PAGE_LIMIT as usize {
            let Some(next) = seq.checked_add(1) else {
                break;
            };
            if !self.refs.contains_key(&next) {
                break;
            }
            out.push(next);
            seq = next;
        }
        out
    }

    pub(crate) fn note_hint(&mut self, _hint: CatchUpHint) {
        self.catch_up.request();
    }

    /// Local-only WS: durable work covering C+1 avoids a pull.
    pub(crate) fn note_local_work(&mut self) {
        self.local_work = true;
    }

    pub(crate) fn finish_catch_up(&mut self) {
        self.catch_up.finish();
    }

    /// Records one catch-up page. True when the run must yield after 16 pages.
    #[must_use]
    pub(crate) fn record_page(&mut self) -> bool {
        if !self.catch_up.in_flight {
            return false;
        }
        self.catch_up.pages = self.catch_up.pages.saturating_add(1);
        if self.catch_up.pages < YIELD_AFTER_PAGES {
            return false;
        }
        self.catch_up.in_flight = false;
        self.catch_up.follow_up = false;
        self.catch_up.pending = true;
        self.catch_up.pages = 0;
        true
    }

    pub(crate) fn tick(&mut self, now_ms: u64) -> Tick {
        if self.local_work {
            self.local_work = false;
            if self.hole() {
                self.catch_up.request();
            } else {
                return Tick::Idle;
            }
        }
        if self.should_fire_gap(now_ms) {
            self.catch_up.request();
            self.gap_started_at = None;
        }
        if self.catch_up.in_flight {
            return Tick::Idle;
        }
        if self.catch_up.pending {
            let after = self.cursor;
            self.catch_up.start();
            return Tick::CatchUp { after, page_limit: PAGE_LIMIT };
        }
        Tick::Idle
    }

    fn should_fire_gap(&self, now_ms: u64) -> bool {
        let Some(started) = self.gap_started_at else {
            return false;
        };
        self.hole() && now_ms.saturating_sub(started) >= GAP_WAIT_MS
    }
}
