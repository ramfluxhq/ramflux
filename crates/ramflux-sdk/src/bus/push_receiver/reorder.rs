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
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub(crate) enum AdmitOutcome {
    ReadyToApply {
        seq: u64,
    },
    /// `seq` is retained in RAM. `evicted` lists every higher ref dropped to fit the caps.
    Buffered {
        seq: u64,
        evicted: Vec<u64>,
    },
    /// `seq` itself was the highest ref and was evicted. `evicted` lists every dropped seq, `seq` included.
    Evicted {
        seq: u64,
        evicted: Vec<u64>,
    },
    Duplicate {
        seq: u64,
    },
    Refused {
        seq: u64,
    },
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
    cover_steps: u64,
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
            cover_steps: 0,
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

    /// Work units spent by `covered` (container operations, not seq positions). Bounded by the ref cap.
    #[must_use]
    pub(crate) fn cover_steps(&self) -> u64 {
        self.cover_steps
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
        let evicted = self.evict_highest();
        self.arm_gap(now_ms);
        if evicted.contains(&seq) {
            AdmitOutcome::Evicted { seq, evicted }
        } else {
            AdmitOutcome::Buffered { seq, evicted }
        }
    }

    fn evict_highest(&mut self) -> Vec<u64> {
        let mut evicted = Vec::new();
        while self.refs.len() > MAX_REFS || self.bytes > MAX_REF_BYTES {
            let Some((&seq, &n)) = self.refs.iter().next_back() else {
                break;
            };
            self.refs.remove(&seq);
            self.bytes = self.bytes.saturating_sub(n);
            evicted.push(seq);
            self.overflow_acks = 0;
            self.catch_up.request();
        }
        evicted
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
    pub(crate) fn applied(&mut self, now_ms: u64, seq: u64) -> Result<(), ReorderError> {
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
        // A contiguous apply can leave a hole behind: that hole starts its own gap timer now.
        self.gap_started_at = if self.hole() { self.gap_started_at.or(Some(now_ms)) } else { None };
        Ok(())
    }

    /// Authoritative page cover: moves C to `new_c` in one call. Every RAM ref at or below
    /// `new_c` is dropped, so the work is bounded by the ref cap, not by the size of the loss range.
    /// The single gap timer is re-armed at `now_ms` when a hole remains past `new_c`.
    ///
    /// # Errors
    /// Returns a protocol error when `new_c` would move C backwards.
    pub(crate) fn covered(&mut self, now_ms: u64, new_c: u64) -> Result<(), ReorderError> {
        if new_c < self.cursor {
            return Err(ReorderError::Protocol("receive reorder cover moves backward"));
        }
        let high = match new_c.checked_add(1) {
            Some(first_kept) => self.refs.split_off(&first_kept),
            None => BTreeMap::new(),
        };
        self.cover_steps = self.cover_steps.saturating_add(1);
        let covered_refs = std::mem::replace(&mut self.refs, high);
        for n in covered_refs.values() {
            self.cover_steps = self.cover_steps.saturating_add(1);
            self.bytes = self.bytes.saturating_sub(*n);
        }
        self.cursor = new_c;
        self.gap_started_at = if self.hole() { Some(now_ms) } else { None };
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

    /// Ends the in-flight run. A hole that outlives the run re-arms the gap timer (L4), so
    /// recovery does not wait for the next push or the safety sweep.
    pub(crate) fn finish_catch_up(&mut self, now_ms: u64) {
        self.catch_up.finish();
        if self.hole() && self.gap_started_at.is_none() {
            self.gap_started_at = Some(now_ms);
        }
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
            // Local work only suppresses a pull it covers. It must not cancel other pending triggers (M1).
            self.local_work = false;
            if self.hole() {
                self.catch_up.request();
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
