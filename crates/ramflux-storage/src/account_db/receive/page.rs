// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Page coverage: indexed receipt-range merge subtracted from (after, covered]
//! before W2. Dormant until the actor wires `ApplyPage` in P20.
use super::cover::{
    ReceiveCover, ReceiveCoverKind, ReceiveCoverResult, ReceiveGap, interval_count,
};
use super::{ReceiveExpectation, ReceiveTransaction};
use crate::{AccountDb, StorageError};
use rusqlite::params;

/// Inclusive known-loss interval from a validated page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveKnownLoss<'a> {
    pub from_seq: u64,
    pub to_seq: u64,
    pub reason: &'a str,
}

/// Authoritative coverage after SDK page validation and stale-suffix trim.
#[derive(Clone, Copy, Debug)]
pub struct ReceivePageView<'a> {
    pub after: u64,
    pub covered: u64,
    pub entries: &'a [u64],
    pub known_losses: &'a [ReceiveKnownLoss<'a>],
}

/// Owned gap fed to [`ReceiveCover`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveGapOwned {
    pub from_seq: u64,
    pub to_seq: u64,
    pub reason: String,
    pub classification: String,
}

impl ReceiveGapOwned {
    /// Borrowed view for a W2 step.
    #[must_use]
    pub fn as_gap(&self) -> ReceiveGap<'_> {
        ReceiveGap {
            from_seq: self.from_seq,
            to_seq: self.to_seq,
            reason: &self.reason,
            classification: &self.classification,
        }
    }
}

/// One ordered W2 step produced by receipt-subtracted coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveCoverStep {
    pub sequence: u64,
    pub kind: ReceiveCoverKind,
    pub gaps: Vec<ReceiveGapOwned>,
    pub retain_until: i64,
}

/// Reconcile either yields a full plan or stops at the first unstaged live entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveReconcileResult {
    Plan(Vec<ReceiveCoverStep>),
    NeedStage { sequence: u64, prefix: Vec<ReceiveCoverStep> },
}

impl ReceiveReconcileResult {
    /// Steps that may run before a possible unstaged entry.
    #[must_use]
    pub fn prefix(&self) -> &[ReceiveCoverStep] {
        match self {
            Self::Plan(steps) | Self::NeedStage { prefix: steps, .. } => steps,
        }
    }
}

impl ReceiveTransaction<'_> {
    /// Subtracts indexed staged/held/erased receipts from page coverage, then builds W2 steps.
    /// Gaps never extend past `covered`. A huge hole is one interval, not a per-seq walk.
    ///
    /// # Errors
    /// Refuses inverted/overflowed coverage, losses outside `(after, covered]`, and storage failures.
    pub fn reconcile(
        &self,
        page: ReceivePageView<'_>,
    ) -> Result<ReceiveReconcileResult, StorageError> {
        self.require_writer()?;
        if page.covered < page.after {
            return Err(StorageError::Integrity("receive page after exceeds covered"));
        }
        if page.covered == page.after {
            return Ok(ReceiveReconcileResult::Plan(Vec::new()));
        }
        let start = page
            .after
            .checked_add(1)
            .ok_or(StorageError::Integrity("receive cover interval overflow"))?;
        let receipts = load_receipts(self, start, page.covered)?;
        let occupied = occupy(start, page.covered, &receipts, page.entries)?;
        let holes = invert(start, page.covered, &occupied)?;
        let gaps = paint(holes, page.known_losses, page.after, page.covered)?;
        plan(gaps, &receipts, page.entries, start, page.covered)
    }
}

impl AccountDb {
    /// Commits each reconciled step in its own expected-(E,C) transaction.
    /// A later pause leaves earlier steps durable.
    ///
    /// # Errors
    /// Propagates fence, cover and storage failures.
    pub fn apply_receive_plan(
        &self,
        expected: ReceiveExpectation<'_>,
        generation: u64,
        steps: &[ReceiveCoverStep],
    ) -> Result<ReceiveCoverResult, StorageError> {
        let mut cursor = expected.cursor;
        for step in steps {
            let gaps: Vec<ReceiveGap<'_>> = step.gaps.iter().map(ReceiveGapOwned::as_gap).collect();
            let result = self.receive_transaction(
                ReceiveExpectation { cursor, ..expected },
                generation,
                |tx| {
                    tx.cover(ReceiveCover {
                        sequence: step.sequence,
                        kind: step.kind,
                        gaps: &gaps,
                        retain_until: step.retain_until,
                    })
                },
            )?;
            if result == ReceiveCoverResult::Paused {
                return Ok(result);
            }
            cursor = step.sequence;
        }
        Ok(ReceiveCoverResult::Covered)
    }
}

#[derive(Clone, Copy, Debug)]
struct ReceiptSpan {
    from_seq: u64,
    to_seq: u64,
    kind: ReceiveCoverKind,
}

fn load_receipts(
    tx: &ReceiveTransaction<'_>,
    from: u64,
    to: u64,
) -> Result<Vec<ReceiptSpan>, StorageError> {
    if skip_receipts() {
        return Ok(Vec::new());
    }
    let from_b = from.to_be_bytes();
    let to_b = to.to_be_bytes();
    let mut query = tx.db.connection.prepare(
        "SELECT inbox_seq,disposition FROM gateway_receive_receipt \
         WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq>=?3 AND inbox_seq<=?4 \
         ORDER BY inbox_seq",
    )?;
    let rows = query.query_map(
        params![tx.target, tx.incarnation, from_b.as_slice(), to_b.as_slice()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
    )?;
    let mut spans: Vec<ReceiptSpan> = Vec::new();
    for row in rows {
        let (bytes, disposition) = row?;
        let seq = be_u64(bytes)?;
        if seq < from || seq > to {
            return Err(StorageError::Integrity("receive reconcile beyond covered"));
        }
        let kind = match disposition.as_str() {
            "held" | "quarantined" => ReceiveCoverKind::Held,
            "staged" | "completed" | "rejected" | "erased" => ReceiveCoverKind::Terminal,
            _ => return Err(StorageError::Integrity("receive cover requires a receipt")),
        };
        if let Some(last) = spans.last_mut() {
            let adjacent = last
                .to_seq
                .checked_add(1)
                .ok_or(StorageError::Integrity("receive cover interval overflow"))?;
            if adjacent == seq && last.kind == kind {
                last.to_seq = seq;
                continue;
            }
        }
        spans.push(ReceiptSpan { from_seq: seq, to_seq: seq, kind });
    }
    Ok(spans)
}

fn occupy(
    from: u64,
    to: u64,
    receipts: &[ReceiptSpan],
    entries: &[u64],
) -> Result<Vec<(u64, u64)>, StorageError> {
    let mut occupied = Vec::new();
    for span in receipts {
        occupied.push((span.from_seq, span.to_seq));
    }
    for &seq in entries {
        if seq < from || seq > to {
            return Err(StorageError::Integrity("receive page entry outside coverage"));
        }
        occupied.push((seq, seq));
    }
    occupied.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (a, b) in occupied {
        let _ = interval_count(a, b)?;
        if let Some(last) = merged.last_mut() {
            if a <= last.1 {
                last.1 = last.1.max(b);
                continue;
            }
            let adjacent = last
                .1
                .checked_add(1)
                .ok_or(StorageError::Integrity("receive cover interval overflow"))?;
            if adjacent == a {
                last.1 = b;
                continue;
            }
        }
        merged.push((a, b));
    }
    Ok(merged)
}

fn invert(from: u64, to: u64, occupied: &[(u64, u64)]) -> Result<Vec<(u64, u64)>, StorageError> {
    let mut cursor = from;
    let mut holes = Vec::new();
    for &(a, b) in occupied {
        if b < a || a < from || b > to {
            return Err(StorageError::Integrity("receive reconcile beyond covered"));
        }
        if a < cursor {
            return Err(StorageError::Integrity("receive cover interval overlap"));
        }
        if a > cursor {
            let end = a
                .checked_sub(1)
                .ok_or(StorageError::Integrity("receive cover interval overflow"))?;
            holes.push((cursor, end));
        }
        cursor =
            b.checked_add(1).ok_or(StorageError::Integrity("receive cover interval overflow"))?;
        if cursor > to {
            return Ok(holes);
        }
    }
    if cursor <= to {
        holes.push((cursor, to));
    }
    Ok(holes)
}

fn paint(
    holes: Vec<(u64, u64)>,
    losses: &[ReceiveKnownLoss<'_>],
    after: u64,
    covered: u64,
) -> Result<Vec<ReceiveGapOwned>, StorageError> {
    let mut ordered = losses.to_vec();
    ordered.sort_by_key(|loss| loss.from_seq);
    let mut last_to = after;
    for loss in &ordered {
        let _ = interval_count(loss.from_seq, loss.to_seq)?;
        if loss.from_seq <= after || loss.to_seq > covered {
            return Err(StorageError::Integrity("receive cover interval outside page"));
        }
        if loss.from_seq <= last_to {
            return Err(StorageError::Integrity("receive cover interval overlap"));
        }
        if loss.reason.is_empty() {
            return Err(StorageError::Integrity("receive cover interval missing reason"));
        }
        last_to = loss.to_seq;
    }
    let mut painted = Vec::new();
    for (from, to) in holes {
        let mut cursor = from;
        for loss in &ordered {
            if loss.to_seq < cursor || loss.from_seq > to {
                continue;
            }
            let start = cursor.max(loss.from_seq);
            let end = to.min(loss.to_seq);
            if start > end {
                continue;
            }
            if start > cursor {
                let unknown_end = start
                    .checked_sub(1)
                    .ok_or(StorageError::Integrity("receive cover interval overflow"))?;
                painted.push(gap(cursor, unknown_end, "unknown"));
            }
            painted.push(gap(start, end, loss.reason));
            cursor = end
                .checked_add(1)
                .ok_or(StorageError::Integrity("receive cover interval overflow"))?;
            if cursor > to {
                break;
            }
        }
        if cursor <= to {
            painted.push(gap(cursor, to, "unknown"));
        }
    }
    Ok(painted)
}

fn gap(from_seq: u64, to_seq: u64, reason: &str) -> ReceiveGapOwned {
    ReceiveGapOwned {
        from_seq,
        to_seq,
        reason: reason.to_owned(),
        classification: "unavailable".to_owned(),
    }
}

fn plan(
    gaps: Vec<ReceiveGapOwned>,
    receipts: &[ReceiptSpan],
    entries: &[u64],
    start: u64,
    covered: u64,
) -> Result<ReceiveReconcileResult, StorageError> {
    #[derive(Clone)]
    enum Event {
        Gap(ReceiveGapOwned),
        Live { sequence: u64, kind: ReceiveCoverKind },
        Stage { sequence: u64 },
    }
    let receipt_at = |seq: u64| -> Option<ReceiveCoverKind> {
        receipts
            .iter()
            .find_map(|span| (seq >= span.from_seq && seq <= span.to_seq).then_some(span.kind))
    };
    let mut events = Vec::new();
    for g in gaps {
        events.push((g.from_seq, Event::Gap(g)));
    }
    for span in receipts {
        let mut seq = span.from_seq;
        loop {
            events.push((seq, Event::Live { sequence: seq, kind: span.kind }));
            if seq == span.to_seq {
                break;
            }
            seq = seq
                .checked_add(1)
                .ok_or(StorageError::Integrity("receive cover interval overflow"))?;
        }
    }
    for &seq in entries {
        if receipt_at(seq).is_none() {
            events.push((seq, Event::Stage { sequence: seq }));
        }
    }
    events.sort_by_key(|(seq, _)| *seq);
    let mut pending: Vec<ReceiveGapOwned> = Vec::new();
    let mut steps = Vec::new();
    let flush_gaps = |pending: &mut Vec<ReceiveGapOwned>,
                      steps: &mut Vec<ReceiveCoverStep>|
     -> Result<(), StorageError> {
        if pending.is_empty() {
            return Ok(());
        }
        let sequence = pending.last().map_or(start, |gap| gap.to_seq);
        steps.push(ReceiveCoverStep {
            sequence,
            kind: ReceiveCoverKind::GapOnly,
            gaps: std::mem::take(pending),
            retain_until: 0,
        });
        Ok(())
    };
    for (_, event) in events {
        match event {
            Event::Gap(g) => {
                if pending.len() >= 64 {
                    flush_gaps(&mut pending, &mut steps)?;
                }
                pending.push(g);
            }
            Event::Live { sequence, kind } => {
                if pending.len() >= 64 {
                    flush_gaps(&mut pending, &mut steps)?;
                }
                steps.push(ReceiveCoverStep {
                    sequence,
                    kind,
                    gaps: std::mem::take(&mut pending),
                    retain_until: 0,
                });
            }
            Event::Stage { sequence } => {
                flush_gaps(&mut pending, &mut steps)?;
                return Ok(ReceiveReconcileResult::NeedStage { sequence, prefix: steps });
            }
        }
    }
    flush_gaps(&mut pending, &mut steps)?;
    if steps.last().is_some_and(|step| step.sequence > covered) {
        return Err(StorageError::Integrity("receive reconcile beyond covered"));
    }
    Ok(ReceiveReconcileResult::Plan(steps))
}

fn be_u64(bytes: Vec<u8>) -> Result<u64, StorageError> {
    let buf: [u8; 8] = bytes
        .try_into()
        .map_err(|_| StorageError::Integrity("receive sequence must be positive"))?;
    Ok(u64::from_be_bytes(buf))
}

fn skip_receipts() -> bool {
    #[cfg(test)]
    {
        SKIP.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

#[cfg(test)]
thread_local! {
    static SKIP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn run<T>(fault: ReconcileFault, write: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            SKIP.with(|slot| slot.set(false));
        }
    }
    SKIP.with(|slot| slot.set(true));
    let _reset = Reset;
    let _ = fault;
    write()
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReconcileFault {
    SkipReceipts,
}
