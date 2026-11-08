// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! W2 cover. One expected-(E,C) transaction writes loss, unpublished gap outbox,
//! terminal intent, cleanup and C. Dormant until the actor wires it in P20.
use super::ReceiveTransaction;
use crate::{ProjectionStore, StorageError};
use rusqlite::{OptionalExtension, params};

const BOUNDARY_LIMIT: usize = 64;
const SLOT_LIMIT: i64 = 1024;
const GAP_REASONS: &[&str] =
    &["expired", "ack_window_overflow", "nacked", "aborted", "oversize", "unknown"];
const GAP_CLASSIFICATIONS: &[&str] = &["unavailable", "legacy_unverified"];

/// Inclusive missing interval with no local receipt. Adjacent same-reason ranges merge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveGap<'a> {
    pub from_seq: u64,
    pub to_seq: u64,
    pub reason: &'a str,
    pub classification: &'a str,
}

/// How the live sequence at `ReceiveCover::sequence` is accounted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveCoverKind {
    /// Completed, duplicate, rejected or erased: intent + cleanup, then C = s.
    Terminal,
    /// Held or quarantined: keep work, omit intent, then C = s.
    Held,
    /// Range-only cover: gaps then C = page.covered, no live receipt.
    GapOnly,
}

/// One W2 step: preceding gaps plus the next ordered boundary.
#[derive(Clone, Copy, Debug)]
pub struct ReceiveCover<'a> {
    pub sequence: u64,
    pub kind: ReceiveCoverKind,
    pub gaps: &'a [ReceiveGap<'a>],
}

/// Cover either commits the whole step or pauses without writing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveCoverResult {
    Covered,
    Paused,
}

impl ReceiveTransaction<'_> {
    /// Commits loss, unpublished gap outbox, optional intent/cleanup and C together.
    ///
    /// # Errors
    /// Refuses inverted/overflowed intervals, more than 64 boundaries, gaps that overlap a
    /// receipt or fall outside `(C, sequence]`, stale writer authority, and storage failures.
    pub fn cover(&self, input: ReceiveCover<'_>) -> Result<ReceiveCoverResult, StorageError> {
        self.require_writer()?;
        let gaps = merge_gaps(input.gaps)?;
        let live = match input.kind {
            ReceiveCoverKind::GapOnly => usize::from(gaps.is_empty()),
            ReceiveCoverKind::Terminal | ReceiveCoverKind::Held => 1,
        };
        if gaps.len().saturating_add(live) > BOUNDARY_LIMIT {
            return Err(StorageError::Integrity("receive cover boundary limit"));
        }
        if input.sequence == 0 {
            return Err(StorageError::Integrity("receive sequence must be positive"));
        }
        let cursor = self
            .db
            .projection_checkpoint(&cursor_name(self.target))?
            .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?;
        for gap in &gaps {
            if gap.from_seq <= cursor || gap.to_seq > input.sequence {
                return Err(StorageError::Integrity("receive cover interval outside page"));
            }
            if self.receipt_in_range(gap.from_seq, gap.to_seq)? {
                return Err(StorageError::Integrity("receive cover interval has a receipt"));
            }
        }
        span_page(cursor, input.sequence, input.kind, &gaps)?;
        if input.kind != ReceiveCoverKind::GapOnly {
            if input.sequence <= cursor {
                return Err(StorageError::Integrity("receive cover interval outside page"));
            }
            let disposition = self.disposition(input.sequence)?;
            let allowed = match input.kind {
                ReceiveCoverKind::Terminal => disposition.is_some(),
                ReceiveCoverKind::Held => {
                    matches!(disposition.as_deref(), Some("staged" | "held" | "quarantined"))
                }
                ReceiveCoverKind::GapOnly => true,
            };
            if !allowed {
                return Err(StorageError::Integrity("receive cover requires a receipt"));
            }
        }
        if input.kind == ReceiveCoverKind::Terminal
            && self.intent_slots(input.sequence)? >= SLOT_LIMIT
        {
            return Ok(ReceiveCoverResult::Paused);
        }
        let now = crate::unix_now();
        for gap in &gaps {
            self.write_gap(gap, now)?;
        }
        match input.kind {
            ReceiveCoverKind::Terminal => self.finish_terminal(input.sequence, now)?,
            ReceiveCoverKind::Held => self.mark_held(input.sequence)?,
            ReceiveCoverKind::GapOnly => {}
        }
        self.db
            .set_projection_checkpoint(&cursor_name(self.target), &input.sequence.to_string())?;
        before_commit()?;
        Ok(ReceiveCoverResult::Covered)
    }

    fn receipt_in_range(&self, from: u64, to: u64) -> Result<bool, StorageError> {
        let from = from.to_be_bytes();
        let to = to.to_be_bytes();
        let found: i64 = self.db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq>=?3 AND inbox_seq<=?4)",
            params![self.target, self.incarnation, from.as_slice(), to.as_slice()],
            |row| row.get(0),
        )?;
        Ok(found != 0)
    }

    fn disposition(&self, sequence: u64) -> Result<Option<String>, StorageError> {
        let seq = sequence.to_be_bytes();
        Ok(self.db.connection.query_row(
            "SELECT disposition FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
            params![self.target, self.incarnation, seq.as_slice()],
            |row| row.get(0),
        ).optional()?)
    }

    fn intent_slots(&self, sequence: u64) -> Result<i64, StorageError> {
        let seq = sequence.to_be_bytes();
        Ok(self.db.connection.query_row(
            "SELECT count(*) FROM (
               SELECT incarnation_id,inbox_seq FROM gateway_ack_intent WHERE target_delivery_id=?1
               UNION
               SELECT incarnation_id,inbox_seq FROM gateway_receive_receipt
                WHERE target_delivery_id=?1 AND NOT (incarnation_id=?2 AND inbox_seq=?3)
             )",
            params![self.target, self.incarnation, seq.as_slice()],
            |row| row.get(0),
        )?)
    }

    fn write_gap(&self, gap: &ReceiveGap<'_>, now: i64) -> Result<(), StorageError> {
        let count = interval_count(gap.from_seq, gap.to_seq)?;
        let from = gap.from_seq.to_be_bytes();
        let to = gap.to_seq.to_be_bytes();
        let count_bytes = count.to_be_bytes();
        self.db.connection.execute(
            "INSERT INTO gateway_inbox_loss VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                self.target,
                self.incarnation,
                from.as_slice(),
                to.as_slice(),
                count_bytes.as_slice(),
                gap.reason,
                now,
                gap.classification
            ],
        )?;
        let source = format!(
            "receive-gap:{}:{}:{}:{}",
            self.target, self.incarnation, gap.from_seq, gap.to_seq
        );
        let keys = serde_json::json!({
            "source_key": source,
            "target": self.target,
            "incarnation": self.incarnation,
            "from_seq": gap.from_seq,
            "to_seq": gap.to_seq,
            "count": count,
            "reason": gap.reason,
            "classification": gap.classification,
        });
        let keys_json = serde_json::to_string(&keys)?;
        self.db.connection.execute(
            "INSERT INTO runtime_outbox(table_name,change_kind,row_id,published,keys_json)
             SELECT 'gateway_inbox_loss','insert',0,0,?1
             WHERE NOT EXISTS (
               SELECT 1 FROM runtime_outbox WHERE json_extract(keys_json,'$.source_key')=?2
             )",
            params![keys_json, source],
        )?;
        Ok(())
    }

    fn finish_terminal(&self, sequence: u64, now: i64) -> Result<(), StorageError> {
        let seq = sequence.to_be_bytes();
        self.db.connection.execute(
            "INSERT INTO gateway_ack_intent VALUES(?1,?2,?3,?4,0,?5,?6)",
            params![
                self.target,
                self.incarnation,
                seq.as_slice(),
                now,
                now,
                now.saturating_add(604_800)
            ],
        )?;
        self.db.connection.execute(
            "DELETE FROM gateway_receive_work WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
            params![self.target, self.incarnation, seq.as_slice()],
        )?;
        self.db.connection.execute(
            "DELETE FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
            params![self.target, self.incarnation, seq.as_slice()],
        )?;
        Ok(())
    }

    fn mark_held(&self, sequence: u64) -> Result<(), StorageError> {
        let seq = sequence.to_be_bytes();
        self.db.connection.execute(
            "UPDATE gateway_receive_receipt SET disposition='held' WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3 AND disposition='staged'",
            params![self.target, self.incarnation, seq.as_slice()],
        )?;
        Ok(())
    }
}

fn cursor_name(target: &str) -> String {
    format!("gateway_receive_cursor:{target}")
}

fn interval_count(from: u64, to: u64) -> Result<u64, StorageError> {
    if from == 0 {
        return Err(StorageError::Integrity("receive sequence must be positive"));
    }
    if to < from {
        return Err(StorageError::Integrity("receive cover interval inverted"));
    }
    to.checked_sub(from)
        .and_then(|span| span.checked_add(1))
        .ok_or(StorageError::Integrity("receive cover interval overflow"))
}

fn span_page(
    cursor: u64,
    sequence: u64,
    kind: ReceiveCoverKind,
    gaps: &[ReceiveGap<'_>],
) -> Result<(), StorageError> {
    let start =
        cursor.checked_add(1).ok_or(StorageError::Integrity("receive cover interval overflow"))?;
    let successor = |seq: u64| {
        seq.checked_add(1).ok_or(StorageError::Integrity("receive cover interval overflow"))
    };
    let chained = |ranges: &[ReceiveGap<'_>]| -> Result<bool, StorageError> {
        for pair in ranges.windows(2) {
            if successor(pair[0].to_seq)? != pair[1].from_seq {
                return Ok(false);
            }
        }
        Ok(true)
    };
    let covered = match kind {
        ReceiveCoverKind::GapOnly => {
            !gaps.is_empty()
                && gaps[0].from_seq == start
                && gaps.last().is_some_and(|gap| gap.to_seq == sequence)
                && chained(gaps)?
        }
        ReceiveCoverKind::Terminal | ReceiveCoverKind::Held if start == sequence => gaps.is_empty(),
        ReceiveCoverKind::Terminal | ReceiveCoverKind::Held => match gaps.last() {
            None => false,
            Some(last) => {
                gaps[0].from_seq == start && successor(last.to_seq)? == sequence && chained(gaps)?
            }
        },
    };
    if covered {
        Ok(())
    } else {
        Err(StorageError::Integrity("receive cover interval outside page"))
    }
}

fn merge_gaps<'a>(gaps: &[ReceiveGap<'a>]) -> Result<Vec<ReceiveGap<'a>>, StorageError> {
    let mut ordered = gaps.to_vec();
    ordered.sort_by_key(|gap| gap.from_seq);
    let mut merged: Vec<ReceiveGap<'a>> = Vec::new();
    for gap in ordered {
        let _ = interval_count(gap.from_seq, gap.to_seq)?;
        if gap.reason.is_empty() || gap.classification.is_empty() {
            return Err(StorageError::Integrity("receive cover interval missing reason"));
        }
        if !GAP_REASONS.contains(&gap.reason) {
            return Err(StorageError::Integrity("receive cover interval unknown reason"));
        }
        if !GAP_CLASSIFICATIONS.contains(&gap.classification) {
            return Err(StorageError::Integrity("receive cover interval unknown classification"));
        }
        if let Some(last) = merged.last_mut() {
            if gap.from_seq <= last.to_seq {
                return Err(StorageError::Integrity("receive cover interval overlap"));
            }
            let adjacent = last
                .to_seq
                .checked_add(1)
                .ok_or(StorageError::Integrity("receive cover interval overflow"))?;
            if adjacent == gap.from_seq
                && last.reason == gap.reason
                && last.classification == gap.classification
            {
                last.to_seq = gap.to_seq;
                continue;
            }
        }
        merged.push(gap);
    }
    Ok(merged)
}

fn before_commit() -> Result<(), StorageError> {
    if current_fault() == Fault::BeforeCommit {
        return Err(StorageError::Integrity("receive cover before-commit"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    BeforeCommit,
}

fn current_fault() -> Fault {
    #[cfg(test)]
    {
        FAULT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        Fault::None
    }
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
}

#[cfg(test)]
pub(crate) fn run<T>(fault: FaultKind, write: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|slot| slot.set(Fault::None));
        }
    }
    let mapped = match fault {
        FaultKind::BeforeCommit => Fault::BeforeCommit,
    };
    FAULT.with(|slot| slot.set(mapped));
    let _reset = Reset;
    write()
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultKind {
    BeforeCommit,
}
