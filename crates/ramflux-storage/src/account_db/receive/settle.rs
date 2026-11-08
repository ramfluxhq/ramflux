// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WS below-C settlement. Indexed local redrive: terminal intent+cleanup or a preserved
//! hold, never a C write. Above-C delegates to ordered W2 (`cover`). Inactive E is local
//! recovery only. Dormant until the actor wires it in P20.
use super::ReceiveTransaction;
use super::cover::{ReceiveCover, ReceiveCoverKind, ReceiveCoverResult};
use crate::{ProjectionStore, StorageError};
use rusqlite::params;

const DUE_LIMIT: u32 = 64;

/// How below-C retained work is settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveSettleKind {
    /// Completed/duplicate/rejected/erased/local policy: intent + cleanup, C unchanged.
    Terminal,
    /// Still held: keep work, omit intent, C unchanged.
    Held,
}

/// One WS step on a retained sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveSettle {
    pub sequence: u64,
    pub kind: ReceiveSettleKind,
}

/// WS either commits the step, preserves the hold, or pauses an above-C cover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveSettleResult {
    Settled,
    Held,
    Paused,
}

impl ReceiveTransaction<'_> {
    /// Settles retained work at `sequence`. `s<=C` is WS (C frozen). `s=C+1` is W2 cover.
    ///
    /// # Errors
    /// Refuses a zero sequence, missing retained work, an inactive-E cover, a jump over C,
    /// stale writer authority, and storage failures.
    pub fn settle(&self, input: ReceiveSettle) -> Result<ReceiveSettleResult, StorageError> {
        self.require_writer()?;
        if input.sequence == 0 {
            return Err(StorageError::Integrity("receive sequence must be positive"));
        }
        let cursor = self.cursor()?;
        if input.sequence > cursor {
            return self.delegate_cover(input);
        }
        match input.kind {
            ReceiveSettleKind::Terminal => self.finish_below_cursor(input.sequence)?,
            ReceiveSettleKind::Held => self.keep_held(input.sequence)?,
        }
        before_commit()?;
        Ok(match input.kind {
            ReceiveSettleKind::Terminal => ReceiveSettleResult::Settled,
            ReceiveSettleKind::Held => ReceiveSettleResult::Held,
        })
    }

    /// Held/quarantined/staged receipts at or below C that still have work, oldest first.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn due_retained(&self, limit: u32) -> Result<Vec<u64>, StorageError> {
        self.require_writer()?;
        let cursor = self.cursor()?.to_be_bytes();
        let cap = i64::from(limit.min(DUE_LIMIT));
        let mut query = self.db.connection.prepare(
            "SELECT r.inbox_seq FROM gateway_receive_receipt r
             INNER JOIN gateway_receive_work w
               ON w.target_delivery_id=r.target_delivery_id
              AND w.incarnation_id=r.incarnation_id
              AND w.inbox_seq=r.inbox_seq
             WHERE r.target_delivery_id=?1 AND r.incarnation_id=?2
               AND r.inbox_seq<=?3
               AND r.disposition IN ('held','quarantined','staged')
             ORDER BY r.inbox_seq LIMIT ?4",
        )?;
        let rows = query
            .query_map(params![self.target, self.incarnation, cursor.as_slice(), cap], |row| {
                row.get::<_, Vec<u8>>(0)
            })?;
        let mut out = Vec::new();
        for row in rows {
            let bytes = row?;
            let seq = u64::from_be_bytes(
                bytes
                    .try_into()
                    .map_err(|_| StorageError::Integrity("receive sequence encoding"))?,
            );
            out.push(seq);
        }
        Ok(out)
    }

    fn cursor(&self) -> Result<u64, StorageError> {
        self.db
            .projection_checkpoint(&format!("gateway_receive_cursor:{}", self.target))?
            .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))
    }

    fn incarnation_verified(&self) -> Result<bool, StorageError> {
        let flag: i64 = self.db.connection.query_row(
            "SELECT incarnation_verified FROM gateway_receive_epoch WHERE target_delivery_id=?1",
            params![self.target],
            |row| row.get(0),
        )?;
        Ok(flag == 1)
    }

    fn delegate_cover(&self, input: ReceiveSettle) -> Result<ReceiveSettleResult, StorageError> {
        if !self.incarnation_verified()? {
            return Err(StorageError::Integrity("inactive incarnation allows local recovery only"));
        }
        let kind = match input.kind {
            ReceiveSettleKind::Terminal => ReceiveCoverKind::Terminal,
            ReceiveSettleKind::Held => ReceiveCoverKind::Held,
        };
        match self.cover(ReceiveCover { sequence: input.sequence, kind, gaps: &[] })? {
            ReceiveCoverResult::Paused => Ok(ReceiveSettleResult::Paused),
            ReceiveCoverResult::Covered => Ok(match input.kind {
                ReceiveSettleKind::Terminal => ReceiveSettleResult::Settled,
                ReceiveSettleKind::Held => ReceiveSettleResult::Held,
            }),
        }
    }

    fn finish_below_cursor(&self, sequence: u64) -> Result<(), StorageError> {
        let seq = sequence.to_be_bytes();
        if self.intent_exists(sequence)? {
            return Ok(());
        }
        if !self.work_exists(sequence)? {
            return Err(StorageError::Integrity("settle requires retained work"));
        }
        let now = crate::unix_now();
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

    fn keep_held(&self, sequence: u64) -> Result<(), StorageError> {
        if !self.work_exists(sequence)? {
            return Err(StorageError::Integrity("settle requires retained work"));
        }
        let seq = sequence.to_be_bytes();
        let now = crate::unix_now();
        let changed = self.db.connection.execute(
            "UPDATE gateway_receive_receipt
             SET disposition=CASE WHEN disposition='staged' THEN 'held' ELSE disposition END,
                 retain_until=MAX(retain_until,?4)
             WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3
               AND disposition IN ('held','quarantined','staged')",
            params![self.target, self.incarnation, seq.as_slice(), now],
        )?;
        if changed == 0 {
            return Err(StorageError::Integrity("settle requires retained work"));
        }
        Ok(())
    }

    fn intent_exists(&self, sequence: u64) -> Result<bool, StorageError> {
        let seq = sequence.to_be_bytes();
        let found: i64 = self.db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_ack_intent WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3)",
            params![self.target, self.incarnation, seq.as_slice()],
            |row| row.get(0),
        )?;
        Ok(found != 0)
    }

    fn work_exists(&self, sequence: u64) -> Result<bool, StorageError> {
        let seq = sequence.to_be_bytes();
        let found: i64 = self.db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_receive_work WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3)",
            params![self.target, self.incarnation, seq.as_slice()],
            |row| row.get(0),
        )?;
        Ok(found != 0)
    }
}

fn before_commit() -> Result<(), StorageError> {
    if current_fault() == Fault::BeforeCommit {
        return Err(StorageError::Integrity("receive settle before-commit"));
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
