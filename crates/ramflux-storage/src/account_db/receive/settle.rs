// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WS below-C settlement. Indexed local redrive: terminal intent+cleanup or a preserved
//! hold, never a C write. Above-C delegates to ordered W2 (`cover`). A retired incarnation
//! is local cleanup of any sequence (no ACK intent, no C write, no cover). Compat U
//! (`incarnation_verified=0`) stays live. Cover and stage refuse a retired E; the source
//! gate and bind allow already-retained work. Dormant until the actor wires it in P20.
//! The typed `inbox_receive_failure` event is
//! written by P07/P08 in the same caller transaction.
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
    /// A retired E skips the C comparison and never delegates to cover.
    ///
    /// # Errors
    /// Refuses a zero sequence, missing retained work, a jump over C on the live E,
    /// stale writer authority, and storage failures.
    pub fn settle(&self, input: ReceiveSettle) -> Result<ReceiveSettleResult, StorageError> {
        self.require_writer()?;
        if !self.retired {
            self.refuse_frozen()?;
        }
        if input.sequence == 0 {
            return Err(StorageError::Integrity("receive sequence must be positive"));
        }
        if !self.retired {
            let cursor = self.cursor()?;
            if input.sequence > cursor {
                return self.delegate_cover(input);
            }
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

    /// Settles retained work for another incarnation fenced as retired by the current target.
    /// This is used inside an already-open target transaction so cleanup joins the caller's
    /// commit; the P06 `settle` path remains the only way to remove its ledger work.
    pub(crate) fn settle_retained_for(
        &self,
        incarnation: &str,
        input: ReceiveSettle,
    ) -> Result<ReceiveSettleResult, StorageError> {
        self.require_writer()?;
        if incarnation == self.incarnation {
            return self.settle(input);
        }
        let retired_blob: Vec<u8> = self.db.connection.query_row(
            "SELECT retired_incarnations FROM gateway_receive_epoch WHERE target_delivery_id=?1",
            params![self.target],
            |row| row.get(0),
        )?;
        let retired: Vec<String> = if retired_blob.is_empty() {
            Vec::new()
        } else {
            serde_json::from_slice(&retired_blob)
                .map_err(|_| StorageError::Integrity("retired incarnation encoding"))?
        };
        if !retired.iter().any(|value| value == incarnation) {
            return Err(StorageError::AuthorizationRejected);
        }
        ReceiveTransaction { db: self.db, target: self.target, incarnation, retired: true }
            .settle(input)
    }

    /// Held/quarantined/staged work and erased receipts, oldest first. Live E is at or
    /// below C; a retired E lists every retained or erased row of that incarnation.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn due_retained(&self, limit: u32) -> Result<Vec<u64>, StorageError> {
        self.require_writer()?;
        let cursor = self.cursor()?.to_be_bytes();
        let cap = i64::from(limit.min(DUE_LIMIT));
        let retired = i64::from(self.retired);
        let mut query = self.db.connection.prepare(
            "SELECT r.inbox_seq FROM gateway_receive_receipt r
             LEFT JOIN gateway_receive_work w
               ON w.target_delivery_id=r.target_delivery_id
              AND w.incarnation_id=r.incarnation_id
              AND w.inbox_seq=r.inbox_seq
             WHERE r.target_delivery_id=?1 AND r.incarnation_id=?2
               AND (r.inbox_seq<=?3 OR ?4=1)
               AND (
                 (r.disposition IN ('held','quarantined','staged') AND w.inbox_seq IS NOT NULL)
                 OR r.disposition='erased'
               )
             ORDER BY r.inbox_seq LIMIT ?5",
        )?;
        let rows = query.query_map(
            params![self.target, self.incarnation, cursor.as_slice(), retired, cap],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
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

    fn delegate_cover(&self, input: ReceiveSettle) -> Result<ReceiveSettleResult, StorageError> {
        let kind = match input.kind {
            ReceiveSettleKind::Terminal => ReceiveCoverKind::Terminal,
            ReceiveSettleKind::Held => ReceiveCoverKind::Held,
        };
        match self.cover(ReceiveCover {
            sequence: input.sequence,
            kind,
            gaps: &[],
            retain_until: 0,
        })? {
            ReceiveCoverResult::Paused => Ok(ReceiveSettleResult::Paused),
            ReceiveCoverResult::Covered => Ok(match input.kind {
                ReceiveSettleKind::Terminal => ReceiveSettleResult::Settled,
                ReceiveSettleKind::Held => ReceiveSettleResult::Held,
            }),
        }
    }

    fn finish_below_cursor(&self, sequence: u64) -> Result<(), StorageError> {
        if self.retired {
            if !self.receipt_exists(sequence)? && !self.work_exists(sequence)? {
                return Err(StorageError::Integrity("settle requires retained work"));
            }
            return self.cleanup_settled(sequence);
        }
        if !self.work_exists(sequence)? && !self.erased_receipt(sequence)? {
            if self.intent_exists(sequence)? {
                return Ok(());
            }
            return Err(StorageError::Integrity("settle requires retained work"));
        }
        self.finish_terminal(sequence, crate::unix_now())
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

    fn keep_held(&self, sequence: u64) -> Result<(), StorageError> {
        if !self.work_exists(sequence)? {
            return Err(StorageError::Integrity("settle requires retained work"));
        }
        let seq = sequence.to_be_bytes();
        let changed = self.db.connection.execute(
            "UPDATE gateway_receive_receipt
             SET disposition=CASE WHEN disposition='staged' THEN 'held' ELSE disposition END
             WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3
               AND disposition IN ('held','quarantined','staged')",
            params![self.target, self.incarnation, seq.as_slice()],
        )?;
        if changed == 0 {
            return Err(StorageError::Integrity("settle requires retained work"));
        }
        Ok(())
    }

    fn receipt_exists(&self, sequence: u64) -> Result<bool, StorageError> {
        let seq = sequence.to_be_bytes();
        let found: i64 = self.db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3)",
            params![self.target, self.incarnation, seq.as_slice()],
            |row| row.get(0),
        )?;
        Ok(found != 0)
    }

    fn erased_receipt(&self, sequence: u64) -> Result<bool, StorageError> {
        let seq = sequence.to_be_bytes();
        let found: i64 = self.db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3 AND disposition='erased')",
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
