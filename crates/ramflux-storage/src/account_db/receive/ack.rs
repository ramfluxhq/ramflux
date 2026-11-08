// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WA: one sorted positive max-64 ACK-intent batch with an exact result set.
//! A terminal outcome settles in ONE transaction: the intent is deleted and its
//! terminal compat work/receipt rows are released. Uncertainty retains; `invalid_seq`
//! diagnoses and asks the caller to revalidate E; mismatch asks the caller for P10
//! reset; a result for an old incarnation is dropped; an expired intent is dropped
//! locally without network traffic. Held work is never selected. Seq > C is refused.
//! Dormant until P20e/P20g/P24 wire the actor flush.
use super::ReceiveTransaction;
use crate::StorageError;
use rusqlite::params;

/// Wire and storage share this cap (S6a `AckBatch`).
pub const ACK_BATCH_MAX: usize = 64;
/// Flush when this many intents are due.
pub const ACK_FLUSH_COUNT: usize = 16;
/// Flush when the oldest due intent is this many seconds old.
pub const ACK_FLUSH_SECS: i64 = 1;
const BACKOFF_MIN: i64 = 1;
const BACKOFF_MAX: i64 = 60;

/// Router/session result for one intent. SDK maps the wire `AckOutcome` here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveAckOutcome {
    /// Router retired the row.
    Acked,
    /// The router answered that the row was already retired (an explicit reply only).
    AlreadySettled,
    /// Held locally while the router dropped the row.
    NotFound,
    /// Named seq is not valid for this E; delete once, diagnose and revalidate E.
    InvalidSeq,
    /// Transient rejection; backoff 1..60s.
    Transient,
    /// Incarnation mismatch; caller runs P10, no intent is deleted.
    Mismatch,
    /// Lost send, lost reply, or timeout-after-write: retain the intent. The caller also
    /// retires the session; nothing here may map a lost response to a terminal outcome.
    Uncertain,
    /// Intent `expires_at` elapsed (reported by the caller); diagnostic only, never marks.
    Expired,
}

/// One seq in an exact WA result set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveAckResult {
    pub sequence: u64,
    pub outcome: ReceiveAckOutcome,
}

/// Caller-supplied batch plus the exact per-seq results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveAckApply<'a> {
    pub incarnation: &'a str,
    pub sequences: &'a [u64],
    pub results: &'a [ReceiveAckResult],
    pub now: i64,
}

/// WA either settles, drops a stale batch, or asks for reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveAckApplyResult {
    /// `settled` intents were terminal. `revalidate` is set when a result was
    /// `invalid_seq`: the caller must revalidate incarnation E.
    Applied { settled: usize, revalidate: bool },
    /// The batch was built under an older incarnation: the outcome is dropped, no write.
    StaleIncarnation,
    /// The router reported an incarnation mismatch: the caller runs P10 reset.
    ResetRequired,
}

impl ReceiveTransaction<'_> {
    /// Due intents at or below C, never held/quarantined/staged work, never expired.
    /// Returned sorted ascending by `inbox_seq` (the wire order), unique.
    ///
    /// # Errors
    /// Requires the writer; returns SQL errors.
    pub fn due_ack_intents(&self, now: i64, limit: u32) -> Result<Vec<u64>, StorageError> {
        let mut out = self.due_by_age(now, limit)?;
        out.sort_unstable();
        Ok(out)
    }

    fn due_by_age(&self, now: i64, limit: u32) -> Result<Vec<u64>, StorageError> {
        self.require_writer()?;
        let cursor = self.ack_cursor()?.to_be_bytes();
        let cap = i64::from(limit.min(64));
        let mut query = self.db.connection.prepare(
            "SELECT i.inbox_seq FROM gateway_ack_intent i
             WHERE i.target_delivery_id=?1 AND i.incarnation_id=?2
               AND i.next_attempt_at<=?3 AND i.inbox_seq<=?4 AND i.expires_at>?3
               AND NOT EXISTS (
                 SELECT 1 FROM gateway_receive_receipt r
                  WHERE r.target_delivery_id=i.target_delivery_id
                    AND r.incarnation_id=i.incarnation_id
                    AND r.inbox_seq=i.inbox_seq
                    AND r.disposition IN ('held','quarantined','staged')
               )
             ORDER BY i.next_attempt_at, i.inbox_seq LIMIT ?5",
        )?;
        let rows = query.query_map(
            params![self.target, self.incarnation, now, cursor.as_slice(), cap],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut out = Vec::new();
        for seq in rows {
            out.push(u64_from_seq(&seq?)?);
        }
        Ok(out)
    }

    /// Drops every intent whose `expires_at` has passed, locally: no network traffic, one
    /// diagnostic each, terminal compat rows released, own-copy locators never marked.
    /// Returns the expired sequences ascending.
    ///
    /// # Errors
    /// Requires the writer; returns SQL errors.
    pub fn expire_ack_intents(&self, now: i64) -> Result<Vec<u64>, StorageError> {
        self.require_writer()?;
        let mut query = self.db.connection.prepare(
            "SELECT inbox_seq FROM gateway_ack_intent
             WHERE target_delivery_id=?1 AND incarnation_id=?2 AND expires_at<=?3
             ORDER BY inbox_seq",
        )?;
        let rows = query.query_map(params![self.target, self.incarnation, now], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let mut expired = Vec::new();
        for seq in rows {
            expired.push(u64_from_seq(&seq?)?);
        }
        drop(query);
        for sequence in &expired {
            self.settle_intent(*sequence)?;
            self.diagnose(*sequence, now, ReceiveAckOutcome::Expired)?;
        }
        Ok(expired)
    }

    /// Local expiry first, then 16 due, oldest age >= 1s, or `force` (Connected / before
    /// catch-up). The returned batch is always sorted ascending and unique, whatever the
    /// retry order of the selected intents.
    ///
    /// # Errors
    /// Requires the writer; returns SQL errors.
    pub fn select_ack_batch(&self, now: i64, force: bool) -> Result<Vec<u64>, StorageError> {
        self.expire_ack_intents(now)?;
        let mut due = self.due_by_age(now, 64)?;
        if due.is_empty() {
            return Ok(due);
        }
        let ready = force
            || due.len() >= ACK_FLUSH_COUNT
            || self
                .oldest_due_created_at(now)?
                .is_some_and(|created| now.saturating_sub(created) >= ACK_FLUSH_SECS);
        if !ready {
            return Ok(Vec::new());
        }
        if !force {
            due.truncate(ACK_FLUSH_COUNT);
        }
        due.sort_unstable();
        Ok(due)
    }

    /// Apply an exact result set. Uncertain retains. Mismatch writes nothing.
    ///
    /// # Errors
    /// Refuses a retired writer, a zero/unsorted/>64 batch, a result-set mismatch,
    /// seq > C, and storage failures.
    pub fn apply_ack_results(
        &self,
        input: ReceiveAckApply<'_>,
    ) -> Result<ReceiveAckApplyResult, StorageError> {
        self.apply_ack_results_with(input, |_| Ok(()))
    }

    /// [`Self::apply_ack_results`] plus `after`: caller effects that must commit with the
    /// settlement (own-copy marking). `after` runs only when results were applied, and the
    /// commit fault hook runs after it, as the last step before COMMIT.
    ///
    /// # Errors
    /// As [`Self::apply_ack_results`], plus any error from `after`.
    pub fn apply_ack_results_with(
        &self,
        input: ReceiveAckApply<'_>,
        after: impl FnOnce(&Self) -> Result<(), StorageError>,
    ) -> Result<ReceiveAckApplyResult, StorageError> {
        self.require_writer()?;
        validate_batch(input.sequences)?;
        if input.results.len() != input.sequences.len()
            || input
                .results
                .iter()
                .zip(input.sequences)
                .any(|(result, seq)| result.sequence != *seq)
        {
            return Err(StorageError::Integrity("receive ack result set must be exact"));
        }
        if input.incarnation != self.incarnation {
            return Ok(ReceiveAckApplyResult::StaleIncarnation);
        }
        if input.results.iter().any(|row| row.outcome == ReceiveAckOutcome::Mismatch) {
            return Ok(ReceiveAckApplyResult::ResetRequired);
        }
        let cursor = self.ack_cursor()?;
        if input.sequences.iter().any(|seq| *seq > cursor) {
            return Err(StorageError::Integrity("receive ack sequence exceeds cursor"));
        }
        let mut settled = 0usize;
        for row in input.results {
            settled += usize::from(self.apply_one(row, input.now)?);
        }
        let revalidate =
            input.results.iter().any(|row| row.outcome == ReceiveAckOutcome::InvalidSeq);
        after(self)?;
        before_commit()?;
        Ok(ReceiveAckApplyResult::Applied { settled, revalidate })
    }

    fn apply_one(&self, row: &ReceiveAckResult, now: i64) -> Result<bool, StorageError> {
        match row.outcome {
            ReceiveAckOutcome::Acked
            | ReceiveAckOutcome::AlreadySettled
            | ReceiveAckOutcome::NotFound
            | ReceiveAckOutcome::InvalidSeq
            | ReceiveAckOutcome::Expired => {
                self.settle_intent(row.sequence)?;
                if matches!(row.outcome, ReceiveAckOutcome::InvalidSeq | ReceiveAckOutcome::Expired)
                {
                    self.diagnose(row.sequence, now, row.outcome)?;
                }
                Ok(true)
            }
            ReceiveAckOutcome::Transient => {
                self.backoff_intent(row.sequence, now)?;
                Ok(false)
            }
            ReceiveAckOutcome::Uncertain | ReceiveAckOutcome::Mismatch => Ok(false),
        }
    }

    fn diagnose(
        &self,
        sequence: u64,
        now: i64,
        outcome: ReceiveAckOutcome,
    ) -> Result<(), StorageError> {
        let reason = match outcome {
            ReceiveAckOutcome::InvalidSeq => "invalid_seq",
            ReceiveAckOutcome::Expired => "ack_expired",
            _ => return Ok(()),
        };
        let source = format!("ack-{}:{}:{}:{sequence}", reason, self.target, self.incarnation);
        self.db.insert_journal(
            &source,
            "inbox.receive_failure",
            &serde_json::json!({
                "target_delivery_id": self.target,
                "incarnation_id": self.incarnation,
                "inbox_seq": sequence,
                "reason": reason,
            }),
            now,
            None,
        )?;
        Ok(())
    }

    /// One transaction step: delete the intent and release its terminal compat work and
    /// receipt (work first, it references the receipt). Held/staged rows are untouched.
    fn settle_intent(&self, sequence: u64) -> Result<(), StorageError> {
        let seq = sequence.to_be_bytes();
        let key = params![self.target, self.incarnation, seq.as_slice()];
        self.db.connection.execute(
            "DELETE FROM gateway_ack_intent WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
            key,
        )?;
        self.db.connection.execute(
            "DELETE FROM gateway_receive_work WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3
             AND EXISTS (SELECT 1 FROM gateway_receive_receipt r
                          WHERE r.target_delivery_id=?1 AND r.incarnation_id=?2 AND r.inbox_seq=?3
                            AND r.disposition IN ('completed','rejected'))",
            key,
        )?;
        self.db.connection.execute(
            "DELETE FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3
             AND disposition IN ('completed','rejected')",
            key,
        )?;
        Ok(())
    }

    fn backoff_intent(&self, sequence: u64, now: i64) -> Result<(), StorageError> {
        let seq = sequence.to_be_bytes();
        let attempts: i64 = match self.db.connection.query_row(
            "SELECT attempts FROM gateway_ack_intent WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
            params![self.target, self.incarnation, seq.as_slice()],
            |row| row.get(0),
        ) {
            Ok(value) => value,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let shift = u32::try_from(attempts.clamp(0, 6)).unwrap_or(6);
        let delay = BACKOFF_MIN.saturating_mul(1_i64 << shift).min(BACKOFF_MAX);
        self.db.connection.execute(
            "UPDATE gateway_ack_intent SET attempts=attempts+1, next_attempt_at=?1
             WHERE target_delivery_id=?2 AND incarnation_id=?3 AND inbox_seq=?4",
            params![now.saturating_add(delay), self.target, self.incarnation, seq.as_slice()],
        )?;
        Ok(())
    }

    fn oldest_due_created_at(&self, now: i64) -> Result<Option<i64>, StorageError> {
        let cursor = self.ack_cursor()?.to_be_bytes();
        self.db
            .connection
            .query_row(
                "SELECT min(created_at) FROM gateway_ack_intent
                 WHERE target_delivery_id=?1 AND incarnation_id=?2 AND next_attempt_at<=?3 AND inbox_seq<=?4",
                params![self.target, self.incarnation, now, cursor.as_slice()],
                |row| row.get(0),
            )
            .map_err(StorageError::from)
    }

    fn ack_cursor(&self) -> Result<u64, StorageError> {
        self.db.receive_cursor(self.target)
    }
}

fn validate_batch(sequences: &[u64]) -> Result<(), StorageError> {
    if sequences.is_empty() || sequences.len() > ACK_BATCH_MAX || sequences.contains(&0) {
        return Err(StorageError::Integrity("receive ack batch must be 1..=64 positive seqs"));
    }
    if sequences.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(StorageError::Integrity("receive ack batch must be strictly increasing"));
    }
    Ok(())
}

fn u64_from_seq(bytes: &[u8]) -> Result<u64, StorageError> {
    let seq: [u8; 8] =
        bytes.try_into().map_err(|_| StorageError::Integrity("receive sequence encoding"))?;
    Ok(u64::from_be_bytes(seq))
}

fn before_commit() -> Result<(), StorageError> {
    if current_fault() {
        return Err(StorageError::Integrity("receive ack before-commit"));
    }
    Ok(())
}

fn current_fault() -> bool {
    #[cfg(test)]
    {
        FAULT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn run<T>(fault: bool, write: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|slot| slot.set(false));
        }
    }
    FAULT.with(|slot| slot.set(fault));
    let _reset = Reset;
    write()
}
