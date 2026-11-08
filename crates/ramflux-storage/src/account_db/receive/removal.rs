// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Terminal hold removal and failure-policy admission. Every removal joins W2/WS through
//! `finish_terminal` / `cleanup_settled`. Dormant until the actor wires it in P20.
use super::ReceiveTransaction;
use super::settle::{ReceiveSettle, ReceiveSettleKind, ReceiveSettleResult};
use crate::{AccountDb, InboxFailurePolicy, ProjectionStore, StorageError};
use rusqlite::params;

const HOLD_EXPIRY_MAX: i64 = 604_800;

/// Local terminal loss reason stored as `inbox.receive_failure`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum ReceiveFailureReason {
    HeldEvicted,
    HeldExpired,
    PolicyRejected,
}

impl ReceiveFailureReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HeldEvicted => "held_evicted",
            Self::HeldExpired => "held_expired",
            Self::PolicyRejected => "policy_rejected",
        }
    }
}

/// Retryable holds the receipt; deterministic/exhausted settle it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum ReceiveFailureKind {
    Retryable,
    Deterministic,
    Exhausted,
}

/// One failure-policy admission for an already-staged W0 sequence.
#[derive(Clone, Copy, Debug)]
pub struct ReceiveFailure<'a> {
    pub sequence: u64,
    pub admission_key: &'a str,
    pub entry: &'a [u8],
    pub kind: ReceiveFailureKind,
    pub error_code: &'a str,
    pub at: i64,
    /// Verified sender policy from the SDK helper; never inferred as unverified here.
    pub policy: InboxFailurePolicy<'a>,
}

/// `Held` keeps work; `Rejected` is the terminal W-path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum ReceiveFailureResult {
    Held,
    Rejected,
}

impl ReceiveTransaction<'_> {
    /// Journals `inbox.receive_failure` and settles through WS/W2 in this transaction.
    ///
    /// # Errors
    /// Returns settle, journal or SQL errors. A retired E uses local cleanup (no ACK intent).
    pub fn settle_failure(
        &self,
        sequence: u64,
        reason: ReceiveFailureReason,
        at: i64,
    ) -> Result<ReceiveSettleResult, StorageError> {
        self.require_writer()?;
        self.db.insert_journal(
            &format!("receive-hold-terminal:{}:{}:{sequence}", self.target, self.incarnation),
            "inbox.receive_failure",
            &serde_json::json!({
                "target_delivery_id": self.target,
                "incarnation_id": self.incarnation,
                "inbox_seq": sequence,
                "reason": reason.as_str(),
            }),
            at,
            None,
        )?;
        self.settle(ReceiveSettle { sequence, kind: ReceiveSettleKind::Terminal })
    }

    /// Joins verified policy, retry or dead-letter marker, and held/terminal receipt.
    ///
    /// # Errors
    /// Propagates storage errors with W0 retained. A paused cover returns `Integrity`.
    pub fn admit_failure(
        &self,
        input: ReceiveFailure<'_>,
    ) -> Result<ReceiveFailureResult, StorageError> {
        self.require_writer()?;
        if input.sequence == 0 || input.admission_key.is_empty() {
            return Err(StorageError::Integrity("receive failure identity missing"));
        }
        if !self.db.apply_inbox_failure_policy(input.admission_key, input.entry, input.policy)? {
            return self.reject_failure(input.sequence, input.at);
        }
        match input.kind {
            ReceiveFailureKind::Retryable => {
                let attempts =
                    self.db.defer_inbox_entry_inner(input.admission_key, input.entry, input.at)?;
                if attempts == 0 {
                    return self.reject_failure(input.sequence, input.at);
                }
                match self.settle(ReceiveSettle {
                    sequence: input.sequence,
                    kind: ReceiveSettleKind::Held,
                })? {
                    ReceiveSettleResult::Held => {
                        before_commit()?;
                        Ok(ReceiveFailureResult::Held)
                    }
                    ReceiveSettleResult::Paused => {
                        Err(StorageError::Integrity("failure admission coverage paused"))
                    }
                    ReceiveSettleResult::Settled => {
                        Err(StorageError::Integrity("retryable failure must remain held"))
                    }
                }
            }
            ReceiveFailureKind::Deterministic | ReceiveFailureKind::Exhausted => {
                self.db.insert_inbox_dead_letter(
                    input.admission_key,
                    input.entry,
                    &serde_json::json!({"retry_key": input.admission_key, "error_code": input.error_code}),
                    input.at,
                )?;
                self.reject_failure(input.sequence, input.at)
            }
        }
    }

    /// Expires held/quarantined work whose local policy `expires_at` or 7-day class max
    /// from `first_seen` is due. Router `retain_until` never selects a row.
    ///
    /// # Errors
    /// Returns settle or SQL errors.
    pub fn expire_holds(&self, at: i64) -> Result<Vec<u64>, StorageError> {
        self.require_writer()?;
        let due = self.due_failure_holds(at)?;
        let mut settled = Vec::new();
        for sequence in due {
            match self.settle_failure(sequence, ReceiveFailureReason::HeldExpired, at)? {
                ReceiveSettleResult::Settled => settled.push(sequence),
                ReceiveSettleResult::Paused => {
                    return Err(StorageError::Integrity("hold expiry coverage paused"));
                }
                ReceiveSettleResult::Held => {
                    return Err(StorageError::Integrity("hold expiry did not settle"));
                }
            }
        }
        before_commit()?;
        Ok(settled)
    }

    fn reject_failure(&self, sequence: u64, at: i64) -> Result<ReceiveFailureResult, StorageError> {
        match self.settle_failure(sequence, ReceiveFailureReason::PolicyRejected, at)? {
            ReceiveSettleResult::Settled => {
                before_commit()?;
                Ok(ReceiveFailureResult::Rejected)
            }
            ReceiveSettleResult::Paused => {
                Err(StorageError::Integrity("failure admission coverage paused"))
            }
            ReceiveSettleResult::Held => {
                Err(StorageError::Integrity("rejected failure must settle"))
            }
        }
    }

    fn due_failure_holds(&self, at: i64) -> Result<Vec<u64>, StorageError> {
        let sql = format!(
            "SELECT w.inbox_seq FROM gateway_receive_work w
             JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq)
             LEFT JOIN runtime_inbox_policy p ON p.envelope_key=w.admission_key
             WHERE w.target_delivery_id=?1 AND w.incarnation_id=?2
               AND r.disposition IN ('held','quarantined')
               AND COALESCE(p.expires_at, r.first_seen + {HOLD_EXPIRY_MAX}) <= ?3
             ORDER BY r.first_seen,w.inbox_seq"
        );
        let mut query = self.db.connection.prepare(&sql)?;
        let rows = query.query_map(params![self.target, self.incarnation, at], |row| {
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
}

impl AccountDb {
    /// True when the dormant receive-ledger tables are installed.
    pub(crate) fn receive_ledger_present(&self) -> Result<bool, StorageError> {
        let found: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='gateway_receive_work')",
            [],
            |row| row.get(0),
        )?;
        Ok(found != 0)
    }

    /// Settles `(target, incarnation, sequence)` rows for `admission_key` through WS/W2. Expiry and
    /// eviction reasons settle only held or quarantined rows; other reasons settle every row.
    /// Local GC fences on expected cursor and erasure generation; the actor generation fence is P20.
    ///
    /// # Errors
    /// Returns settle, fence or SQL errors.
    pub(crate) fn settle_admission(
        &self,
        key: &str,
        reason: ReceiveFailureReason,
        at: i64,
    ) -> Result<bool, StorageError> {
        // Expiry and eviction are local hold removals: staged (unprocessed) rows that share the
        // admission key, and their receipts, are never settled by them (design §2.6).
        let held_only =
            matches!(reason, ReceiveFailureReason::HeldExpired | ReceiveFailureReason::HeldEvicted);
        let rows = self.admission_work(key, held_only)?;
        if rows.is_empty() {
            return Ok(false);
        }
        for (target, incarnation, sequence) in rows {
            let cursor = self
                .projection_checkpoint(&format!("gateway_receive_cursor:{target}"))?
                .map_or(Ok(0), |value| {
                value.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected)
            })?;
            let expected = crate::ReceiveExpectation {
                target: &target,
                incarnation: &incarnation,
                cursor,
                generation: 1,
                erasure_generation: self.privacy_erasure_generation()?,
            };
            self.receive_transaction(expected, 1, |tx| {
                match tx.settle_failure(sequence, reason, at)? {
                    ReceiveSettleResult::Settled => Ok(()),
                    ReceiveSettleResult::Paused => {
                        Err(StorageError::Integrity("hold removal coverage paused"))
                    }
                    ReceiveSettleResult::Held => {
                        Err(StorageError::Integrity("hold removal did not settle"))
                    }
                }
            })?;
        }
        Ok(true)
    }

    /// 7-day unrouted purge through the W-path when ledger work exists.
    pub(crate) fn trim_expired_unrouted(&self, at: i64) -> Result<(), StorageError> {
        let cutoff = at.saturating_sub(7 * 24 * 60 * 60);
        let mut query = self
            .connection
            .prepare("SELECT envelope_id FROM runtime_unrouted WHERE received_at<?1")?;
        let ids = query
            .query_map(params![cutoff], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(query);
        for id in ids {
            if !self.try_settle_admission(&id, ReceiveFailureReason::HeldExpired, at)?
                && !self.has_staged_only_admission(&id)?
            {
                self.connection
                    .execute("DELETE FROM runtime_unrouted WHERE envelope_id=?1", params![id])?;
            }
        }
        Ok(())
    }

    /// Oldest-first 64-cap unrouted eviction through the W-path when ledger work exists.
    pub(crate) fn trim_overflow_unrouted(&self, at: i64) -> Result<(), StorageError> {
        let mut query = self.connection.prepare(
            "SELECT envelope_id FROM runtime_unrouted
             ORDER BY received_at DESC,inbox_seq DESC,envelope_id DESC LIMIT -1 OFFSET 63",
        )?;
        let ids = query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(query);
        for id in ids {
            if !self.try_settle_admission(&id, ReceiveFailureReason::HeldEvicted, at)? {
                self.connection
                    .execute("DELETE FROM runtime_unrouted WHERE envelope_id=?1", params![id])?;
            }
        }
        Ok(())
    }

    fn try_settle_admission(
        &self,
        key: &str,
        reason: ReceiveFailureReason,
        at: i64,
    ) -> Result<bool, StorageError> {
        if !self.receive_ledger_present()? {
            return Ok(false);
        }
        self.settle_admission(key, reason, at)
    }

    /// True when `key` has ledger work but none of it is held or quarantined (only staged work).
    /// Hold expiry and unrouted trim must leave such keys untouched.
    pub(crate) fn has_staged_only_admission(&self, key: &str) -> Result<bool, StorageError> {
        if !self.receive_ledger_present()? {
            return Ok(false);
        }
        let any: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_receive_work WHERE admission_key=?1)",
            params![key],
            |row| row.get(0),
        )?;
        Ok(any && self.admission_work(key, true)?.is_empty())
    }

    fn admission_work(
        &self,
        key: &str,
        held_only: bool,
    ) -> Result<Vec<(String, String, u64)>, StorageError> {
        if !self.receive_ledger_present()? {
            return Ok(Vec::new());
        }
        let mut query = self.connection.prepare(
            "SELECT w.target_delivery_id,w.incarnation_id,w.inbox_seq FROM gateway_receive_work w
             WHERE w.admission_key=?1
               AND (?2=0 OR EXISTS(
                 SELECT 1 FROM gateway_receive_receipt r
                 WHERE r.target_delivery_id=w.target_delivery_id
                   AND r.incarnation_id=w.incarnation_id
                   AND r.inbox_seq=w.inbox_seq
                   AND r.disposition IN ('held','quarantined')))
             ORDER BY w.target_delivery_id,w.incarnation_id,w.inbox_seq",
        )?;
        let rows = query.query_map(params![key, i64::from(held_only)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (target, incarnation, seq) = row?;
            let sequence = u64::from_be_bytes(
                seq.try_into().map_err(|_| StorageError::Integrity("receive sequence encoding"))?,
            );
            out.push((target, incarnation, sequence));
        }
        Ok(out)
    }
}

fn before_commit() -> Result<(), StorageError> {
    if current_fault() == Fault::BeforeCommit {
        return Err(StorageError::Integrity("receive failure before-commit"));
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
