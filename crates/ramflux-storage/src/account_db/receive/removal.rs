// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Terminal hold removal and failure-policy admission. Every removal joins W2/WS through
//! `finish_terminal` / `cleanup_settled`. Dormant until the actor wires it in P20.
use super::ReceiveTransaction;
use super::settle::{ReceiveSettle, ReceiveSettleKind, ReceiveSettleResult};
use crate::{AccountDb, ProjectionStore, StorageError};
use rusqlite::{OptionalExtension, params};

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
        if !self.db.apply_inbox_failure_policy(
            input.admission_key,
            input.entry,
            crate::InboxFailurePolicy {
                verified_source: None,
                trusted: false,
                dependency: ("none", ""),
                at: input.at,
            },
        )? {
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

    /// Expires held work whose policy or `retain_until` is due, including contact holds.
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
        let mut query = self.db.connection.prepare(
            "SELECT w.inbox_seq FROM gateway_receive_work w
             JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq)
             LEFT JOIN runtime_inbox_policy p ON p.envelope_key=w.admission_key
             WHERE w.target_delivery_id=?1 AND w.incarnation_id=?2
               AND r.disposition IN ('held','quarantined','staged')
               AND (r.retain_until<=?3 OR (p.expires_at IS NOT NULL AND p.expires_at<=?3))
             ORDER BY r.first_seen,w.inbox_seq",
        )?;
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

    /// Settles ledger work for `admission_key` through WS/W2. Returns false when none exists.
    ///
    /// # Errors
    /// Returns settle, fence or SQL errors.
    pub(crate) fn settle_admission(
        &self,
        key: &str,
        reason: ReceiveFailureReason,
        at: i64,
    ) -> Result<bool, StorageError> {
        let Some((target, incarnation, sequence)) = self.admission_work(key)? else {
            return Ok(false);
        };
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
            if !self.try_settle_admission(&id, ReceiveFailureReason::HeldExpired, at)? {
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

    fn admission_work(&self, key: &str) -> Result<Option<(String, String, u64)>, StorageError> {
        if !self.receive_ledger_present()? {
            return Ok(None);
        }
        let row: Option<(String, String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT target_delivery_id,incarnation_id,inbox_seq FROM gateway_receive_work
                 WHERE admission_key=?1",
                params![key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((target, incarnation, seq)) = row else {
            return Ok(None);
        };
        let sequence = u64::from_be_bytes(
            seq.try_into().map_err(|_| StorageError::Integrity("receive sequence encoding"))?,
        );
        Ok(Some((target, incarnation, sequence)))
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
