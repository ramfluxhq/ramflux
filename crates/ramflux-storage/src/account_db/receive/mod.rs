// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant receive-ledger schema and transaction authority; activation is a separate step.
pub(crate) mod ack;
#[cfg(test)]
mod ack_tests;
pub(crate) mod activation;
#[cfg(test)]
mod activation_tests;
#[cfg(test)]
mod application_outbox_backup_tests;
#[cfg(test)]
mod compat_backup_tests;
pub(crate) mod cover;
#[cfg(test)]
mod cover_tests;
pub(crate) mod erased_capture;
#[cfg(test)]
mod erased_capture_tests;
pub(crate) mod erased_input;
#[cfg(test)]
mod erased_input_guard_tests;
#[cfg(test)]
mod erased_input_inventory_tests;
#[cfg(test)]
mod erased_input_lifecycle_tests;
#[cfg(test)]
mod erased_input_producers_tests;
#[cfg(test)]
mod erased_input_tests;
#[cfg(test)]
mod erased_input_union_tests;
pub(crate) mod hold;
#[cfg(test)]
mod hold_tests;
pub(crate) mod ledger_backup;
pub(crate) mod loss;
#[cfg(test)]
mod loss_tests;
pub(crate) mod migrate;
#[cfg(test)]
mod migrate_tests;
pub(crate) mod page;
#[cfg(test)]
mod page_tests;
pub(crate) mod privacy;
#[cfg(test)]
mod privacy_restore_tests;
#[cfg(test)]
mod privacy_tests;
pub(crate) mod removal;
#[cfg(test)]
mod removal_tests;
#[cfg(test)]
mod reply_outbox_backup_tests;
pub(crate) mod reset;
#[cfg(test)]
mod reset_tests;
pub(crate) mod schema;
pub(crate) mod settle;
#[cfg(test)]
mod settle_tests;
mod source_gate;
#[cfg(any(test, feature = "test-instrumentation"))]
pub use source_gate::ReceiveLedgerSnap;
pub(crate) mod stage;
#[cfg(test)]
mod stage_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod w0_replay_support;

use crate::{AccountDb, ProjectionStore, StorageError};
use rusqlite::OptionalExtension;
use std::sync::atomic::{AtomicU64, Ordering};

static RECEIVE_TX_ID: AtomicU64 = AtomicU64::new(1);

/// Expected actor and durable state for one ledger writer phase.
#[derive(Clone, Copy, Debug)]
pub struct ReceiveExpectation<'a> {
    pub target: &'a str,
    pub incarnation: &'a str,
    pub cursor: u64,
    pub generation: u64,
    pub erasure_generation: i64,
}

/// One open W0/W1 recovery input (staged or held receipt plus its work row).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryInput {
    pub sequence: u64,
    pub disposition: String,
    /// Normalized authenticated entry bytes staged by W0; the redrive source of truth.
    pub entry_json: Vec<u8>,
}

/// Unforgeable authority scoped to an account's immediate writer transaction.
pub struct ReceiveTransaction<'a> {
    db: &'a AccountDb,
    target: &'a str,
    incarnation: &'a str,
    /// True when the fence admitted a name in `retired_incarnations`, not the live E.
    retired: bool,
    /// Unique id for this writer phase; SDK tokens bind to it.
    tx_id: u64,
}

/// Cover and stage refuse a retired incarnation with this exact error.
pub(crate) const RETIRED_INCARNATION: &str = "retired incarnation is local recovery only";

impl ReceiveTransaction<'_> {
    /// Confirms that authority is still inside the account writer transaction.
    /// # Errors
    /// Refuses use after an unexpected transaction completion.
    pub fn require_writer(&self) -> Result<(), StorageError> {
        if self.db.connection.is_autocommit()? {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(())
    }

    /// Account writer this fence is bound to. W1 joiners and `*_in(tx)` adapters persist through this handle.
    #[must_use]
    pub fn account(&self) -> &AccountDb {
        self.db
    }

    /// Cover and stage refuse a retired incarnation. Source gate and bind allow retained work.
    ///
    /// # Errors
    /// Returns the exact retired-incarnation integrity error.
    pub(crate) fn refuse_retired(&self) -> Result<(), StorageError> {
        if self.retired {
            return Err(StorageError::Integrity(RETIRED_INCARNATION));
        }
        Ok(())
    }

    /// Marks staged recovery input held without advancing C. Capacity refusal uses this so W0
    /// stays until a later W2/WS.
    ///
    /// # Errors
    /// Requires the writer transaction; returns SQL errors.
    pub fn hold_receipt(&self, sequence: u64) -> Result<(), StorageError> {
        self.require_writer()?;
        let seq = sequence.to_be_bytes();
        self.db.connection.execute(
            "UPDATE gateway_receive_receipt SET disposition='held'
             WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3
               AND disposition IN ('staged','held')",
            rusqlite::params![self.target, self.incarnation, seq.as_slice()],
        )?;
        Ok(())
    }

    /// Live receive cursor C for this target. Requires the open writer transaction.
    ///
    /// # Errors
    /// [`StorageError::AuthorizationRejected`] when the writer is closed or C is not a u64.
    pub fn receive_cursor(&self) -> Result<u64, StorageError> {
        self.require_writer()?;
        self.db
            .projection_checkpoint(&format!("gateway_receive_cursor:{}", self.target))?
            .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))
    }

    /// Writes C inside the open receive transaction. SDK token checks live in the executor.
    ///
    /// # Errors
    /// [`StorageError::AuthorizationRejected`] when the writer is closed; storage errors from the write.
    pub fn persist_receive_cursor(&self, seq: u64) -> Result<(), StorageError> {
        self.require_writer()?;
        self.db.set_projection_checkpoint(
            &format!("gateway_receive_cursor:{}", self.target),
            &seq.to_string(),
        )
    }

    /// Identifies this writer phase so SDK tokens cannot move to another transaction.
    #[must_use]
    pub const fn writer_id(&self) -> u64 {
        self.tx_id
    }

    /// Hold-table delete inside the open receive transaction.
    ///
    /// # Errors
    /// [`StorageError::AuthorizationRejected`] when the writer is closed; storage errors from the delete.
    pub fn remove_unrouted(&self, id: &str) -> Result<(), StorageError> {
        self.require_writer()?;
        self.db.remove_unrouted(id)
    }

    /// Open staged or held receipt+work rows for this (T,E). Disk is the only recovery source.
    ///
    /// # Errors
    /// Requires the writer transaction; returns SQL and sequence-encoding errors.
    pub fn recovery_inputs(&self) -> Result<Vec<RecoveryInput>, StorageError> {
        self.require_writer()?;
        let mut statement = self.db.connection.prepare(
            "SELECT r.inbox_seq, r.disposition, w.entry_json FROM gateway_receive_receipt r
             JOIN gateway_receive_work w
               ON w.target_delivery_id=r.target_delivery_id
              AND w.incarnation_id=r.incarnation_id
              AND w.inbox_seq=r.inbox_seq
             WHERE r.target_delivery_id=?1 AND r.incarnation_id=?2
               AND r.disposition IN ('staged','held')
             ORDER BY r.inbox_seq",
        )?;
        let rows =
            statement.query_map(rusqlite::params![self.target, self.incarnation], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))
            })?;
        let mut inputs = Vec::new();
        for row in rows {
            let (seq, disposition, entry_json) = row?;
            let sequence = u64::from_be_bytes(
                seq.try_into().map_err(|_| StorageError::Integrity("receive sequence encoding"))?,
            );
            inputs.push(RecoveryInput { sequence, disposition, entry_json });
        }
        Ok(inputs)
    }
}

impl AccountDb {
    /// Live incarnation for `target`, or `None` when the ledger is unactivated (no table or row).
    ///
    /// # Errors
    /// Returns storage errors other than a missing table or missing row.
    pub fn receive_epoch(&self, target: &str) -> Result<Option<String>, StorageError> {
        use rusqlite::OptionalExtension;
        let exists: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='gateway_receive_epoch')",
            [],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Ok(None);
        }
        Ok(self
            .connection
            .query_row(
                "SELECT incarnation_id FROM gateway_receive_epoch WHERE target_delivery_id=?1",
                rusqlite::params![target],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Executes a ledger phase under generation, incarnation, cursor and erasure fences.
    /// The actor supplies its current generation; the closure performs no network I/O.
    /// # Errors
    /// Rejects stale authority before effects; callback and commit errors roll back the phase.
    pub fn receive_transaction<T>(
        &self,
        expected: ReceiveExpectation<'_>,
        current_generation: u64,
        write: impl FnOnce(&ReceiveTransaction<'_>) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.write_transaction(|| {
            if current_generation != expected.generation {
                return Err(StorageError::AuthorizationRejected);
            }
            if self.privacy_erasure_generation()? != expected.erasure_generation {
                return Err(StorageError::ObjectErased);
            }
            let (incarnation, retired_blob): (String, Vec<u8>) = self.connection.query_row(
                "SELECT incarnation_id, retired_incarnations FROM gateway_receive_epoch WHERE target_delivery_id=?1",
                rusqlite::params![expected.target],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let retired = retired_incarnations(&retired_blob)?;
            let cursor = self
                .projection_checkpoint(&format!("gateway_receive_cursor:{}", expected.target))?
                .map_or(Ok(0), |s| {
                    s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected)
                })?;
            let named = expected.incarnation == incarnation
                || retired.iter().any(|was| was == expected.incarnation);
            if !named || cursor != expected.cursor {
                return Err(StorageError::AuthorizationRejected);
            }
            let authority = ReceiveTransaction {
                db: self,
                target: expected.target,
                incarnation: expected.incarnation,
                retired: expected.incarnation != incarnation,
                tx_id: RECEIVE_TX_ID.fetch_add(1, Ordering::Relaxed),
            };
            let value = write(&authority)?;
            authority.require_writer()?;
            if self.privacy_erasure_generation()? != expected.erasure_generation {
                return Err(StorageError::ObjectErased);
            }
            Ok(value)
        })
    }

    /// Read-only startup incarnation E and cursor C. Never writes max into C.
    ///
    /// # Errors
    /// [`StorageError::AuthorizationRejected`] when the stored checkpoint is not a u64;
    /// storage errors from the epoch lookup.
    pub fn receive_startup(&self, target: &str) -> Result<(String, u64), StorageError> {
        let incarnation = self
            .connection
            .query_row(
                "SELECT incarnation_id FROM gateway_receive_epoch WHERE target_delivery_id=?1",
                rusqlite::params![target],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_default();
        let cursor = self
            .projection_checkpoint(&format!("gateway_receive_cursor:{target}"))?
            .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))?;
        Ok((incarnation, cursor))
    }

    /// Committed receive counters for the manager snapshot. Missing tables count as zero.
    ///
    /// # Errors
    /// SQLite errors other than a missing table.
    pub fn receive_status_counters(
        &self,
        target: &str,
    ) -> Result<ReceiveStatusCounters, StorageError> {
        let count = |sql: &str| -> Result<u64, StorageError> {
            match self.connection.query_row(sql, rusqlite::params![target], |row| row.get(0)) {
                Ok(value) => Ok(value),
                Err(rusqlite::Error::SqliteFailure(code, _))
                    if code.code == rusqlite::ErrorCode::Unknown =>
                {
                    Ok(0)
                }
                Err(error) => Err(error.into()),
            }
        };
        let inbox_gaps_total =
            count("SELECT count(*) FROM gateway_inbox_loss WHERE target_delivery_id=?1")?;
        let legacy_unverified_total = count(
            "SELECT count(*) FROM gateway_inbox_loss WHERE target_delivery_id=?1 AND classification='legacy_unverified'",
        )?;
        let ack_intents_pending =
            count("SELECT count(*) FROM gateway_ack_intent WHERE target_delivery_id=?1")?;
        let held_entries = count(
            "SELECT count(*) FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND disposition='held'",
        )?;
        let held_evicted_total = match self.connection.query_row(
            "SELECT count(*) FROM runtime_journal WHERE topic='inbox.receive_failure' AND json_extract(CAST(body_json AS TEXT),'$.reason')='held_evicted'",
            [],
            |row| row.get(0),
        ) {
            Ok(value) => value,
            Err(rusqlite::Error::SqliteFailure(code, _))
                if code.code == rusqlite::ErrorCode::Unknown =>
            {
                0
            }
            Err(error) => return Err(error.into()),
        };
        let (incarnation, retired_blob, verified): (Option<String>, Option<Vec<u8>>, Option<i64>) =
            match self.connection.query_row(
                "SELECT incarnation_id, retired_incarnations, incarnation_verified FROM gateway_receive_epoch WHERE target_delivery_id=?1",
                rusqlite::params![target],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ) {
                Ok(row) => (Some(row.0), Some(row.1), Some(row.2)),
                Err(rusqlite::Error::QueryReturnedNoRows) => (None, None, None),
                Err(rusqlite::Error::SqliteFailure(code, _))
                    if code.code == rusqlite::ErrorCode::Unknown =>
                {
                    (None, None, None)
                }
                Err(error) => return Err(error.into()),
            };
        let inbox_resets_total = retired_blob
            .as_deref()
            .map(retired_incarnations)
            .transpose()?
            .map_or(0, |retired| u64::try_from(retired.len()).unwrap_or(u64::MAX));
        let incarnation_unverified = self.actor_state_usage("gateway/compat-suspended/")?.0;
        Ok(ReceiveStatusCounters {
            inbox_gaps_total,
            legacy_unverified_total,
            ack_intents_pending,
            held_entries,
            inbox_resets_total,
            held_evicted_total,
            incarnation_unverified,
            incarnation,
            incarnation_unverified_flag: verified == Some(0),
        })
    }
}

/// Committed receive counters the SDK snapshot copies.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReceiveStatusCounters {
    pub inbox_gaps_total: u64,
    pub legacy_unverified_total: u64,
    pub ack_intents_pending: u64,
    pub held_entries: u64,
    pub inbox_resets_total: u64,
    pub held_evicted_total: u64,
    pub incarnation_unverified: u64,
    pub incarnation: Option<String>,
    pub incarnation_unverified_flag: bool,
}

pub(crate) fn retired_incarnations(blob: &[u8]) -> Result<Vec<String>, StorageError> {
    if blob.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_slice(blob)
        .map_err(|_| StorageError::Integrity("retired incarnation encoding"))
}

pub(crate) const fn schema_version() -> i64 {
    schema::VERSION
}
