// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant receive-ledger schema and transaction authority; activation is a separate step.
#[cfg(test)]
mod application_outbox_backup_tests;
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

/// Expected actor and durable state for one ledger writer phase.
#[derive(Clone, Copy, Debug)]
pub struct ReceiveExpectation<'a> {
    pub target: &'a str,
    pub incarnation: &'a str,
    pub cursor: u64,
    pub generation: u64,
    pub erasure_generation: i64,
}

/// Unforgeable authority scoped to an account's immediate writer transaction.
pub struct ReceiveTransaction<'a> {
    db: &'a AccountDb,
    target: &'a str,
    incarnation: &'a str,
    /// True when the fence admitted a name in `retired_incarnations`, not the live E.
    retired: bool,
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
