// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable account-scoped retry reservations and response receipts.

use super::super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};

impl AccountDb {
    /// Reserves a mutation key before effects. A pending receipt fails closed after a crash.
    ///
    /// # Errors
    /// Rejects conflicting payloads and pending operations that require reconciliation.
    pub fn reserve_operation(
        &self,
        id: &str,
        fingerprint: &str,
    ) -> Result<Option<serde_json::Value>, StorageError> {
        let transaction = self.connection.immediate_transaction()?;
        let existing: Option<(String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT fingerprint,response_json FROM runtime_operation WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((saved, response)) = existing {
            if saved != fingerprint {
                return Err(StorageError::EventIdConflict(id.to_owned()));
            }
            let response = response.ok_or_else(|| {
                StorageError::EventIdConflict(format!("operation requires reconciliation: {id}"))
            })?;
            transaction.commit()?;
            return Ok(Some(serde_json::from_str(&response)?));
        }
        self.connection.execute(
            "INSERT INTO runtime_operation(operation_id,fingerprint) VALUES(?1,?2)",
            params![id, fingerprint],
        )?;
        transaction.commit()?;
        Ok(None)
    }

    /// # Errors
    /// Returns an error if the committed mutation response cannot be saved for retries.
    pub fn complete_operation(
        &self,
        id: &str,
        response: &serde_json::Value,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE runtime_operation SET response_json=?2 WHERE operation_id=?1",
            params![id, serde_json::to_string(response)?],
        )?;
        Ok(())
    }
}
