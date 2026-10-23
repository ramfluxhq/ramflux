// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Supervisor metadata receipts remain available while encrypted account DBs are locked.

use super::AccountIndex;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};

impl AccountIndex {
    pub(super) fn install_operation_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS supervisor_operation (
            account_scope TEXT NOT NULL, operation_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
            response_json TEXT, PRIMARY KEY(account_scope,operation_id)
        );",
        )?;
        Ok(())
    }

    /// # Errors
    /// Rejects changed intent and incomplete operations that require reconciliation.
    pub fn reserve_supervisor_operation(
        &self,
        scope: &str,
        operation: &str,
        fingerprint: &str,
    ) -> Result<Option<serde_json::Value>, StorageError> {
        let transaction = self.connection.unchecked_transaction()?;
        let saved: Option<(String,Option<String>)> = self.connection.query_row(
            "SELECT fingerprint,response_json FROM supervisor_operation WHERE account_scope=?1 AND operation_id=?2",
            params![scope,operation], |row| Ok((row.get(0)?,row.get(1)?))
        ).optional()?;
        if let Some((saved, response)) = saved {
            if saved != fingerprint {
                return Err(StorageError::EventIdConflict(operation.to_owned()));
            }
            let response = response.ok_or_else(|| {
                StorageError::EventIdConflict(format!(
                    "operation requires reconciliation: {operation}"
                ))
            })?;
            transaction.commit()?;
            return Ok(Some(serde_json::from_str(&response)?));
        }
        self.connection.execute("INSERT INTO supervisor_operation(account_scope,operation_id,fingerprint) VALUES(?1,?2,?3)",params![scope,operation,fingerprint])?;
        transaction.commit()?;
        Ok(None)
    }

    /// # Errors
    /// Returns an error if a metadata response cannot be durably saved for retries.
    pub fn complete_supervisor_operation(
        &self,
        scope: &str,
        operation: &str,
        response: &serde_json::Value,
    ) -> Result<(), StorageError> {
        self.connection.execute("UPDATE supervisor_operation SET response_json=?3 WHERE account_scope=?1 AND operation_id=?2", params![scope,operation,serde_json::to_string(response)?])?;
        Ok(())
    }

    /// # Errors
    /// Returns an error if the supervisor cannot persist the account's explicit lock state.
    pub fn set_account_unlocked(
        &self,
        account_id: &str,
        unlocked: bool,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE local_account SET account_state=?2 WHERE local_account_id=?1",
            params![account_id, if unlocked { "active" } else { "locked" }],
        )?;
        Ok(())
    }
}
