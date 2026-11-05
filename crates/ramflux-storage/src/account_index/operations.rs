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

    /// Looks up a lifecycle receipt without reserving or modifying it.
    ///
    /// # Errors
    /// Returns database or response decoding errors.
    pub fn lookup_supervisor_operation(
        &self,
        scope: &str,
        operation: &str,
        fingerprint: &str,
    ) -> Result<crate::OperationLookup, StorageError> {
        let saved: Option<(String, Option<String>)> = self.connection.query_row(
            "SELECT fingerprint,response_json FROM supervisor_operation WHERE account_scope=?1 AND operation_id=?2",
            params![scope,operation], |row| Ok((row.get(0)?,row.get(1)?))
        ).optional()?;
        Ok(match saved {
            None => crate::OperationLookup::Absent,
            Some((saved, _)) if saved != fingerprint => crate::OperationLookup::Mismatch,
            Some((_, None)) => crate::OperationLookup::Pending,
            Some((_, Some(response))) => {
                crate::OperationLookup::Completed(serde_json::from_str(&response)?)
            }
        })
    }

    /// Validates a pending receipt for takeover by the supervisor's exclusive live holder.
    /// No row rewrite or schema upgrade is needed: the in-memory registry owns execution.
    ///
    /// # Errors
    /// Rejects absent, completed or mismatched receipts, and database failures.
    pub fn take_over_supervisor_operation(
        &self,
        scope: &str,
        operation: &str,
        fingerprint: &str,
    ) -> Result<(), StorageError> {
        let transaction = self.connection.immediate_transaction()?;
        if !matches!(
            self.lookup_supervisor_operation(scope, operation, fingerprint)?,
            crate::OperationLookup::Pending
        ) {
            return Err(StorageError::EventIdConflict(operation.to_owned()));
        }
        transaction.commit()?;
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
        let transaction = self.connection.immediate_transaction()?;
        let saved: Option<(String,Option<String>)> = self.connection.query_row(
            "SELECT fingerprint,response_json FROM supervisor_operation WHERE account_scope=?1 AND operation_id=?2",
            params![scope,operation], |row| Ok((row.get(0)?,row.get(1)?))
        ).optional()?;
        if let Some((saved, response)) = saved {
            if saved != fingerprint {
                return Err(StorageError::EventIdConflict(operation.to_owned()));
            }
            let response = response.ok_or_else(|| {
                StorageError::OperationReconciliationRequired { key: operation.to_owned() }
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

impl AccountIndex {
    /// Lists all known account ids, including explicitly locked accounts.
    ///
    /// # Errors
    /// Returns errors querying the index.
    pub fn known_account_ids(&self) -> Result<Vec<String>, StorageError> {
        let mut statement = self
            .connection
            .prepare("SELECT local_account_id FROM local_account ORDER BY local_account_id")?;
        Ok(statement.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperationLookup;
    type Case = Result<(), Box<dyn std::error::Error>>;
    fn root() -> Result<std::path::PathBuf, std::time::SystemTimeError> {
        Ok(std::env::temp_dir().join(format!(
            "supervisor-lookup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        )))
    }
    #[test]
    fn typed_lookup_reports_absent_completed_pending_mismatch() -> Case {
        let root = root()?;
        let index = AccountIndex::open(&root)?;
        assert!(matches!(
            index.lookup_supervisor_operation("alice", "key", "fp")?,
            OperationLookup::Absent
        ));
        assert!(index.reserve_supervisor_operation("alice", "key", "fp")?.is_none());
        assert!(matches!(
            index.lookup_supervisor_operation("alice", "key", "fp")?,
            OperationLookup::Pending
        ));
        assert!(matches!(
            index.lookup_supervisor_operation("alice", "key", "other")?,
            OperationLookup::Mismatch
        ));
        index.take_over_supervisor_operation("alice", "key", "fp")?;
        let body = serde_json::json!({"state":"unlocked"});
        index.complete_supervisor_operation("alice", "key", &body)?;
        assert!(
            matches!(index.lookup_supervisor_operation("alice", "key", "fp")?, OperationLookup::Completed(saved) if saved == body)
        );
        assert!(index.take_over_supervisor_operation("alice", "key", "fp").is_err());
        assert!(index.take_over_supervisor_operation("alice", "missing", "fp").is_err());
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn takeover_with_a_different_fingerprint_is_refused() -> Case {
        let root = root()?;
        let index = AccountIndex::open(&root)?;
        index.reserve_supervisor_operation("alice", "key", "fp")?;
        assert!(matches!(
            index.take_over_supervisor_operation("alice", "key", "other"),
            Err(StorageError::EventIdConflict(_))
        ));
        assert!(matches!(
            index.lookup_supervisor_operation("alice", "key", "fp")?,
            OperationLookup::Pending
        ));
        assert!(matches!(
            index.lookup_supervisor_operation("alice", "key", "other")?,
            OperationLookup::Mismatch
        ));
        // Existing reserve remains fail-closed for pending receipts.
        assert!(
            matches!(index.reserve_supervisor_operation("alice", "key", "fp"), Err(StorageError::OperationReconciliationRequired { key }) if key == "key")
        );
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
