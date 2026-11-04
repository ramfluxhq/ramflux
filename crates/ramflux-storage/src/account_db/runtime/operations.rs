// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable account-scoped retry reservations and response receipts.

use super::super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};

/// Read-only disposition of an account-scoped operation key.
#[derive(Clone, Debug, PartialEq)]
pub enum OperationLookup {
    Absent,
    Completed(serde_json::Value),
    Pending,
    Mismatch,
}

impl AccountDb {
    /// Looks up a retry receipt without reserving a key or starting a write transaction.
    ///
    /// # Errors
    /// Returns a storage or decoding error if the saved receipt cannot be read.
    pub fn lookup_operation(
        &self,
        id: &str,
        fingerprint: &str,
    ) -> Result<OperationLookup, StorageError> {
        let existing: Option<(String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT fingerprint,response_json FROM runtime_operation WHERE operation_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(match existing {
            None => OperationLookup::Absent,
            Some((saved, _)) if saved != fingerprint => OperationLookup::Mismatch,
            Some((_, None)) => OperationLookup::Pending,
            Some((_, Some(response))) => {
                OperationLookup::Completed(serde_json::from_str(&response)?)
            }
        })
    }

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
            let response: serde_json::Value = serde_json::from_str(&response)?;
            if response.get("object_erased").and_then(serde_json::Value::as_bool) == Some(true) {
                return Err(StorageError::ObjectErased);
            }
            return Ok(Some(response));
        }
        self.connection.execute(
            "INSERT INTO runtime_operation(operation_id,fingerprint) VALUES(?1,?2)",
            params![id, fingerprint],
        )?;
        transaction.commit()?;
        Ok(None)
    }

    /// # Errors
    /// Binds a reserved operation to its payloads before effects, including payload-free responses.
    pub fn bind_operation_objects(
        &self,
        id: &str,
        request: &serde_json::Value,
    ) -> Result<(), StorageError> {
        self.register_object_response(id, request)
    }

    /// # Errors
    /// Returns an error if the committed mutation response cannot be saved for retries.
    pub fn complete_operation(
        &self,
        id: &str,
        response: &serde_json::Value,
    ) -> Result<(), StorageError> {
        let transaction = self.connection.immediate_transaction()?;
        if let Err(error) = self.register_object_response(id, response) {
            if matches!(error, StorageError::ObjectErased) {
                self.connection.execute("UPDATE runtime_operation SET response_json='{\"object_erased\":true}' WHERE operation_id=?1",params![id])?;
                transaction.commit()?;
            }
            return Err(error);
        }
        self.connection.execute(
            "UPDATE runtime_operation SET response_json=?2 WHERE operation_id=?1",
            params![id, serde_json::to_string(response)?],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lookup_operation_is_read_only_and_preserves_every_receipt_state() -> Result<(), StorageError>
    {
        let (root, db) = crate::tests::test_db("operation-lookup")?;
        let reader = db.open_reader()?;
        assert_eq!(reader.lookup_operation("new", "a")?, OperationLookup::Absent);
        assert_eq!(db.lookup_operation("new", "b")?, OperationLookup::Absent);
        assert_eq!(db.reserve_operation("new", "a")?, None);
        assert_eq!(reader.lookup_operation("new", "a")?, OperationLookup::Pending);
        assert_eq!(reader.lookup_operation("new", "b")?, OperationLookup::Mismatch);
        assert!(matches!(db.reserve_operation("new", "a"), Err(StorageError::EventIdConflict(_))));
        let response = json!({"value":"committed"});
        db.complete_operation("new", &response)?;
        assert_eq!(
            reader.lookup_operation("new", "a")?,
            OperationLookup::Completed(response.clone())
        );
        assert_eq!(db.reserve_operation("new", "a")?, Some(response));
        db.complete_operation("new", &json!({"object_erased":true}))?;
        assert_eq!(
            reader.lookup_operation("new", "a")?,
            OperationLookup::Completed(json!({"object_erased":true}))
        );
        assert!(matches!(db.reserve_operation("new", "a"), Err(StorageError::ObjectErased)));
        drop(reader);
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
