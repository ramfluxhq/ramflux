// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic task projections and bounded private task state reads.
use super::AccountDb;
use crate::StorageError;
use rusqlite::params;
impl AccountDb {
    /// Applies a synchronous task phase atomically, including inside receive transactions.
    /// # Errors
    /// Rolls back the complete phase on callback or database failure.
    pub fn task_transaction<T, E>(&self, apply: impl FnOnce() -> Result<T, E>) -> Result<T, E>
    where
        E: From<StorageError>,
    {
        self.connection.execute_batch("SAVEPOINT task_projection").map_err(StorageError::from)?;
        match apply() {
            Ok(value) => {
                if let Err(error) = self.connection.execute_batch("RELEASE task_projection") {
                    self.connection
                        .execute_batch("ROLLBACK TO task_projection; RELEASE task_projection")
                        .map_err(StorageError::from)?;
                    return Err(StorageError::from(error).into());
                }
                Ok(value)
            }
            Err(error) => {
                self.connection
                    .execute_batch("ROLLBACK TO task_projection; RELEASE task_projection")
                    .map_err(StorageError::from)?;
                Err(error)
            }
        }
    }
    /// Deletes a private task transport job after delivery or expiry.
    /// # Errors
    /// Rejects non-transport keys or returns database errors.
    pub fn delete_task_state(&self, key: &str) -> Result<(), StorageError> {
        if !key.starts_with("task/transport/") {
            return Err(StorageError::AuthorizationRejected);
        }
        self.connection
            .execute("DELETE FROM runtime_actor_state WHERE state_kind=?1", params![key])?;
        Ok(())
    }
    /// Reads at most 101 account-owned task rows after an opaque key cursor.
    /// # Errors
    /// Returns database/decoding errors or rejects a non-task prefix.
    pub fn task_record_page<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
        after: &str,
        limit: u32,
    ) -> Result<Vec<(String, T)>, StorageError> {
        if !prefix.starts_with("task/") {
            return Err(StorageError::AuthorizationRejected);
        }
        let mut query=self.connection.prepare("SELECT state_kind,state_json FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 AND state_kind>?2 ORDER BY state_kind LIMIT ?3")?;
        let rows = query.query_map(params![prefix, after, limit.clamp(1, 101)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|row| {
            let (key, bytes) = row?;
            Ok((key, serde_json::from_slice(&bytes)?))
        })
        .collect()
    }
}
