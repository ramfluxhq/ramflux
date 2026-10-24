// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic task projections and bounded private task state reads.
use super::AccountDb;
use crate::StorageError;
use rusqlite::params;
impl AccountDb {
    /// Deletes a private task delivery or holdback job after completion or expiry.
    /// # Errors
    /// Rejects keys outside task delivery/holdback or returns database errors.
    pub fn delete_task_state(&self, key: &str) -> Result<(), StorageError> {
        if !(key.starts_with("task/pending/")
            || key.starts_with("task/ack/")
            || key.starts_with("task/forward/"))
        {
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
    /// Returns count and byte usage for one private task namespace.
    /// # Errors
    /// Rejects non-task namespaces and returns database errors.
    pub fn task_state_usage(&self, prefix: &str) -> Result<(u64, u64), StorageError> {
        if !prefix.starts_with("task/") {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(self.connection.query_row("SELECT count(*),coalesce(sum(length(state_json)),0) FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1",params![prefix],|r|Ok((r.get(0)?,r.get(1)?)))?)
    }
    /// Retains a bounded diagnostic/rate ledger without removing accepted event receipts.
    /// # Errors
    /// Rejects other namespaces and returns database errors.
    pub fn prune_task_diagnostics(&self, prefix: &str, retain: u32) -> Result<(), StorageError> {
        if !matches!(prefix, "task/rejected/" | "task/rate/" | "task/ack_sent/") {
            return Err(StorageError::AuthorizationRejected);
        }
        self.connection.execute("DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 ORDER BY coalesce(json_extract(CAST(state_json AS TEXT),'$.start'),rowid) DESC,state_kind DESC LIMIT -1 OFFSET ?2)",params![prefix,retain.clamp(1,2048)])?;
        Ok(())
    }
}
