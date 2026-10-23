// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Nested atomic surface projections and bounded account-owned history reads.
use super::AccountDb;
use crate::StorageError;
use rusqlite::params;
impl AccountDb {
    /// Runs a surface update atomically inside or outside a receive transaction, without I/O.
    /// # Errors
    /// Rolls back all projection/receipt writes on any callback or SQLite failure.
    pub fn surface_transaction<T, E>(&self, write: impl FnOnce() -> Result<T, E>) -> Result<T, E>
    where
        E: From<StorageError>,
    {
        self.connection
            .execute_batch("SAVEPOINT surface_projection")
            .map_err(StorageError::from)?;
        match write() {
            Ok(value) => {
                if let Err(error) = self.connection.execute_batch("RELEASE surface_projection") {
                    let _ = self.connection.execute_batch(
                        "ROLLBACK TO surface_projection; RELEASE surface_projection",
                    );
                    return Err(StorageError::from(error).into());
                }
                Ok(value)
            }
            Err(error) => {
                self.connection
                    .execute_batch("ROLLBACK TO surface_projection; RELEASE surface_projection")
                    .map_err(StorageError::from)?;
                Err(error)
            }
        }
    }
    /// Replaces an authenticated surface carrier with its validated text fallback.
    /// # Errors
    /// Returns database errors. Conversation identity must match the stored row.
    pub fn replace_surface_message_content(
        &self,
        conversation: &str,
        message: &str,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.connection.execute("INSERT INTO runtime_message_content(message_id,conversation_id,body) VALUES(?1,?2,?3) ON CONFLICT(message_id) DO UPDATE SET body=excluded.body WHERE runtime_message_content.conversation_id=excluded.conversation_id", params![message,conversation,body])?;
        Ok(())
    }
    /// Private actor-state history page; callers must enforce their account/conversation scope.
    /// # Errors
    /// Returns SQL/JSON errors; pages never exceed 101 rows.
    pub fn surface_history_page<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
        after: &str,
        limit: u32,
    ) -> Result<Vec<T>, StorageError> {
        let mut query=self.connection.prepare("SELECT state_json FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 AND state_kind>?2 ORDER BY state_kind LIMIT ?3")?;
        query
            .query_map(params![prefix, after, limit.min(101)], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| Ok(serde_json::from_slice(&row?)?))
            .collect()
    }
}
