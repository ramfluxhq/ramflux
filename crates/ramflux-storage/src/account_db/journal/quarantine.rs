// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unbound legacy envelopes remain encrypted, bounded and never implicitly acknowledged.
use super::*;
impl AccountDb {
    /// Holds an unbound envelope without acknowledging it. Oldest entries are evicted at capacity.
    ///
    /// # Errors
    /// Returns storage errors or an oversized-entry rejection. Capacity is bounded by eviction.
    pub fn hold_unrouted(
        &self,
        id: &str,
        seq: u64,
        entry: &[u8],
        at: i64,
    ) -> Result<(), StorageError> {
        if entry.len() > 1024 * 1024 {
            return Err(StorageError::AuthorizationRejected);
        }
        self.write_transaction(|| {
            if let Some(marker) = self.inbox_envelope_marker(entry)?
                && self.actor_state_exists(&marker)?
            {
                return Ok(());
            }
            let exists: i64 = self.connection.query_row(
                "SELECT count(*) FROM runtime_unrouted WHERE envelope_id=?1",
                params![id],
                |row| row.get(0),
            )?;
            self.connection.execute("DELETE FROM runtime_unrouted WHERE received_at<?1",params![at.saturating_sub(7*24*60*60)])?;
            if exists == 0 {
                self.connection.execute("DELETE FROM runtime_unrouted WHERE envelope_id IN (SELECT envelope_id FROM runtime_unrouted ORDER BY received_at DESC,inbox_seq DESC,envelope_id DESC LIMIT -1 OFFSET 63)",[])?;
            }
            self.connection.execute(
                "INSERT OR IGNORE INTO runtime_unrouted VALUES(?1,?2,?3,?4)",
                params![id, seq, entry, at],
            )?;
            Ok(())
        })
    }
    /// # Errors
    /// Returns errors reading the bounded quarantine.
    pub fn unrouted_entries(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT entry_json FROM runtime_unrouted ORDER BY inbox_seq,envelope_id LIMIT 64",
        )?;
        Ok(statement.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// # Errors
    /// Returns SQL errors.
    pub fn unrouted_count(&self) -> Result<u64, StorageError> {
        Ok(self
            .connection
            .query_row("SELECT count(*) FROM runtime_unrouted", [], |row| row.get(0))?)
    }
    /// Removes a quarantine entry only after successful explicitly bound processing.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn remove_unrouted(&self, id: &str) -> Result<(), StorageError> {
        self.connection
            .execute("DELETE FROM runtime_unrouted WHERE envelope_id=?1", params![id])?;
        Ok(())
    }
}
