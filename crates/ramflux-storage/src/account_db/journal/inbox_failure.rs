// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded encrypted dead letters and independently retried transient inbox failures.
use super::*;
const MAX_AGE: i64 = 7 * 24 * 60 * 60;
impl AccountDb {
    /// Removes expired holds and terminally records expired retries without acknowledging v1.
    /// # Errors
    /// Returns SQL or journal serialization errors.
    pub fn expire_inbox_holds(&self, at: i64) -> Result<(), StorageError> {
        self.write_transaction(|| {
            let floor=at.saturating_sub(MAX_AGE);
            let mut query=self.connection.prepare("SELECT envelope_key,entry_json FROM runtime_inbox_retry WHERE created_at<?1 LIMIT 64")?;
            let expired=query.query_map(params![floor],|row|Ok((row.get::<_,String>(0)?,row.get::<_,Vec<u8>>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            drop(query);
            for (key,entry) in expired {self.insert_inbox_dead_letter(&key,&entry,&serde_json::json!({"retry_key":key,"error_code":"retry_expired"}),at)?;}
            self.connection.execute("DELETE FROM runtime_unrouted WHERE received_at<?1",params![floor])?;
            self.connection.execute("DELETE FROM runtime_inbox_dead_letter WHERE received_at<?1",params![floor])?;
            Ok(())
        })
    }
    /// Durably records rejected ciphertext and terminal metadata before network ACK.
    /// # Errors
    /// Returns SQL/serialization errors. Oversized raw entries retain metadata only.
    pub fn dead_letter_inbox(
        &self,
        key: &str,
        entry: &[u8],
        metadata: &serde_json::Value,
        at: i64,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| self.insert_inbox_dead_letter(key, entry, metadata, at))
    }
    fn insert_inbox_dead_letter(
        &self,
        key: &str,
        entry: &[u8],
        metadata: &serde_json::Value,
        at: i64,
    ) -> Result<(), StorageError> {
        let bounded = if entry.len() <= 1024 * 1024 { entry } else { &[] };
        self.connection.execute(
            "INSERT OR IGNORE INTO runtime_inbox_dead_letter VALUES(?1,?2,?3,?4)",
            params![
                key,
                bounded,
                metadata.get("error_code").and_then(serde_json::Value::as_str),
                at
            ],
        )?;
        self.connection.execute("DELETE FROM runtime_inbox_dead_letter WHERE envelope_key IN (SELECT envelope_key FROM runtime_inbox_dead_letter ORDER BY received_at DESC,rowid DESC LIMIT -1 OFFSET 64)",[])?;
        self.connection.execute(
            "DELETE FROM runtime_inbox_dead_letter WHERE received_at<?1",
            params![at.saturating_sub(MAX_AGE)],
        )?;
        self.insert_journal(
            &format!("undeliverable:{key}"),
            "message.undeliverable",
            metadata,
            at,
            None,
        )?;
        self.connection
            .execute("DELETE FROM runtime_inbox_retry WHERE envelope_key=?1", params![key])?;
        Ok(())
    }
    /// Queues transient work without blocking later inbox entries; evictions emit terminal events.
    /// # Errors
    /// Returns SQL/serialization errors or rejects entries above the one-MiB bound.
    pub fn defer_inbox_entry(&self, key: &str, entry: &[u8], at: i64) -> Result<u32, StorageError> {
        if entry.len() > 1024 * 1024 {
            return Err(StorageError::AuthorizationRejected);
        }
        self.write_transaction(|| {
            self.connection.execute("INSERT INTO runtime_inbox_retry VALUES(?1,?2,1,?3,?4) ON CONFLICT(envelope_key) DO UPDATE SET attempts=attempts+1,next_at=?4+min(64,(1 << min(attempts+1,6)))",params![key,entry,at.saturating_add(2),at])?;
            let attempts=self.connection.query_row("SELECT attempts FROM runtime_inbox_retry WHERE envelope_key=?1",params![key],|row|row.get(0))?;
            let mut query=self.connection.prepare("SELECT envelope_key,entry_json FROM runtime_inbox_retry ORDER BY created_at DESC,rowid DESC LIMIT -1 OFFSET 64")?;
            let evicted=query.query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,Vec<u8>>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            drop(query);
            for (old_key,old_entry) in evicted {self.insert_inbox_dead_letter(&old_key,&old_entry,&serde_json::json!({"retry_key":old_key,"error_code":"retry_capacity"}),at)?;}
            Ok(attempts)
        })
    }
    /// Checks the retry deadline even if a peer redelivers an entry before its backoff expires.
    /// # Errors
    /// Returns SQL errors.
    pub fn inbox_retry_ready(&self, key: &str, at: i64) -> Result<bool, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT next_at<=?2 FROM runtime_inbox_retry WHERE envelope_key=?1",
                params![key, at],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(true))
    }
    /// Reads a bounded due retry page without any projection or private-key material.
    /// # Errors
    /// Returns SQL errors.
    pub fn due_inbox_retries(&self, at: i64) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut query=self.connection.prepare("SELECT entry_json FROM runtime_inbox_retry WHERE next_at<=?1 ORDER BY created_at,envelope_key LIMIT 64")?;
        Ok(query.query_map(params![at], |row| row.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Clears a retry only after durable successful processing.
    /// # Errors
    /// Returns SQL errors.
    pub fn remove_inbox_retry(&self, key: &str) -> Result<(), StorageError> {
        self.connection
            .execute("DELETE FROM runtime_inbox_retry WHERE envelope_key=?1", params![key])?;
        Ok(())
    }
}

impl AccountDb {
    /// Returns whether the packet has durable pending retry work.
    /// # Errors
    /// Returns SQLite errors.
    pub fn has_inbox_retry(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM runtime_inbox_retry WHERE envelope_key=?1)",
            params![key],
            |row| row.get(0),
        )?)
    }
    /// Requeues retained ciphertext and wakes state-dependent work after membership/identity changes.
    /// # Errors
    /// Returns SQL/serialization errors. All work remains within existing queue bounds.
    pub fn redrive_inbox_dead_letters(&self, at: i64) -> Result<usize, StorageError> {
        self.write_transaction(|| {
            let mut query = self.connection.prepare("SELECT envelope_key,entry_json FROM runtime_inbox_dead_letter WHERE length(entry_json)>0 ORDER BY received_at LIMIT (SELECT max(0,64-count(*)) FROM runtime_inbox_retry)")?;
            let rows = query.query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,Vec<u8>>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            drop(query);
            for (key,entry) in &rows {
                self.connection.execute("DELETE FROM runtime_inbox_dead_letter WHERE envelope_key=?1",params![key])?;
                self.connection.execute("INSERT INTO runtime_inbox_retry VALUES(?1,?2,0,?3,?3) ON CONFLICT(envelope_key) DO UPDATE SET entry_json=excluded.entry_json,next_at=excluded.next_at",params![key,entry,at])?;
            }
            self.connection.execute("UPDATE runtime_inbox_retry SET next_at=?1", params![at])?;
            Ok(rows.len())
        })
    }
    /// Monotonic revision of group/manifest records, independent of journal retention.
    /// # Errors
    /// Returns SQL errors.
    pub fn inbox_recovery_revision(&self) -> Result<u64, StorageError> {
        Ok(self.connection.query_row(
            "SELECT revision FROM runtime_inbox_recovery WHERE singleton=1",
            [],
            |row| row.get(0),
        )?)
    }
}
