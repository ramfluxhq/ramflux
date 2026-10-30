// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded retry and dead-letter storage; admission never evicts another source.
use super::*;
impl AccountDb {
    /// Expires held work using its original local lifetime, never a sender-selected long TTL.
    /// # Errors
    /// Returns SQLite or journal serialization errors.
    pub fn expire_inbox_holds(&self, at: i64) -> Result<(), StorageError> {
        self.write_transaction(|| {
            self.release_expired_legacy_inbox(at)?;
            let mut q=self.connection.prepare("SELECT r.envelope_key,r.entry_json FROM runtime_inbox_retry r JOIN runtime_inbox_policy p USING(envelope_key) WHERE p.expires_at<=?1 AND NOT EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind='inbox/legacy-held/'||p.envelope_key)")?;
            let rows=q.query_map(params![at],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            drop(q);
            for (key,entry) in rows { self.insert_inbox_dead_letter(&key,&entry,&serde_json::json!({"retry_key":key,"error_code":"retry_expired"}),at)?; }
            self.connection.execute("DELETE FROM runtime_inbox_dead_letter WHERE envelope_key IN (SELECT envelope_key FROM runtime_inbox_policy WHERE expires_at<=?1)",params![at])?;
            self.connection.execute("DELETE FROM runtime_unrouted WHERE received_at<?1",params![at.saturating_sub(7 * 24 * 60 * 60)])?;
            self.cleanup_legacy_inbox_holds()?;
            self.cleanup_inbox_policy()
        })
    }
    /// Records terminal metadata before ACK; never-seen inputs retain bounded diagnostics.
    /// # Errors
    /// Returns SQLite or journal serialization errors.
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
        if let Some(marker) = self.inbox_envelope_marker(entry)? {
            self.connection
                .execute("DELETE FROM runtime_inbox_retry WHERE envelope_key=?1", params![key])?;
            self.connection
                .execute("DELETE FROM runtime_unrouted WHERE envelope_id=?1", params![key])?;
            if self.actor_state_exists(&marker)? {
                return self.cleanup_inbox_policy();
            }
            if let Some(canonical) = self.deleted_inbox_envelope(entry)? {
                return self.insert_routed_dead_letter(
                    &canonical,
                    metadata
                        .get("error_code")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown"),
                    at,
                );
            }
        }
        let admitted = self.ensure_inbox_policy(key, entry, at)?;
        let bounded = if entry.len() <= 1024 * 1024 { entry } else { &[] };
        if admitted {
            let count: i64 = self.connection.query_row(
                "SELECT count(*) FROM runtime_inbox_dead_letter",
                [],
                |r| r.get(0),
            )?;
            if count < 64 {
                self.connection.execute("INSERT OR IGNORE INTO runtime_inbox_dead_letter SELECT ?1,?2,?3,first_seen FROM runtime_inbox_policy WHERE envelope_key=?1",params![key,bounded,metadata.get("error_code").and_then(serde_json::Value::as_str).unwrap_or("unknown")])?;
            }
        }
        self.insert_journal(
            &format!("undeliverable:{key}"),
            "message.undeliverable",
            metadata,
            at,
            None,
        )?;
        self.connection
            .execute("DELETE FROM runtime_inbox_retry WHERE envelope_key=?1", params![key])?;
        self.cleanup_inbox_policy()
    }
    pub(crate) fn insert_routed_dead_letter(
        &self,
        canonical_envelope: &[u8],
        code: &str,
        at: i64,
    ) -> Result<(), StorageError> {
        let marker = self.routed_seen_key(canonical_envelope)?;
        self.insert_inbox_dead_letter(
            &marker,
            &serde_json::to_vec(&serde_json::json!({"marker":marker}))?,
            &serde_json::json!({"marker":marker,"error_code":code}),
            at,
        )
    }
    /// Defers transient work; zero means its quota, lifetime, or attempt budget was exhausted.
    /// # Errors
    /// Returns SQLite errors or rejects a raw entry exceeding one MiB.
    pub fn defer_inbox_entry(&self, key: &str, entry: &[u8], at: i64) -> Result<u32, StorageError> {
        if entry.len() > 1024 * 1024 {
            return Err(StorageError::AuthorizationRejected);
        }
        self.write_transaction(|| {
            if let Some(marker) = self.inbox_envelope_marker(entry)?
                && self.actor_state_exists(&marker)?
                // Initial ACK failure may retain a live committed receipt. Deletion removes it.
                && !(key.starts_with("routed/committed/") && self.actor_state_exists(key)?)
            {
                return Ok(0);
            }
            if !self.ensure_inbox_policy(key,entry,at)? {return Ok(0);}
            let allowed:bool=self.connection.query_row("SELECT expires_at>?2 AND attempts<CASE WHEN trusted=1 THEN 8 ELSE 3 END FROM runtime_inbox_policy WHERE envelope_key=?1",params![key,at],|r|r.get(0))?;
            let count:i64=self.connection.query_row("SELECT count(*) FROM runtime_inbox_retry r JOIN runtime_inbox_policy p USING(envelope_key) WHERE r.envelope_key!=?1 AND p.expires_at>?2 AND r.next_at<9223372036854775807",params![key,at],|r|r.get(0))?;
            if !allowed || count>=64 {return Ok(0);}
            self.connection.execute("UPDATE runtime_inbox_policy SET attempts=attempts+1 WHERE envelope_key=?1",params![key])?;
            self.connection.execute("INSERT INTO runtime_inbox_retry SELECT envelope_key,?2,attempts,?3+min(64,(1<<min(attempts,6))),first_seen FROM runtime_inbox_policy WHERE envelope_key=?1 ON CONFLICT(envelope_key) DO UPDATE SET attempts=excluded.attempts,next_at=excluded.next_at",params![key,entry,at])?;
            let attempts: u32 = self.connection.query_row("SELECT attempts FROM runtime_inbox_policy WHERE envelope_key=?1",params![key],|r|r.get(0))?;
            self.release_expired_legacy_inbox(at)?;
            Ok(attempts)
        })
    }
    /// Checks backoff even when the gateway redelivers pending work.
    /// # Errors
    /// Returns SQLite errors.
    pub fn inbox_retry_ready(&self, key: &str, at: i64) -> Result<bool, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT next_at<=?2 FROM runtime_inbox_retry WHERE envelope_key=?1",
                params![key, at],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(true))
    }
    /// Reads a bounded due retry page.
    /// # Errors
    /// Returns SQLite errors.
    pub fn due_inbox_retries(&self, at: i64) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut q=self.connection.prepare("SELECT entry_json FROM runtime_inbox_retry WHERE next_at<=?1 ORDER BY created_at,envelope_key LIMIT 64")?;
        Ok(q.query_map(params![at], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Reads due retry rows together with their pre-retention admission keys.
    /// # Errors
    /// Returns SQLite errors.
    pub fn due_inbox_retry_rows(&self, at: i64) -> Result<Vec<(String, Vec<u8>)>, StorageError> {
        let mut query = self.connection.prepare(
            "SELECT envelope_key,entry_json FROM runtime_inbox_retry \
             WHERE next_at<=?1 ORDER BY created_at,envelope_key LIMIT 64",
        )?;
        Ok(query
            .query_map(params![at], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Clears successful retry work and its admission state.
    /// # Errors
    /// Returns SQLite errors.
    pub fn remove_inbox_retry(&self, key: &str) -> Result<(), StorageError> {
        self.connection
            .execute("DELETE FROM runtime_inbox_retry WHERE envelope_key=?1", params![key])?;
        self.cleanup_inbox_policy()
    }
    /// Returns whether the packet has pending retry work.
    /// # Errors
    /// Returns SQLite errors.
    pub fn has_inbox_retry(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM runtime_inbox_retry WHERE envelope_key=?1)",
            params![key],
            |r| r.get(0),
        )?)
    }
    /// Returns the latest actual membership/manifest change revision.
    /// # Errors
    /// Returns SQLite errors.
    pub fn inbox_recovery_revision(&self) -> Result<u64, StorageError> {
        Ok(self.connection.query_row(
            "SELECT revision FROM runtime_inbox_recovery WHERE singleton=1",
            [],
            |r| r.get(0),
        )?)
    }
}
