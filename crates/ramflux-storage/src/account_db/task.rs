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
            || key.starts_with("task/forward/")
            || key.starts_with("task/decision_reserved/")
            || key.starts_with("task/local_pending/")
            || key.starts_with("task/local_intent_status/")
            || key.starts_with("task/history/")
            || key.starts_with("task/checkpoint/")
            || key.starts_with("task/lifecycle/")
            || key.starts_with("task/view/")
            || key.starts_with("task/receipt/")
            || key.starts_with("task/message/")
            || key.starts_with("task/committed_decision/"))
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
    /// Bounds unrelated-task tombstones per original signer and age.
    /// # Errors
    /// Returns database errors.
    pub fn prune_task_no_role(&self, now: i64) -> Result<(), StorageError> {
        self.connection.execute("DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM (SELECT state_kind,json_extract(CAST(state_json AS TEXT),'$.at') at,row_number() OVER (PARTITION BY json_extract(CAST(state_json AS TEXT),'$.source') ORDER BY rowid DESC) sender_rank,row_number() OVER (ORDER BY rowid DESC) account_rank FROM runtime_actor_state WHERE substr(state_kind,1,13)='task/no_role/') WHERE sender_rank>64 OR account_rank>512 OR at<?1)",params![now.saturating_sub(7*86400)])?;
        Ok(())
    }
    /// Bounds compact pending-status records separately from active local decision slots.
    /// # Errors
    /// Returns database errors.
    pub fn prune_local_task_intent_status(&self, now: i64) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM (SELECT state_kind,json_extract(CAST(state_json AS TEXT),'$.start') start,row_number() OVER (PARTITION BY json_extract(CAST(state_json AS TEXT),'$.executor') ORDER BY rowid DESC) peer_rank,row_number() OVER (ORDER BY rowid DESC) account_rank FROM runtime_actor_state WHERE substr(state_kind,1,25)='task/local_intent_status/') WHERE peer_rank>64 OR account_rank>512 OR start<?1)",
            params![now.saturating_sub(30 * 24 * 60 * 60)],
        )?;
        Ok(())
    }
    /// Reads a bounded upgrade page of histories missing their lifecycle index.
    /// # Errors
    /// Returns database or decoding errors.
    pub fn unindexed_task_histories<T: serde::de::DeserializeOwned>(
        &self,
    ) -> Result<Vec<T>, StorageError> {
        let mut query = self.connection.prepare("SELECT h.state_json FROM runtime_actor_state h WHERE substr(h.state_kind,1,13)='task/history/' AND NOT EXISTS(SELECT 1 FROM runtime_actor_state l WHERE l.state_kind=replace(h.state_kind,'task/history/','task/lifecycle/') AND json_type(CAST(l.state_json AS TEXT),'$.usage') IS NOT NULL) ORDER BY h.state_kind LIMIT 32")?;
        let rows = query.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|r| Ok(serde_json::from_slice(&r?)?)).collect()
    }
    /// Sums every retained event for its verified signer, independently of maintenance page limits.
    /// None indicates that this signer's legacy histories still need bounded accounting migration.
    /// # Errors
    /// Returns database errors.
    pub fn task_signer_usage(
        &self,
        signer: &str,
        conversation: Option<&str>,
        excluded_lifecycle: &str,
    ) -> Result<Option<[u64; 4]>, StorageError> {
        let legacy: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM runtime_actor_state h LEFT JOIN runtime_actor_state l ON l.state_kind=replace(h.state_kind,'task/history/','task/lifecycle/') WHERE substr(h.state_kind,1,13)='task/history/' AND replace(h.state_kind,'task/history/','task/lifecycle/')!=?3 AND (l.state_kind IS NULL OR json_type(CAST(l.state_json AS TEXT),'$.usage') IS NULL) AND EXISTS(SELECT 1 FROM json_each(CAST(h.state_json AS TEXT),'$.events') e WHERE json_extract(e.value,'$.carrier.principal_id')=?1))",params![signer,conversation,excluded_lifecycle],|r|r.get(0))?;
        if legacy {
            return Ok(None);
        }
        Ok(Some(self.connection.query_row("SELECT coalesce(sum(json_extract(u.value,'$.bytes')),0),coalesce(sum(json_extract(u.value,'$.events')),0),coalesce(sum(json_extract(u.value,'$.decisions')),0),coalesce(sum(json_extract(u.value,'$.decision_bytes')),0) FROM runtime_actor_state l,json_each(CAST(l.state_json AS TEXT),'$.usage') u WHERE substr(l.state_kind,1,15)='task/lifecycle/' AND u.key=?1 AND (?2 IS NULL OR json_extract(CAST(l.state_json AS TEXT),'$.conversation_id')=?2) AND l.state_kind!=?3",params![signer,conversation,excluded_lifecycle],|r|Ok([r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?]))?))
    }
    /// Reads lifecycle rows for one source, conversation, or a bounded terminal maintenance page.
    /// # Errors
    /// Returns database or decoding errors.
    pub fn task_lifecycle_rows(
        &self,
        source: Option<&str>,
        conversation: Option<&str>,
        terminal_only: bool,
    ) -> Result<Vec<serde_json::Value>, StorageError> {
        self.read_task_lifecycle_rows(source, conversation, terminal_only, false)
    }
    /// Reads a bounded terminal page after filtering to its retention owner.
    /// # Errors
    /// Returns database or decoding errors.
    pub fn task_retention_rows(
        &self,
        source: Option<&str>,
        conversation: Option<&str>,
    ) -> Result<Vec<serde_json::Value>, StorageError> {
        self.read_task_lifecycle_rows(source, conversation, true, true)
    }
    fn read_task_lifecycle_rows(
        &self,
        source: Option<&str>,
        conversation: Option<&str>,
        terminal_only: bool,
        retention: bool,
    ) -> Result<Vec<serde_json::Value>, StorageError> {
        let mut query = self.connection.prepare(
            "SELECT state_json FROM runtime_actor_state WHERE substr(state_kind,1,15)='task/lifecycle/' AND (?1 IS NULL OR CASE WHEN ?4 THEN coalesce(json_extract(CAST(state_json AS TEXT),'$.retention_source'),json_extract(CAST(state_json AS TEXT),'$.source')) ELSE json_extract(CAST(state_json AS TEXT),'$.source') END=?1) AND (?2 IS NULL OR json_extract(CAST(state_json AS TEXT),'$.conversation_id')=?2) AND (?3=0 OR json_extract(CAST(state_json AS TEXT),'$.terminal')=1) ORDER BY json_extract(CAST(state_json AS TEXT),'$.updated_at') DESC,state_kind LIMIT 2048",
        )?;
        let rows = query
            .query_map(params![source, conversation, terminal_only, retention], |r| {
                r.get::<_, Vec<u8>>(0)
            })?;
        rows.map(|row| Ok(serde_json::from_slice(&row?)?)).collect()
    }
    /// Caps transient commit certificates by count and age without deleting consumed decisions.
    /// # Errors
    /// Returns database errors.
    pub fn prune_task_certificates(&self, now: i64) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM (SELECT state_kind,json_extract(CAST(state_json AS TEXT),'$.issued_at') issued_at,json_extract(CAST(state_json AS TEXT),'$.conversation_id') conversation_id,json_extract(CAST(state_json AS TEXT),'$.resolution.task_id') task_id,row_number() OVER (PARTITION BY json_extract(CAST(state_json AS TEXT),'$.assignee') ORDER BY rowid DESC) peer_rank,row_number() OVER (PARTITION BY json_extract(CAST(state_json AS TEXT),'$.conversation_id') ORDER BY rowid DESC) conversation_rank,row_number() OVER (ORDER BY rowid DESC) account_rank FROM runtime_actor_state WHERE substr(state_kind,1,24)='task/committed_decision/') ranked WHERE peer_rank>32 OR conversation_rank>64 OR account_rank>256 OR issued_at<?1 OR EXISTS(SELECT 1 FROM runtime_actor_state l WHERE substr(l.state_kind,1,15)='task/lifecycle/' AND json_extract(CAST(l.state_json AS TEXT),'$.conversation_id')=ranked.conversation_id AND json_extract(CAST(l.state_json AS TEXT),'$.task_id')=ranked.task_id AND json_extract(CAST(l.state_json AS TEXT),'$.compacted')=1))",
            params![now.saturating_sub(7 * 24 * 60 * 60)],
        )?;
        Ok(())
    }
    /// Retains a bounded diagnostic/rate ledger without removing accepted event receipts.
    /// # Errors
    /// Rejects other namespaces and returns database errors.
    pub fn prune_task_diagnostics(&self, prefix: &str, retain: u32) -> Result<(), StorageError> {
        if !matches!(
            prefix,
            "task/rejected/"
                | "task/verified_roster/"
                | "task/rate/"
                | "task/ack_sent/"
                | "task/import_skip/"
                | "task/message/"
        ) {
            return Err(StorageError::AuthorizationRejected);
        }
        self.connection.execute("DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 ORDER BY coalesce(json_extract(CAST(state_json AS TEXT),'$.start'),rowid) DESC,state_kind DESC LIMIT -1 OFFSET ?2)",params![prefix,retain.clamp(1,2048)])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
