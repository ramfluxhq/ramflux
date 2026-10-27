// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable metadata journal, explicit sticky acknowledgement and bounded quarantine.
use super::super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
mod inbox_failure;
mod inbox_legacy;
mod inbox_policy;
pub use inbox_policy::InboxFailurePolicy;
mod quarantine;
mod retention;

/// A retry bucket has an authenticated root-qualified owner or only an opaque quarantine key.
#[derive(Clone, Copy)]
pub enum InboxFailureSource<'a> {
    Unverified,
    Authenticated { device: &'a ramflux_crypto::RootQualifiedDeviceRef, related: bool },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct JournalEvent {
    pub seq: u64,
    pub at: i64,
    pub topic: String,
    pub body: serde_json::Value,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct JournalBounds {
    pub head_seq: u64,
    pub floor_seq: u64,
    pub pruned_through: u64,
}

impl AccountDb {
    pub(super) fn install_journal_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS runtime_journal(seq INTEGER PRIMARY KEY AUTOINCREMENT,at INTEGER NOT NULL,topic TEXT NOT NULL,body_json BLOB NOT NULL,source_key TEXT NOT NULL UNIQUE,sticky INTEGER NOT NULL DEFAULT 0,acknowledged INTEGER NOT NULL DEFAULT 0,subject TEXT);
        CREATE TABLE IF NOT EXISTS runtime_journal_bounds(singleton INTEGER PRIMARY KEY CHECK(singleton=1),head_seq INTEGER NOT NULL,pruned_through INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS runtime_journal_topic ON runtime_journal(topic);
        INSERT OR IGNORE INTO runtime_journal_bounds VALUES(1,0,0);
        CREATE TABLE IF NOT EXISTS runtime_unrouted(envelope_id TEXT PRIMARY KEY,inbox_seq INTEGER NOT NULL,entry_json BLOB NOT NULL,received_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS runtime_inbox_dead_letter(envelope_key TEXT PRIMARY KEY,entry_json BLOB NOT NULL,error_code TEXT NOT NULL,received_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS runtime_inbox_retry(envelope_key TEXT PRIMARY KEY,entry_json BLOB NOT NULL,attempts INTEGER NOT NULL,next_at INTEGER NOT NULL,created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS runtime_inbox_policy(envelope_key TEXT PRIMARY KEY,source TEXT NOT NULL,trusted INTEGER NOT NULL,first_seen INTEGER NOT NULL,expires_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,failure_class TEXT NOT NULL,subject TEXT NOT NULL,last_redrive INTEGER NOT NULL DEFAULT 0,last_revision INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS runtime_inbox_changes(kind TEXT NOT NULL,subject TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(kind,subject));
        CREATE TABLE IF NOT EXISTS runtime_message_content(message_id TEXT PRIMARY KEY,conversation_id TEXT NOT NULL,body BLOB NOT NULL);
        CREATE INDEX IF NOT EXISTS runtime_message_content_conversation ON runtime_message_content(conversation_id,message_id);")?;
        self.connection.execute_batch("CREATE TRIGGER IF NOT EXISTS runtime_content_deleted AFTER UPDATE OF deleted ON direct_message_projection WHEN NEW.deleted=1 BEGIN DELETE FROM runtime_message_content WHERE message_id=NEW.message_id; END;
            CREATE TRIGGER IF NOT EXISTS runtime_content_removed AFTER DELETE ON direct_message_projection BEGIN DELETE FROM runtime_message_content WHERE message_id=OLD.message_id; END;")?;
        Ok(())
    }

    /// Returns the newest retained transition for a topic, for older snapshot upgrades.
    ///
    /// # Errors
    /// Returns SQL or stored event decoding errors.
    pub fn latest_journal_event(&self, topic: &str) -> Result<Option<JournalEvent>, StorageError> {
        Ok(self.connection.query_row(
            "SELECT seq,at,topic,body_json FROM runtime_journal WHERE topic=?1 ORDER BY seq DESC LIMIT 1",
            params![topic], row,
        ).optional()?)
    }

    /// Appends compact, explicitly constructed metadata once per durable source key.
    ///
    /// # Errors
    /// Returns serialization/SQL errors or rejects an oversized metadata body.
    pub fn append_journal(
        &self,
        source: &str,
        topic: &str,
        body: &serde_json::Value,
        at: i64,
        subject: Option<&str>,
    ) -> Result<JournalEvent, StorageError> {
        self.write_transaction(|| self.insert_journal(source, topic, body, at, subject))
    }

    fn insert_journal(
        &self,
        source: &str,
        topic: &str,
        body: &serde_json::Value,
        at: i64,
        subject: Option<&str>,
    ) -> Result<JournalEvent, StorageError> {
        let bytes = serde_json::to_vec(body)?;
        if bytes.len() > 512 * 1024 {
            return Err(StorageError::AuthorizationRejected);
        }
        self.connection.execute("INSERT OR IGNORE INTO runtime_journal(at,topic,body_json,source_key,sticky,subject) VALUES(?1,?2,?3,?4,?5,?6)",params![at,topic,bytes,source,i64::from(matches!(topic,"safety.changed"|"mcp.approval.request")),subject])?;
        let event = self.connection.query_row(
            "SELECT seq,at,topic,body_json FROM runtime_journal WHERE source_key=?1",
            params![source],
            row,
        )?;
        self.connection.execute(
            "UPDATE runtime_journal_bounds SET head_seq=max(head_seq,?1) WHERE singleton=1",
            params![event.seq],
        )?;
        Ok(event)
    }

    /// Commits journal projections and the corresponding outbox receipt in one FULL transaction.
    ///
    /// # Errors
    /// Rolls back the entire batch on SQL/serialization errors.
    pub fn journal_outbox(
        &self,
        sequence: i64,
        events: &[(String, serde_json::Value, Option<String>)],
        at: i64,
    ) -> Result<Vec<JournalEvent>, StorageError> {
        self.write_transaction(|| {
            let mut result = Vec::new();
            for (index, (topic, body, subject)) in events.iter().enumerate() {
                result.push(self.insert_journal(
                    &format!("outbox:{sequence}:{index}"),
                    topic,
                    body,
                    at,
                    subject.as_deref(),
                )?);
            }
            self.mark_outbox_published(sequence)?;
            Ok(result)
        })
    }

    /// Returns committed per-account sequence bounds, including retention-hole detection.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn journal_bounds(&self) -> Result<JournalBounds, StorageError> {
        Ok(self.connection.query_row("SELECT head_seq,coalesce((SELECT min(seq) FROM runtime_journal),head_seq),pruned_through FROM runtime_journal_bounds WHERE singleton=1",[],|row|Ok(JournalBounds{head_seq:row.get(0)?,floor_seq:row.get(1)?,pruned_through:row.get(2)?}))?)
    }

    /// Reads a bounded ordered replay page. Callers validate cursor bounds in the same snapshot.
    ///
    /// # Errors
    /// Returns SQL/JSON errors.
    pub fn journal_after(&self, seq: u64, limit: u32) -> Result<Vec<JournalEvent>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT seq,at,topic,body_json FROM runtime_journal WHERE seq>?1 ORDER BY seq LIMIT ?2",
        )?;
        Ok(statement
            .query_map(params![seq, limit.min(128)], row)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Marks a sticky event acknowledged only after an explicit user-facing action.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn acknowledge_journal(&self, seq: u64) -> Result<(), StorageError> {
        self.connection
            .execute("UPDATE runtime_journal SET acknowledged=1 WHERE seq=?1", params![seq])?;
        Ok(())
    }

    /// Completes sticky events associated with an approval/safety decision.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn acknowledge_journal_subject(&self, subject: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE runtime_journal SET acknowledged=1 WHERE subject=?1",
            params![subject],
        )?;
        Ok(())
    }

    /// Stores content only in the SDK's encrypted message store, never in journal bodies.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn store_message_content(
        &self,
        conversation: &str,
        message: &str,
        body: &[u8],
    ) -> Result<(), StorageError> {
        if self.message_is_deleted(message)? {
            return Ok(());
        }
        self.connection.execute("INSERT OR IGNORE INTO runtime_message_content(message_id,conversation_id,body) VALUES(?1,?2,?3)",params![message,conversation,body])?;
        Ok(())
    }

    /// Reads approved content separately from metadata streaming.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn message_content(&self, message: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT body FROM runtime_message_content WHERE message_id=?1",
                params![message],
                |row| row.get(0),
            )
            .optional()?)
    }
}
fn row(row: &crate::database::Row) -> rusqlite::Result<JournalEvent> {
    let bytes: Vec<u8> = row.get(3)?;
    let body = serde_json::from_slice(&bytes).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    Ok(JournalEvent { seq: row.get(0)?, at: row.get(1)?, topic: row.get(2)?, body })
}

#[cfg(test)]
mod tests;
