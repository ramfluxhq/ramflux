// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only list facts: unread totals, the read cursor, and the latest visible message.
//! These queries do not write and do not select ciphertext.

use super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};

/// Account-wide badge counts. Unread is the sum of per-conversation unread rows.
/// Attention is pending decisions, not unread messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryTotals {
    /// Sum of visible unread messages across every directory conversation.
    pub unread: u64,
    /// Inbound contact requests still pending, plus pending approval rows.
    pub attention: u64,
}

/// Stored read cursor and the message a client should treat as the first unread row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationReadPosition {
    /// `conversation_read_state.read_through_message_id`, when this reader has one.
    pub read_through_message_id: Option<String>,
    /// Active unread-marker id, otherwise the oldest visible message after the cursor.
    pub first_unread_message_id: Option<String>,
}

const CONVERSATION_IDS: &str = "
    SELECT conversation_id AS id FROM direct_message_projection
    UNION SELECT conversation_id FROM conversation_projection
    UNION SELECT conversation_id FROM conversation_list_state
    UNION SELECT substr(state_kind,24) FROM runtime_actor_state
     WHERE state_kind GLOB 'directory/conversation/*'";

impl AccountDb {
    /// Sums unread messages and pending decisions without returning directory rows.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn client_conversation_totals(
        &self,
        reader: Option<&ramflux_crypto::RootQualifiedDeviceRef>,
    ) -> Result<DirectoryTotals, StorageError> {
        let reader_key = reader.map(ramflux_crypto::RootQualifiedDeviceRef::storage_key);
        Ok(DirectoryTotals {
            unread: self.unread_total(reader_key)?,
            attention: self.attention_total()?,
        })
    }

    /// Reads the stored cursor and the first unread message id for one conversation.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn conversation_read_position(
        &self,
        conversation_id: &str,
        reader: Option<&ramflux_crypto::RootQualifiedDeviceRef>,
    ) -> Result<ConversationReadPosition, StorageError> {
        let reader_key = reader.map(ramflux_crypto::RootQualifiedDeviceRef::storage_key);
        let cleared =
            self.read_conversation_list_state(conversation_id)?.cleared_at.unwrap_or(i64::MIN);
        let read_through = self.stored_read_through(conversation_id, reader_key)?;
        let active = self.active_unread_marker(conversation_id, reader_key)?;
        let first_unread = match active {
            Some(message_id) => Some(message_id),
            None => self.first_message_after_read(conversation_id, reader_key, cleared)?,
        };
        Ok(ConversationReadPosition {
            read_through_message_id: read_through,
            first_unread_message_id: first_unread,
        })
    }

    /// Latest non-deleted message that is still after the conversation's clear cursor.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn latest_visible_message(
        &self,
        conversation_id: &str,
    ) -> Result<Option<(String, i64)>, StorageError> {
        let cleared =
            self.read_conversation_list_state(conversation_id)?.cleared_at.unwrap_or(i64::MIN);
        self.connection
            .query_row(
                "SELECT message_id, created_at
                   FROM direct_message_projection
                  WHERE conversation_id = ?1 AND deleted = 0 AND created_at > ?2
                  ORDER BY created_at DESC, message_id DESC
                  LIMIT 1",
                params![conversation_id, cleared],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Approved plaintext only when its stored length is within `max_bytes`.
    /// Oversized or missing bodies return `None` so a list read does not allocate them.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn message_content_within(
        &self,
        message_id: &str,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let max = i64::try_from(max_bytes).map_err(|_| StorageError::AuthorizationRejected)?;
        let length: Option<i64> = self
            .connection
            .query_row(
                "SELECT length(body) FROM runtime_message_content WHERE message_id = ?1",
                params![message_id],
                |row| row.get(0),
            )
            .optional()?;
        if length.is_none_or(|length| length < 0 || length > max) {
            return Ok(None);
        }
        self.message_content(message_id)
    }

    fn unread_total(&self, reader_id: Option<&str>) -> Result<u64, StorageError> {
        let sql = format!(
            "SELECT coalesce(sum(unread), 0) FROM (
                SELECT (
                    SELECT count(*) FROM direct_message_projection m
                     WHERE m.conversation_id = ids.id AND m.deleted = 0
                       AND m.created_at > coalesce(
                            (SELECT cleared_at FROM conversation_list_state
                              WHERE conversation_id = ids.id), ?1)
                       AND NOT EXISTS (
                            SELECT 1 FROM conversation_read_state r
                            JOIN direct_message_projection last
                              ON last.message_id = r.read_through_message_id
                           WHERE r.conversation_id = ids.id AND r.reader_id = ?2
                             AND (m.created_at < last.created_at
                                  OR (m.created_at = last.created_at
                                      AND m.message_id <= last.message_id))
                       )
                ) AS unread FROM ({CONVERSATION_IDS}) AS ids)"
        );
        self.connection
            .query_row(&sql, params![i64::MIN, reader_id], |row| row.get(0))
            .map_err(StorageError::from)
    }

    fn attention_total(&self) -> Result<u64, StorageError> {
        let now = self.now_unix();
        let contacts: u64 = self.connection.query_row(
            "SELECT count(*) FROM contact_request_projection
              WHERE direction = 'inbound' AND state = 'pending' AND expires_at > ?1",
            params![now],
            |row| row.get(0),
        )?;
        let approvals: u64 = self.connection.query_row(
            "SELECT count(*) FROM runtime_actor_state
              WHERE state_kind GLOB 'directory/approval/*'
                AND json_extract(CAST(state_json AS TEXT), '$.status') = 'pending'",
            [],
            |row| row.get(0),
        )?;
        Ok(contacts.saturating_add(approvals))
    }

    fn stored_read_through(
        &self,
        conversation_id: &str,
        reader_id: Option<&str>,
    ) -> Result<Option<String>, StorageError> {
        self.connection
            .query_row(
                "SELECT NULLIF(read_through_message_id, '')
                   FROM conversation_read_state
                  WHERE conversation_id = ?1 AND reader_id = ?2",
                params![conversation_id, reader_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::from)
    }

    fn active_unread_marker(
        &self,
        conversation_id: &str,
        reader_id: Option<&str>,
    ) -> Result<Option<String>, StorageError> {
        self.connection
            .query_row(
                "SELECT NULLIF(message_id, '')
                   FROM conversation_unread_marker
                  WHERE conversation_id = ?1 AND marker_owner = ?2 AND active = 1",
                params![conversation_id, reader_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::from)
    }

    fn first_message_after_read(
        &self,
        conversation_id: &str,
        reader_id: Option<&str>,
        cleared_at: i64,
    ) -> Result<Option<String>, StorageError> {
        self.connection
            .query_row(
                "SELECT m.message_id
                   FROM direct_message_projection m
                  WHERE m.conversation_id = ?1 AND m.deleted = 0 AND m.created_at > ?2
                    AND NOT EXISTS (
                         SELECT 1 FROM conversation_read_state r
                         JOIN direct_message_projection last
                           ON last.message_id = r.read_through_message_id
                        WHERE r.conversation_id = ?1 AND r.reader_id = ?3
                          AND (m.created_at < last.created_at
                               OR (m.created_at = last.created_at
                                   AND m.message_id <= last.message_id))
                    )
                  ORDER BY m.created_at ASC, m.message_id ASC
                  LIMIT 1",
                params![conversation_id, cleared_at, reader_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::from)
    }
}
