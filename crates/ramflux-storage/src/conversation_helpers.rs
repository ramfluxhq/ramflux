// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::wildcard_imports)]
use crate::*;
use rusqlite::{Connection, params};

pub(crate) fn has_unread_after_read(
    connection: &Connection,
    conversation_id: &str,
    read_through_message_id: Option<&str>,
) -> Result<bool, StorageError> {
    let unread_count: u64 = match read_through_message_id {
        Some(message_id) => connection.query_row(
            "SELECT COUNT(*)
               FROM direct_message_projection
              WHERE conversation_id = ?1
                AND deleted = 0
                AND (
                    created_at > (
                        SELECT created_at
                          FROM direct_message_projection
                         WHERE conversation_id = ?1 AND message_id = ?2
                    )
                    OR (
                        created_at = (
                            SELECT created_at
                              FROM direct_message_projection
                             WHERE conversation_id = ?1 AND message_id = ?2
                        )
                        AND message_id > ?2
                    )
                )",
            params![conversation_id, message_id],
            |row| row.get(0),
        )?,
        None => connection.query_row(
            "SELECT COUNT(*)
               FROM direct_message_projection
              WHERE conversation_id = ?1 AND deleted = 0",
            params![conversation_id],
            |row| row.get(0),
        )?,
    };
    Ok(unread_count > 0)
}

pub(crate) fn disappearing_tombstone_id(conversation_id: &str, message_id: &str) -> String {
    format!("event_tombstone:{conversation_id}:{message_id}")
}
