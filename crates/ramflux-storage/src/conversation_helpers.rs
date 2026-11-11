// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::wildcard_imports)]
use crate::database::Connection;
use crate::*;
use rusqlite::params;

pub(crate) fn has_unread_after_read(
    connection: &Connection,
    conversation_id: &str,
    read_through_message_id: Option<&str>,
) -> Result<bool, StorageError> {
    if let Some(message) = read_through_message_id
        && let Some(unread) = generated_unread_after_read(connection, conversation_id, message)?
    {
        return Ok(unread);
    }
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

fn generated_unread_after_read(
    connection: &Connection,
    conversation: &str,
    marker: &str,
) -> Result<Option<bool>, StorageError> {
    use ramflux_protocol::message::{EventIdentity, identity::order_key};
    use rusqlite::OptionalExtension;
    let marker: Option<Vec<u8>> = connection
        .query_row(
            "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
            params![format!("routed/generated-identity/{marker}")],
            |row| row.get(0),
        )
        .optional()?;
    let Some(marker) = marker else {
        return Ok(None);
    };
    let identity: EventIdentity = serde_json::from_slice(&marker)?;
    let marker = order_key(&identity).map_err(|_| StorageError::AuthorizationRejected)?;
    let mut statement = connection.prepare("SELECT a.state_json FROM direct_message_projection m LEFT JOIN runtime_actor_state a ON a.state_kind='routed/generated-identity/'||m.message_id WHERE m.conversation_id=?1 AND m.deleted=0")?;
    let rows =
        statement.query_map(params![conversation], |row| row.get::<_, Option<Vec<u8>>>(0))?;
    for row in rows {
        let Some(bytes) = row? else {
            return Ok(Some(true));
        };
        let identity: EventIdentity = serde_json::from_slice(&bytes)?;
        if order_key(&identity).map_err(|_| StorageError::AuthorizationRejected)? > marker {
            return Ok(Some(true));
        }
    }
    Ok(Some(false))
}

pub(crate) fn disappearing_tombstone_id(conversation_id: &str, message_id: &str) -> String {
    format!("event_tombstone:{conversation_id}:{message_id}")
}
