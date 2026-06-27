// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::row_mappers::{friend_link_from_row, rejected_inbox_from_row};
use rusqlite::OptionalExtension;

impl AccountDb {
    pub fn establish_friend_link(
        &self,
        link_id: &str,
        requester_id: &str,
        target_id: &str,
    ) -> Result<FriendLinkRecord, StorageError> {
        self.connection.execute(
            "INSERT OR REPLACE INTO friend_link_projection
                (link_id, requester_id, target_id, state, remove_scope, blocked, capability_revoked_at, updated_at)
             VALUES (?1, ?2, ?3, 'accepted', NULL, 0, NULL, ?4)",
            params![link_id, requester_id, target_id, self.now_unix()],
        )?;
        self.friend_link(link_id)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn remove_friend_link(
        &self,
        link_id: &str,
        scope: &str,
        removed_at: i64,
    ) -> Result<FriendLinkRecord, StorageError> {
        let scope = if scope == "own-devices" { "own_devices" } else { scope };
        if !matches!(scope, "me" | "own_devices" | "both") {
            return Err(StorageError::AuthorizationRejected);
        }
        let capability_revoked_at = if scope == "both" { Some(removed_at) } else { None };
        self.connection.execute(
            "UPDATE friend_link_projection
                SET state = 'removed',
                    remove_scope = ?2,
                    capability_revoked_at = COALESCE(?3, capability_revoked_at),
                    updated_at = ?4
              WHERE link_id = ?1",
            params![link_id, scope, capability_revoked_at, removed_at],
        )?;
        self.friend_link(link_id)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn block_friend_link(
        &self,
        link_id: &str,
        blocked_at: i64,
    ) -> Result<FriendLinkRecord, StorageError> {
        self.connection.execute(
            "UPDATE friend_link_projection
                SET state = 'blocked',
                    blocked = 1,
                    capability_revoked_at = COALESCE(capability_revoked_at, ?2),
                    updated_at = ?2
              WHERE link_id = ?1",
            params![link_id, blocked_at],
        )?;
        self.friend_link(link_id)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn unblock_friend_link(
        &self,
        link_id: &str,
        unblocked_at: i64,
    ) -> Result<FriendLinkRecord, StorageError> {
        self.connection.execute(
            "UPDATE friend_link_projection
                SET state = 'accepted',
                    blocked = 0,
                    capability_revoked_at = NULL,
                    updated_at = ?2
              WHERE link_id = ?1",
            params![link_id, unblocked_at],
        )?;
        self.friend_link(link_id)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn friend_link_for_peer(
        &self,
        peer_id: &str,
    ) -> Result<Option<FriendLinkRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT link_id, requester_id, target_id, state, remove_scope, blocked, capability_revoked_at
                  FROM friend_link_projection
                  WHERE requester_id = ?1 OR target_id = ?1
                  ORDER BY (blocked != 0 OR capability_revoked_at IS NOT NULL) DESC,
                           updated_at DESC,
                           link_id DESC
                  LIMIT 1",
                params![peer_id],
                friend_link_from_row,
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn friend_link(&self, link_id: &str) -> Result<FriendLinkRecord, StorageError> {
        Ok(self.connection.query_row(
            "SELECT link_id, requester_id, target_id, state, remove_scope, blocked, capability_revoked_at
               FROM friend_link_projection
              WHERE link_id = ?1",
            params![link_id],
            friend_link_from_row,
        )?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn friend_links(&self) -> Result<Vec<FriendLinkRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT link_id, requester_id, target_id, state, remove_scope, blocked, capability_revoked_at
               FROM friend_link_projection
              ORDER BY updated_at ASC, link_id ASC",
        )?;
        let rows = statement.query_map([], friend_link_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StorageError::from)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn reject_inbox_message(
        &self,
        conversation_id: &str,
        message_id: &str,
        sender_id: &str,
        reason: &str,
        rejected_at: i64,
    ) -> Result<RejectedInboxRecord, StorageError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO rejected_inbox_projection
                (conversation_id, message_id, sender_id, reason, rejected_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![conversation_id, message_id, sender_id, reason, rejected_at],
        )?;
        self.rejected_inbox_message(message_id)?
            .ok_or_else(|| StorageError::MessageNotFound(message_id.to_owned()))
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn rejected_inbox_message(
        &self,
        message_id: &str,
    ) -> Result<Option<RejectedInboxRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT conversation_id, message_id, sender_id, reason, rejected_at
                   FROM rejected_inbox_projection
                  WHERE message_id = ?1",
                params![message_id],
                rejected_inbox_from_row,
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn rejected_inbox(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<RejectedInboxRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT conversation_id, message_id, sender_id, reason, rejected_at
               FROM rejected_inbox_projection
              WHERE conversation_id = ?1
              ORDER BY rejected_at ASC, message_id ASC",
        )?;
        let rows = statement.query_map(params![conversation_id], rejected_inbox_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StorageError::from)
    }
}
