// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::contact_consent::LinkConsentChange;
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
        self.persist_link_consent(
            link_id,
            LinkConsentChange::Establish {
                requester: requester_id.to_owned(),
                target: target_id.to_owned(),
                at: self.now_unix(),
            },
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
        self.persist_link_consent(
            link_id,
            LinkConsentChange::Remove { scope: scope.to_owned(), at: removed_at },
        )?;
        self.friend_link(link_id)
    }

    /// Records an inbound friend request as a `pending` friend link awaiting the
    /// recipient's accept/reject decision. Idempotent via `INSERT OR IGNORE`: it
    /// never downgrades an already-established (e.g. `accepted`) link back to
    /// `pending`.
    ///
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn record_pending_friend_link(
        &self,
        link_id: &str,
        requester_id: &str,
        target_id: &str,
        requested_at: i64,
    ) -> Result<FriendLinkRecord, StorageError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO friend_link_projection
                (link_id, requester_id, target_id, state, remove_scope, blocked, capability_revoked_at, updated_at)
             VALUES (?1, ?2, ?3, 'pending', NULL, 0, NULL, ?4)",
            params![link_id, requester_id, target_id, requested_at],
        )?;
        self.friend_link(link_id)
    }

    /// Declines a pending inbound friend request, transitioning it from
    /// `pending` to `rejected`. This is distinct from remove/block, which act on
    /// an already-established (`accepted`) contact: rejecting a link that is not
    /// a pending inbound request is refused with `AuthorizationRejected`.
    ///
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn reject_friend_link(
        &self,
        link_id: &str,
        rejected_at: i64,
    ) -> Result<FriendLinkRecord, StorageError> {
        if !self.persist_link_consent(link_id, LinkConsentChange::Decline(rejected_at))? {
            return Err(StorageError::AuthorizationRejected);
        }
        self.friend_link(link_id)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn block_friend_link(
        &self,
        link_id: &str,
        blocked_at: i64,
    ) -> Result<FriendLinkRecord, StorageError> {
        self.persist_link_consent(link_id, LinkConsentChange::Block(blocked_at))?;
        self.friend_link(link_id)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn unblock_friend_link(
        &self,
        link_id: &str,
        unblocked_at: i64,
    ) -> Result<FriendLinkRecord, StorageError> {
        self.persist_link_consent(link_id, LinkConsentChange::Unblock(unblocked_at))?;
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
        self.find_friend_link(link_id)?
            .ok_or_else(|| StorageError::Sqlite(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Looks up a friend link without treating an absent peer-supplied ID as a storage failure.
    ///
    /// # Errors
    /// Returns real SQL, I/O, or row decoding errors.
    pub fn find_friend_link(
        &self,
        link_id: &str,
    ) -> Result<Option<FriendLinkRecord>, StorageError> {
        Ok(self.connection.query_row(
            "SELECT link_id, requester_id, target_id, state, remove_scope, blocked, capability_revoked_at
               FROM friend_link_projection
              WHERE link_id = ?1",
            params![link_id],
            friend_link_from_row,
        ).optional()?)
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

    /// Read a bounded page for own-device contact backfill, ordered by stable link ID.
    /// # Errors
    /// Returns storage errors while loading the page.
    pub fn friend_link_page(
        &self,
        after: &str,
        limit: u32,
    ) -> Result<Vec<FriendLinkRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT link_id, requester_id, target_id, state, remove_scope, blocked, capability_revoked_at
             FROM friend_link_projection WHERE link_id > ?1 ORDER BY link_id LIMIT ?2")?;
        let rows = statement.query_map(params![after, limit.min(64)], friend_link_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StorageError::from)
    }

    /// Pages restrictions or accepted links directly, avoiding a full acceptance scan before tombstones.
    /// # Errors
    /// Returns storage errors while reading at most 64 matching rows.
    pub fn friend_link_backfill_page(
        &self,
        after: &str,
        limit: u32,
        restrictions: bool,
    ) -> Result<Vec<FriendLinkRecord>, StorageError> {
        let mut statement=self.connection.prepare(
            "SELECT link_id, requester_id, target_id, state, remove_scope, blocked, capability_revoked_at
             FROM friend_link_projection WHERE link_id > ?1
             AND ((state = 'removed' OR blocked != 0 OR capability_revoked_at IS NOT NULL) = ?3)
             AND (?3 OR state = 'accepted') ORDER BY link_id LIMIT ?2")?;
        let rows = statement
            .query_map(params![after, limit.min(64), restrictions], friend_link_from_row)?;
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
