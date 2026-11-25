// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wake notification candidates. One candidate per first-projected incoming visible message,
//! written in the same receive transaction as the projection. A wake decision revalidates every
//! candidate against read, clear, delete and mute state, then consumes all of them in one
//! transaction. Candidates hold ids and a timestamp only; they never carry message bodies.

use super::AccountDb;
use crate::StorageError;
use rusqlite::params;
use serde::{Deserialize, Serialize};

/// Actor-state namespace of pending candidates. Keys sort oldest first.
const CANDIDATE_PREFIX: &str = "notify/candidate/";
/// Pending candidates kept at once; the oldest is evicted when a new one arrives at the cap.
pub(crate) const CANDIDATE_CAP: u64 = 256;
const PAGE: u32 = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    conversation_id: String,
    message_id: String,
    created_at: i64,
}

/// Result of one wake decision, computed and consumed in one transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NotificationDecision {
    /// At least one pending candidate is still an unread, unmuted, visible incoming message.
    pub show: bool,
    /// Whether any unread, unmuted, visible incoming message remains account-wide.
    pub eligible_unread_remains: bool,
    /// Ordinary unread total (muted conversations included), same snapshot.
    pub unread_total: u64,
}

fn candidate_key(created_at: i64, message_id: &str) -> String {
    let order = u64::try_from(created_at).unwrap_or(0);
    format!("{CANDIDATE_PREFIX}{order:020}/{message_id}")
}

impl AccountDb {
    /// Records one first-projected incoming visible message. Call inside the projection
    /// transaction so the candidate commits or rolls back with the projection.
    ///
    /// # Errors
    /// Returns storage errors from the eviction or the footprint-owned write.
    pub fn record_notification_candidate(
        &self,
        conversation_id: &str,
        message_id: &str,
        created_at: i64,
    ) -> Result<(), StorageError> {
        self.join_write(|| {
            let (count, _) = self.actor_state_usage(CANDIDATE_PREFIX)?;
            if count >= CANDIDATE_CAP {
                for key in self.candidate_keys_page("", 1)? {
                    self.retire_candidate_key(&key)?;
                }
            }
            let value = Candidate {
                conversation_id: conversation_id.to_owned(),
                message_id: message_id.to_owned(),
                created_at,
            };
            self.persist_message_actor_state(message_id, &candidate_key(created_at, message_id), &value)
        })
    }

    /// Revalidates all pending candidates and consumes every one of them, including suppressed
    /// ones, in a single transaction. `reader` selects the read cursor, as in the directory total.
    ///
    /// # Errors
    /// Returns storage errors; on error nothing is consumed.
    pub fn consume_notification_decision(
        &self,
        reader: Option<&ramflux_crypto::RootQualifiedDeviceRef>,
    ) -> Result<NotificationDecision, StorageError> {
        let reader_key = reader.map(ramflux_crypto::RootQualifiedDeviceRef::storage_key);
        self.join_write(|| {
            let now = self.now_unix();
            let unread_total = self.client_conversation_totals(reader)?.unread;
            let keys = self.all_candidate_keys()?;
            let mut show = false;
            for key in &keys {
                let candidate: Candidate = self
                    .load_actor_state(key)?
                    .ok_or(StorageError::Integrity("notification candidate vanished"))?;
                if !show && self.candidate_eligible(&candidate, reader_key, now)? {
                    show = true;
                }
            }
            let eligible_unread_remains = self.eligible_unread_exists(reader_key, now)?;
            for key in &keys {
                self.retire_candidate_key(key)?;
            }
            Ok(NotificationDecision { show, eligible_unread_remains, unread_total })
        })
    }

    fn all_candidate_keys(&self) -> Result<Vec<String>, StorageError> {
        let mut keys = Vec::new();
        let mut after = String::new();
        // The cap bounds the namespace; one extra empty page ends the walk.
        for _ in 0..=(CANDIDATE_CAP / u64::from(PAGE) + 1) {
            let page = self.candidate_keys_page(&after, PAGE)?;
            let Some(last) = page.last().cloned() else { break };
            after = last;
            keys.extend(page);
        }
        if u64::try_from(keys.len()).unwrap_or(u64::MAX) > CANDIDATE_CAP {
            return Err(StorageError::Integrity("notification candidates exceed cap"));
        }
        Ok(keys)
    }

    fn candidate_keys_page(&self, after: &str, limit: u32) -> Result<Vec<String>, StorageError> {
        self.actor_state_key_page_after(CANDIDATE_PREFIX, after, limit)
    }

    fn candidate_eligible(
        &self,
        candidate: &Candidate,
        reader: Option<&str>,
        now: i64,
    ) -> Result<bool, StorageError> {
        self.connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM direct_message_projection m
                     WHERE m.message_id = ?1 AND m.conversation_id = ?2
                       AND m.deleted = 0 AND m.is_own = 0
                       AND m.created_at > coalesce(
                            (SELECT cleared_at FROM conversation_list_state
                              WHERE conversation_id = m.conversation_id), ?3)
                       AND NOT EXISTS (
                            SELECT 1 FROM conversation_list_state s
                             WHERE s.conversation_id = m.conversation_id AND s.mute_until > ?4)
                       AND NOT EXISTS (
                            SELECT 1 FROM conversation_read_state r
                            JOIN direct_message_projection last
                              ON last.message_id = r.read_through_message_id
                           WHERE r.conversation_id = m.conversation_id AND r.reader_id = ?5
                             AND (m.created_at < last.created_at
                                  OR (m.created_at = last.created_at
                                      AND m.message_id <= last.message_id))))",
                params![
                    candidate.message_id,
                    candidate.conversation_id,
                    i64::MIN,
                    now,
                    reader
                ],
                |row| row.get(0),
            )
            .map_err(StorageError::from)
    }

    fn eligible_unread_exists(&self, reader: Option<&str>, now: i64) -> Result<bool, StorageError> {
        self.connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM direct_message_projection m
                     WHERE m.deleted = 0 AND m.is_own = 0
                       AND m.created_at > coalesce(
                            (SELECT cleared_at FROM conversation_list_state
                              WHERE conversation_id = m.conversation_id), ?1)
                       AND NOT EXISTS (
                            SELECT 1 FROM conversation_list_state s
                             WHERE s.conversation_id = m.conversation_id AND s.mute_until > ?2)
                       AND NOT EXISTS (
                            SELECT 1 FROM conversation_read_state r
                            JOIN direct_message_projection last
                              ON last.message_id = r.read_through_message_id
                           WHERE r.conversation_id = m.conversation_id AND r.reader_id = ?3
                             AND (m.created_at < last.created_at
                                  OR (m.created_at = last.created_at
                                      AND m.message_id <= last.message_id))))",
                params![i64::MIN, now, reader],
                |row| row.get(0),
            )
            .map_err(StorageError::from)
    }

    /// Removes one candidate and its message-footprint rows. Caller owns the transaction.
    fn retire_candidate_key(&self, key: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM message_copy_binding WHERE copy_id=?1",
            params![format!("actor:{key}")],
        )?;
        self.connection.execute(
            "DELETE FROM message_footprint WHERE kind='actor' AND locator=?1",
            params![key],
        )?;
        self.remove_actor_state(key)
    }
}
