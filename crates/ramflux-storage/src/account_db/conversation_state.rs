#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::conversation_helpers::disappearing_tombstone_id;
use rusqlite::OptionalExtension;

impl AccountDb {
    pub fn set_disappearing_policy(
        &self,
        conversation_id: &str,
        timer_seconds: i64,
        countdown_mode: &str,
        scope: &str,
        updated_at: i64,
    ) -> Result<DisappearingPolicyRecord, StorageError> {
        self.connection.execute(
            "INSERT INTO conversation_disappearing_policy
                (conversation_id, timer_seconds, countdown_mode, scope, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(conversation_id)
             DO UPDATE SET timer_seconds = excluded.timer_seconds,
                           countdown_mode = excluded.countdown_mode,
                           scope = excluded.scope,
                           updated_at = excluded.updated_at",
            params![conversation_id, timer_seconds, countdown_mode, scope, updated_at],
        )?;
        Ok(DisappearingPolicyRecord {
            conversation_id: conversation_id.to_owned(),
            timer_seconds,
            countdown_mode: countdown_mode.to_owned(),
            scope: scope.to_owned(),
            updated_at,
        })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn disappearing_policy(
        &self,
        conversation_id: &str,
    ) -> Result<Option<DisappearingPolicyRecord>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT conversation_id, timer_seconds, countdown_mode, scope, updated_at
                   FROM conversation_disappearing_policy
                  WHERE conversation_id = ?1",
                params![conversation_id],
                |row| {
                    Ok(DisappearingPolicyRecord {
                        conversation_id: row.get(0)?,
                        timer_seconds: row.get(1)?,
                        countdown_mode: row.get(2)?,
                        scope: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn expire_disappearing_messages(
        &self,
        conversation_id: &str,
        now: i64,
    ) -> Result<Vec<MessageTombstoneRecord>, StorageError> {
        let Some(policy) = self.disappearing_policy(conversation_id)? else {
            return Ok(Vec::new());
        };
        if policy.timer_seconds <= 0 || policy.countdown_mode != "on_send" {
            return Ok(Vec::new());
        }
        let expires_before_or_at = now - policy.timer_seconds;
        let mut statement = self.connection.prepare(
            "SELECT message_id
               FROM direct_message_projection
              WHERE conversation_id = ?1 AND deleted = 0 AND created_at <= ?2
              ORDER BY created_at ASC, message_id ASC",
        )?;
        let rows = statement.query_map(params![conversation_id, expires_before_or_at], |row| {
            row.get::<_, String>(0)
        })?;
        let mut message_ids = Vec::new();
        for row in rows {
            message_ids.push(row?);
        }
        drop(statement);

        let mut tombstones = Vec::new();
        for message_id in message_ids {
            let tombstone_id = disappearing_tombstone_id(conversation_id, &message_id);
            self.connection.execute(
                "UPDATE direct_message_projection
                    SET deleted = 1, encrypted_body = x''
                  WHERE conversation_id = ?1 AND message_id = ?2 AND deleted = 0",
                params![conversation_id, message_id],
            )?;
            self.connection.execute(
                "INSERT OR REPLACE INTO message_tombstone_projection
                    (tombstone_id, conversation_id, message_id, delete_scope, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![tombstone_id, conversation_id, message_id, policy.scope, now],
            )?;
            tombstones.push(MessageTombstoneRecord {
                tombstone_id,
                conversation_id: conversation_id.to_owned(),
                message_id,
                delete_scope: policy.scope.clone(),
            });
        }
        Ok(tombstones)
    }

    pub fn typing_started(
        &self,
        conversation_id: &str,
        actor_identity: &str,
        started_at: i64,
        ttl_seconds: i64,
        privacy_scope: &str,
    ) {
        let ttl_seconds =
            bounded_ttl_seconds(ttl_seconds, DEFAULT_TYPING_TTL_SECONDS, MAX_TYPING_TTL_SECONDS);
        let record = TypingStateRecord {
            conversation_id: conversation_id.to_owned(),
            actor_identity: actor_identity.to_owned(),
            started_at,
            expires_at: started_at.saturating_add(ttl_seconds),
            privacy_scope: privacy_scope.to_owned(),
        };
        self.volatile_typing
            .borrow_mut()
            .insert((conversation_id.to_owned(), actor_identity.to_owned()), record);
    }

    pub fn typing_stopped(&self, conversation_id: &str, actor_identity: &str) {
        self.volatile_typing
            .borrow_mut()
            .remove(&(conversation_id.to_owned(), actor_identity.to_owned()));
    }

    #[must_use]
    pub fn active_typing(&self, conversation_id: &str, now: i64) -> Vec<TypingStateRecord> {
        let mut typing = self.volatile_typing.borrow_mut();
        typing.retain(|_key, record| record.expires_at > now);
        typing
            .values()
            .filter(|record| record.conversation_id == conversation_id)
            .cloned()
            .collect()
    }

    pub fn update_contact_presence(&self, update: ContactPresenceUpdate<'_>) {
        let ttl_seconds = bounded_ttl_seconds(
            update.ttl_seconds,
            DEFAULT_CONTACT_PRESENCE_TTL_SECONDS,
            MAX_CONTACT_PRESENCE_TTL_SECONDS,
        );
        let record = ContactPresenceRecord {
            identity_commitment: update.identity_commitment.to_owned(),
            presence_state: update.presence_state.to_owned(),
            last_seen_at: update.last_seen_at,
            expires_at: update.observed_at.saturating_add(ttl_seconds),
            privacy_scope: update.privacy_scope.to_owned(),
        };
        self.volatile_presence.borrow_mut().insert(update.identity_commitment.to_owned(), record);
    }

    #[must_use]
    pub fn contact_presence(
        &self,
        identity_commitment: &str,
        now: i64,
    ) -> Option<ContactPresenceRecord> {
        let mut presence = self.volatile_presence.borrow_mut();
        presence.retain(|_key, record| record.expires_at > now);
        presence.get(identity_commitment).cloned()
    }
}
