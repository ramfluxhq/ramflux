// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded metadata queries for the local client read model.

use super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

impl AccountDb {
    /// Reads a bounded keyset of directory identifiers without loading payloads.
    ///
    /// # Errors
    /// Returns an error for unsupported directories or failed SQL queries.
    pub fn client_directory_ids(
        &self,
        directory: &str,
        after: &str,
        limit: u32,
    ) -> Result<Vec<String>, StorageError> {
        let sql = match directory {
            "conversation" => {
                "SELECT conversation_id AS id FROM direct_message_projection UNION SELECT conversation_id FROM conversation_projection UNION SELECT conversation_id FROM conversation_list_state UNION SELECT substr(state_kind,24) FROM runtime_actor_state WHERE state_kind GLOB 'directory/conversation/*'"
            }
            "identity" => {
                "SELECT substr(state_kind,20) AS id FROM runtime_actor_state WHERE state_kind GLOB 'directory/identity/*'"
            }
            "object" => "SELECT object_id AS id FROM object_index WHERE tombstoned=0",
            "group" => "SELECT group_id AS id FROM group_projection WHERE deleted_at IS NULL",
            "server" => "SELECT server_id AS id FROM mcp_server_registry",
            "approval" => {
                "SELECT substr(state_kind,20) AS id FROM runtime_actor_state WHERE state_kind GLOB 'directory/approval/*' AND json_extract(CAST(state_json AS TEXT),'$.status')='pending'"
            }
            _ => return Err(StorageError::AuthorizationRejected),
        };
        let mut statement = self
            .connection
            .prepare(&format!("SELECT id FROM ({sql}) WHERE id>?1 ORDER BY id LIMIT ?2"))?;
        Ok(statement
            .query_map(params![after, limit.min(101)], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Returns one persisted, explicit metadata record.
    ///
    /// # Errors
    /// Returns errors querying or decoding the record.
    pub fn client_record(&self, directory: &str, id: &str) -> Result<Option<Value>, StorageError> {
        self.load_actor_state(&format!("directory/{directory}/{id}"))
    }

    /// Persists metadata through the account writer, with transaction-local outbox invalidation.
    ///
    /// # Errors
    /// Returns an error for a failed durable write.
    pub fn persist_client_record(
        &self,
        directory: &str,
        id: &str,
        value: &Value,
    ) -> Result<(), StorageError> {
        self.persist_actor_state(&format!("directory/{directory}/{id}"), value)
    }

    /// Reads scalar object metadata; ciphertext/key/body columns are deliberately never selected.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn client_object_metadata(&self, id: &str) -> Result<Value, StorageError> {
        Ok(self.connection.query_row("SELECT object_id, CASE WHEN total_cipher_size>=16 THEN total_cipher_size-16 ELSE NULL END, object_state, updated_at FROM object_index WHERE object_id=?1 AND tombstoned=0", params![id], |row| {
            Ok(json!({"id":row.get::<_,String>(0)?,"size":row.get::<_,Option<i64>>(1)?,"transfer_state":row.get::<_,String>(2)?,"updated_at":row.get::<_,i64>(3)?}))
        })?)
    }

    /// Returns the latest transfer's public metadata without resume tokens or bitmaps.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn client_object_transfer(&self, id: &str) -> Result<Option<Value>, StorageError> {
        Ok(self.connection.query_row("SELECT transfer_id,state,peer_device_id,updated_at FROM object_transfer_state WHERE object_id=?1 ORDER BY updated_at DESC,transfer_id LIMIT 1",params![id],|row| Ok(json!({"id":row.get::<_,String>(0)?,"state":row.get::<_,String>(1)?,"peer_device_id":row.get::<_,String>(2)?,"updated_at":row.get::<_,i64>(3)?}))).optional()?)
    }

    /// Reads participants' device identifiers without message payloads.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn client_conversation_senders(&self, id: &str) -> Result<Vec<String>, StorageError> {
        let mut statement=self.connection.prepare("SELECT DISTINCT sender_id FROM direct_message_projection WHERE conversation_id=?1 ORDER BY sender_id LIMIT 256")?;
        Ok(statement
            .query_map(params![id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Returns a directory row including flags and the existing authoritative unread projection.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn client_conversation_metadata(
        &self,
        id: &str,
        reader: &str,
    ) -> Result<Value, StorageError> {
        let state = self.read_conversation_list_state(id)?;
        let projection = self.conversation_projection(id, reader)?;
        let activity:Option<i64>=self.connection.query_row("SELECT max(created_at) FROM direct_message_projection WHERE conversation_id=?1 AND deleted=0",params![id],|row|row.get(0))?;
        let unread:u64=self.connection.query_row("SELECT count(*) FROM direct_message_projection m WHERE m.conversation_id=?1 AND m.deleted=0 AND m.created_at>?3 AND NOT EXISTS (SELECT 1 FROM conversation_read_state r JOIN direct_message_projection last ON last.message_id=r.read_through_message_id WHERE r.conversation_id=?1 AND r.reader_id=?2 AND (m.created_at<last.created_at OR (m.created_at=last.created_at AND m.message_id<=last.message_id)))",params![id,reader,state.cleared_at.unwrap_or(i64::MIN)],|row|row.get(0))?;
        Ok(
            json!({"id":id,"archived":state.archived,"hidden":state.hidden_at.is_some(),"last_activity":activity,"unread_count":unread,"is_unread":projection.is_unread,"muted":state.mute_until.is_some_and(|until|until>self.now_unix()),"mute_until":state.mute_until,"disappearing":self.disappearing_policy(id)?.map(|policy|json!({"timer_seconds":policy.timer_seconds,"countdown_mode":policy.countdown_mode,"scope":policy.scope}))}),
        )
    }
}
