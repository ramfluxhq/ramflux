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
            "surface" => {
                "SELECT substr(state_kind,19) AS id FROM runtime_actor_state WHERE state_kind GLOB 'directory/surface/*'"
            }
            "device" => {
                "SELECT substr(state_kind,18) AS id FROM runtime_actor_state WHERE state_kind GLOB 'directory/device/*'"
            }
            "conversation" => {
                "SELECT conversation_id AS id FROM direct_message_projection UNION SELECT conversation_id FROM conversation_projection UNION SELECT conversation_id FROM conversation_list_state UNION SELECT substr(state_kind,24) FROM runtime_actor_state WHERE state_kind GLOB 'directory/conversation/*'"
            }
            "identity" => {
                "SELECT substr(state_kind,20) AS id FROM runtime_actor_state WHERE state_kind GLOB 'directory/identity/*'"
            }
            "object" => {
                "SELECT object_id AS id FROM object_index WHERE tombstoned=0 UNION SELECT substr(m.state_kind,18) AS id FROM runtime_actor_state m WHERE m.state_kind GLOB 'directory/object/*' AND EXISTS(SELECT 1 FROM runtime_actor_state r WHERE r.state_kind='attachment/reference/'||substr(m.state_kind,18)) AND NOT EXISTS(SELECT 1 FROM object_index o WHERE o.object_id=substr(m.state_kind,18) AND o.tombstoned=1)"
            }
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
        if directory == "device" {
            return self.device_record(id);
        }
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
        if directory == "device" {
            return self.persist_device_metadata(id, value);
        }
        self.persist_actor_state(&format!("directory/{directory}/{id}"), value)
    }

    /// Reads scalar object metadata; ciphertext/key/body columns are deliberately never selected.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn client_object_metadata(&self, id: &str) -> Result<Value, StorageError> {
        Ok(self.connection.query_row("SELECT object_id, CASE WHEN total_cipher_size>=16 THEN total_cipher_size-16 ELSE NULL END, object_state, updated_at FROM object_index WHERE object_id=?1 AND tombstoned=0", params![id], |row| {
            Ok(json!({"id":row.get::<_,String>(0)?,"size":row.get::<_,Option<i64>>(1)?,"transfer_state":row.get::<_,String>(2)?,"updated_at":row.get::<_,i64>(3)?}))
        }).optional()?.unwrap_or_else(|| json!({"id":id,"transfer_state":"not_fetched","size":null,"updated_at":null})))
    }

    /// Returns the latest transfer's public metadata without resume tokens or bitmaps.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn client_object_transfer(&self, id: &str) -> Result<Option<Value>, StorageError> {
        Ok(self.connection.query_row("SELECT transfer_id,state,peer_device_id,updated_at,direction,total_bytes,done_bytes FROM object_transfer_state WHERE object_id=?1 ORDER BY updated_at DESC,transfer_id LIMIT 1",params![id],|row| {
            let total:u64=row.get(5)?;let done:u64=row.get(6)?;
            let percent=if total==0 {0} else {done.saturating_mul(100).checked_div(total).unwrap_or(0).min(100)};
            Ok(json!({"id":row.get::<_,String>(0)?,"object_id":id,"state":row.get::<_,String>(1)?,"peer_device_id":row.get::<_,String>(2)?,"updated_at":row.get::<_,i64>(3)?,"direction":row.get::<_,String>(4)?,"total_bytes":total,"done_bytes":done,"percent":percent}))
        }).optional()?)
    }

    /// Reads participants' device identifiers without message payloads.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn client_conversation_senders(&self, id: &str) -> Result<Vec<String>, StorageError> {
        let mut statement=self.connection.prepare("SELECT DISTINCT sender_id FROM direct_message_projection WHERE conversation_id=?1 AND deleted=0 ORDER BY sender_id LIMIT 256")?;
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
        reader: Option<&ramflux_crypto::RootQualifiedDeviceRef>,
    ) -> Result<Value, StorageError> {
        let state = self.read_conversation_list_state(id)?;
        let projection = self.conversation_projection(id, reader)?;
        let reader = reader.map(ramflux_crypto::RootQualifiedDeviceRef::storage_key);
        let activity:Option<i64>=self.connection.query_row("SELECT max(created_at) FROM direct_message_projection WHERE conversation_id=?1 AND deleted=0",params![id],|row|row.get(0))?;
        let unread:u64=self.connection.query_row("SELECT count(*) FROM direct_message_projection m WHERE m.conversation_id=?1 AND m.deleted=0 AND m.created_at>?3 AND NOT EXISTS (SELECT 1 FROM conversation_read_state r JOIN direct_message_projection last ON last.message_id=r.read_through_message_id WHERE r.conversation_id=?1 AND r.reader_id=?2 AND (m.created_at<last.created_at OR (m.created_at=last.created_at AND m.message_id<=last.message_id)))",params![id,reader,state.cleared_at.unwrap_or(i64::MIN)],|row|row.get(0))?;
        Ok(
            json!({"id":id,"archived":state.archived,"hidden":state.hidden_at.is_some(),"last_activity":activity,"unread_count":unread,"is_unread":projection.is_unread,"muted":state.mute_until.is_some_and(|until|until>self.now_unix()),"mute_until":state.mute_until,"disappearing":self.disappearing_policy(id)?.map(|policy|json!({"timer_seconds":policy.timer_seconds,"countdown_mode":policy.countdown_mode,"scope":policy.scope}))}),
        )
    }
}

impl AccountDb {
    /// Reads message list-row metadata without loading its approved plaintext content.
    ///
    /// # Errors
    /// Returns SQL errors.
    pub fn client_message_metadata(&self, id: &str) -> Result<Option<Value>, StorageError> {
        Ok(self.connection.query_row("SELECT message_id,conversation_id,sender_id,deleted,is_own,created_at FROM direct_message_projection WHERE message_id=?1",params![id],|row|{
            let deleted=row.get::<_,i64>(3)?!=0;
            if deleted {
                Ok(json!({"deleted":true,"conversation_id":row.get::<_,String>(1)?,"is_own":row.get::<_,i64>(4)?!=0,"created_at":row.get::<_,i64>(5)?}))
            } else {
                Ok(json!({"id":row.get::<_,String>(0)?,"message_id":row.get::<_,String>(0)?,"conversation_id":row.get::<_,String>(1)?,"sender_id":row.get::<_,String>(2)?,"deleted":false,"created_at":row.get::<_,i64>(5)?}))
            }
        }).optional()?)
    }
    /// Reads an existing audit record for explicit metadata-field projection.
    ///
    /// # Errors
    /// Returns SQL/JSON errors.
    pub fn client_audit_metadata(&self, row_id: i64) -> Result<Option<Value>, StorageError> {
        let body: Option<Vec<u8>> = self
            .connection
            .query_row("SELECT audit_body FROM audit_log WHERE rowid=?1", params![row_id], |row| {
                row.get(0)
            })
            .optional()?
            .flatten();
        body.map(|bytes| serde_json::from_slice(&bytes).map_err(StorageError::from)).transpose()
    }
}

impl AccountDb {
    /// Returns bounded attachment metadata associated with an approved message read.
    ///
    /// # Errors
    /// Returns SQL/JSON decoding errors.
    pub fn client_message_object_ids(&self, message: &str) -> Result<Vec<String>, StorageError> {
        let mut statement=self.connection.prepare("SELECT substr(state_kind,18) FROM runtime_actor_state WHERE state_kind GLOB 'directory/object/*' AND json_extract(CAST(state_json AS TEXT),'$.message_id')=?1 ORDER BY state_kind LIMIT 128")?;
        Ok(statement
            .query_map(params![message], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

impl AccountDb {
    /// Selects a bounded background-fetch page using identifiers and public scheduling state only.
    ///
    /// # Errors
    /// Returns SQL errors. Private attachment reference bodies are never selected.
    pub fn pending_received_attachment_ids(
        &self,
        now: i64,
        limit: u32,
    ) -> Result<Vec<String>, StorageError> {
        let mut query = self.connection.prepare(
            "SELECT substr(r.state_kind,22) AS id FROM runtime_actor_state r
             LEFT JOIN runtime_actor_state f ON f.state_kind='attachment/fetch/'||substr(r.state_kind,22)
             LEFT JOIN runtime_actor_state s ON s.state_kind='sync/attachment/'||substr(r.state_kind,22)
             WHERE r.state_kind GLOB 'attachment/reference/*'
               AND coalesce(json_extract(CAST(f.state_json AS TEXT),'$.transfer_state'),'not_fetched')<>'available'
               AND coalesce(json_extract(CAST(s.state_json AS TEXT),'$.attempts'),0)<3
               AND coalesce(json_extract(CAST(s.state_json AS TEXT),'$.next_at'),0)<=?1
             ORDER BY r.state_kind LIMIT ?2",
        )?;
        Ok(query
            .query_map(params![now, limit.min(64)], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
}
