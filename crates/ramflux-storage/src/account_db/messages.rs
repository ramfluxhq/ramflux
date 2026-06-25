// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;

impl AccountDb {
    pub fn send_direct_message(
        &self,
        conversation_id: &str,
        message_id: &str,
        sender_id: &str,
        encrypted_body: &[u8],
    ) -> Result<(), StorageError> {
        self.send_direct_message_with_metadata(
            conversation_id,
            message_id,
            sender_id,
            encrypted_body,
            &MessageMetadata::default(),
        )
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn send_direct_message_with_metadata(
        &self,
        conversation_id: &str,
        message_id: &str,
        sender_id: &str,
        encrypted_body: &[u8],
        metadata: &MessageMetadata,
    ) -> Result<(), StorageError> {
        self.send_direct_message_at_with_metadata(DirectMessageWrite {
            conversation_id,
            message_id,
            sender_id,
            encrypted_body,
            metadata,
            created_at: self.now_unix(),
        })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn send_direct_message_at_with_metadata(
        &self,
        message: DirectMessageWrite<'_>,
    ) -> Result<(), StorageError> {
        self.ensure_identity_can_send(message.sender_id)?;
        let metadata_json = serde_json::to_vec(message.metadata)?;
        self.connection.execute(
            "INSERT INTO direct_message_projection
                (conversation_id, message_id, sender_id, encrypted_body, metadata_json, deleted, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![
                message.conversation_id,
                message.message_id,
                message.sender_id,
                message.encrypted_body,
                metadata_json,
                message.created_at
            ],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn message_mentions(
        &self,
        conversation_id: &str,
        message_id: &str,
        identity_commitment: &str,
    ) -> Result<bool, StorageError> {
        let metadata = self.message_metadata(conversation_id, message_id)?;
        Ok(metadata.mentions.iter().any(|mention| mention == identity_commitment))
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn message_metadata(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<MessageMetadata, StorageError> {
        let metadata_json: Vec<u8> = self.connection.query_row(
            "SELECT metadata_json
               FROM direct_message_projection
              WHERE conversation_id = ?1 AND message_id = ?2",
            params![conversation_id, message_id],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_slice(&metadata_json)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn direct_messages(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<DirectMessageRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT conversation_id, message_id, sender_id, encrypted_body, metadata_json, deleted
               FROM direct_message_projection
              WHERE conversation_id = ?1
              ORDER BY created_at ASC, message_id ASC",
        )?;
        let rows = statement.query_map(params![conversation_id], |row| {
            let metadata_json: Vec<u8> = row.get(4)?;
            Ok(DirectMessageRecord {
                conversation_id: row.get(0)?,
                message_id: row.get(1)?,
                sender_id: row.get(2)?,
                encrypted_body: row.get(3)?,
                metadata: serde_json::from_slice(&metadata_json).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Blob,
                        Box::new(err),
                    )
                })?,
                deleted: row.get::<_, i64>(5)? != 0,
            })
        })?;
        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    /// # Errors
    pub fn delete_direct_message(
        &self,
        conversation_id: &str,
        message_id: &str,
        delete_scope: &str,
        tombstone_id: &str,
    ) -> Result<MessageTombstoneRecord, StorageError> {
        let changed = self.connection.execute(
            "UPDATE direct_message_projection
                SET deleted = 1, encrypted_body = x''
              WHERE conversation_id = ?1 AND message_id = ?2 AND deleted = 0",
            params![conversation_id, message_id],
        )?;
        if changed == 0 {
            return Err(StorageError::MessageNotFound(message_id.to_owned()));
        }
        self.connection.execute(
            "INSERT OR REPLACE INTO message_tombstone_projection
                (tombstone_id, conversation_id, message_id, delete_scope, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![tombstone_id, conversation_id, message_id, delete_scope, self.now_unix()],
        )?;
        Ok(MessageTombstoneRecord {
            tombstone_id: tombstone_id.to_owned(),
            conversation_id: conversation_id.to_owned(),
            message_id: message_id.to_owned(),
            delete_scope: delete_scope.to_owned(),
        })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn message_tombstone(
        &self,
        tombstone_id: &str,
    ) -> Result<MessageTombstoneRecord, StorageError> {
        Ok(self.connection.query_row(
            "SELECT tombstone_id, conversation_id, message_id, delete_scope
               FROM message_tombstone_projection
              WHERE tombstone_id = ?1",
            params![tombstone_id],
            |row| {
                Ok(MessageTombstoneRecord {
                    tombstone_id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    message_id: row.get(2)?,
                    delete_scope: row.get(3)?,
                })
            },
        )?)
    }
}
