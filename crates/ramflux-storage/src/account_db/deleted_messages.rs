// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transactional erasure of identity-bearing fields from deleted message records.

use super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

impl AccountDb {
    pub(super) fn scrub_deleted_messages(&self) -> Result<(), StorageError> {
        let rows = {
            let mut statement = self.connection.prepare(
                "SELECT conversation_id,message_id FROM direct_message_projection WHERE deleted=1",
            )?;
            statement
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        if rows.is_empty() {
            return Ok(());
        }
        self.write_transaction(|| {
            for (conversation, message) in &rows {
                self.scrub_message_for_deletion(conversation, message, None)?;
            }
            Ok::<(), StorageError>(())
        })?;
        self.checkpoint_retired_secrets_if_committed()?;
        Ok(())
    }

    pub(super) fn scrub_message_for_deletion(
        &self,
        conversation: &str,
        message: &str,
        own_override: Option<bool>,
    ) -> Result<bool, StorageError> {
        let Some((sender, was_deleted, stored_own, created_at)) = self
            .connection
            .query_row(
                "SELECT sender_id,deleted,is_own,created_at FROM direct_message_projection WHERE conversation_id=?1 AND message_id=?2",
                params![conversation, message],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get::<_, i64>(2)? != 0,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
        else {
            return Ok(false);
        };
        let is_own = own_override
            .unwrap_or(stored_own || self.message_sender_is_local(conversation, message, &sender)?);
        self.connection.execute(
            "UPDATE direct_message_projection SET sender_id='',encrypted_body=x'',metadata_json=x'7b7d',deleted=1,is_own=?3 WHERE conversation_id=?1 AND message_id=?2",
            params![conversation, message, i64::from(is_own)],
        )?;
        self.connection
            .execute("DELETE FROM runtime_message_content WHERE message_id=?1", params![message])?;
        let object_ids = {
            let mut statement = self.connection.prepare(
                "SELECT substr(state_kind,18) FROM runtime_actor_state WHERE state_kind GLOB 'directory/object/*' AND json_extract(CAST(state_json AS TEXT),'$.message_id')=?1",
            )?;
            statement
                .query_map(params![message], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for object in object_ids {
            self.connection.execute(
                "DELETE FROM runtime_actor_state WHERE state_kind IN (?1,?2,?3) OR state_kind GLOB ?4",
                params![
                    format!("attachment/reference/{object}"),
                    format!("attachment/fetch/{object}"),
                    format!("sync/attachment/{object}"),
                    format!("attachment/chunk/{object}/*"),
                ],
            )?;
        }
        self.connection.execute(
            "DELETE FROM runtime_actor_state WHERE state_kind GLOB 'directory/object/*' AND json_extract(CAST(state_json AS TEXT),'$.message_id')=?1",
            params![message],
        )?;
        let projection = deleted_projection(conversation, created_at, is_own);
        self.connection.execute(
            "UPDATE runtime_actor_state SET state_json=?2 WHERE state_kind=?1",
            params![format!("directory/message/{message}"), serde_json::to_vec(&projection)?],
        )?;
        self.scrub_message_journal(message, &projection)?;
        self.remove_message_origin(conversation, message)?;
        Ok(!was_deleted)
    }

    fn message_sender_is_local(
        &self,
        conversation: &str,
        message: &str,
        sender: &str,
    ) -> Result<bool, StorageError> {
        let origin_key = format!(
            "message/origin/{}",
            ramflux_crypto::blake3_256_base64url(
                "ramflux.delivery-receipt.v1",
                &ramflux_protocol::canonical_json_bytes(&(conversation, message, ""))?,
            )
        );
        if let Some(origin) = self.load_actor_state::<Value>(&origin_key)? {
            return Ok(origin.get("direction").and_then(Value::as_str) == Some("outgoing"));
        }
        if sender == self.local_account_id || sender == self.principal_commitment {
            return Ok(true);
        }
        if ramflux_protocol::parse_qualified_device_id(sender)?
            .is_some_and(|(root, _)| root == self.principal_commitment)
        {
            return Ok(true);
        }
        if self
            .device_signer()
            .is_some_and(|device| sender == device.device_id || sender == device.principal_id)
        {
            return Ok(true);
        }
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM device_identity WHERE device_id=?1 AND principal_commitment=?2)",
            params![sender, self.principal_commitment],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }

    fn scrub_message_journal(&self, message: &str, projection: &Value) -> Result<(), StorageError> {
        let rows = {
            let mut statement = self.connection.prepare(
                "SELECT seq,body_json FROM runtime_journal WHERE topic IN ('message.received','group.message.received','message.updated')",
            )?;
            statement
                .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (seq, bytes) in rows {
            let mut body: Value = serde_json::from_slice(&bytes)?;
            if body
                .pointer("/message/message_id")
                .or_else(|| body.pointer("/message/id"))
                .and_then(Value::as_str)
                == Some(message)
            {
                body["message"] = projection.clone();
                self.connection.execute(
                    "UPDATE runtime_journal SET body_json=?2 WHERE seq=?1",
                    params![seq, serde_json::to_vec(&body)?],
                )?;
            }
        }
        Ok(())
    }
}

fn deleted_projection(conversation: &str, created_at: i64, is_own: bool) -> Value {
    json!({
        "deleted": true,
        "created_at": created_at,
        "conversation_id": conversation,
        "is_own": is_own,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountDbKey, AccountIndex, MessageMetadata};

    #[test]
    fn delete_scrubs_peer_identity_content_attachments_and_journal() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-peer-scrub")?;
        db.send_direct_message_with_metadata(
            "thread",
            "message",
            "peer-device-secret",
            b"encrypted-secret",
            &MessageMetadata {
                mentions: vec!["peer-principal-secret".to_owned()],
                ..MessageMetadata::default()
            },
        )?;
        db.store_message_content("thread", "message", b"plaintext-secret")?;
        db.persist_actor_state(
            "directory/object/attachment",
            &json!({"message_id":"message","owner":"peer-device-secret"}),
        )?;
        db.persist_actor_state(
            "attachment/reference/attachment",
            &json!({"reference":{"manifest_hash":"secret-manifest"}}),
        )?;
        db.append_journal(
            "received-message",
            "message.received",
            &json!({"message":{"message_id":"message","sender_id":"peer-device-secret"}}),
            1,
            None,
        )?;

        db.delete_direct_message("thread", "message", "local", "tombstone")?;

        let message = db
            .direct_message_by_id("message")?
            .ok_or_else(|| StorageError::MessageNotFound("message".to_owned()))?;
        assert!(message.deleted);
        assert!(!message.is_own);
        assert_eq!(message.sender_id, "");
        assert_eq!(message.encrypted_body, Vec::<u8>::new());
        assert_eq!(message.metadata, MessageMetadata::default());
        assert_eq!(message.receipts, Vec::new());
        assert_eq!(db.message_content("message")?, None);
        assert!(!db.actor_state_exists("directory/object/attachment")?);
        assert!(!db.actor_state_exists("attachment/reference/attachment")?);
        assert_eq!(
            db.client_message_metadata("message")?,
            Some(deleted_projection("thread", message.created_at, false))
        );
        let event = db
            .journal_after(0, 10)?
            .into_iter()
            .find(|event| event.topic == "message.received")
            .ok_or(StorageError::AuthorizationRejected)?;
        assert_eq!(event.body["message"], deleted_projection("thread", message.created_at, false));
        assert!(!serde_json::to_string(&event)?.contains("peer-device-secret"));
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn startup_scrub_is_idempotent_and_preserves_only_ownness() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-startup-scrub")?;
        let key = AccountDbKey::derive("acct", b"storage-test-secret");
        db.send_direct_message("thread", "own-message", "principal", b"secret")?;
        db.connection.execute(
            "UPDATE direct_message_projection SET deleted=1 WHERE message_id='own-message'",
            [],
        )?;
        drop(db);

        for pass in 0..2 {
            let db = AccountDb::open(&AccountIndex::open(&root)?, "acct", &key)?;
            let message = db
                .direct_message_by_id("own-message")?
                .ok_or_else(|| StorageError::MessageNotFound("own-message".to_owned()))?;
            assert!(message.deleted);
            assert!(message.is_own);
            assert_eq!(message.sender_id, "");
            assert_eq!(message.encrypted_body, Vec::<u8>::new());
            assert_eq!(message.metadata, MessageMetadata::default());
            assert_eq!(
                db.client_message_metadata("own-message")?,
                Some(deleted_projection("thread", message.created_at, true))
            );
            if pass == 1 {
                let path = root.join("deleted-snapshot.db");
                let snapshot = db.write_backup_snapshot(&path)?;
                let backup =
                    super::super::backup_database::BackupDatabase::open(&path, &snapshot.key)?;
                let stored: (String, Vec<u8>, Vec<u8>, i64) = backup.db.query_row(
                    "SELECT sender_id,encrypted_body,metadata_json,is_own FROM direct_message_projection WHERE message_id='own-message'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
                assert_eq!(stored, (String::new(), Vec::new(), b"{}".to_vec(), 1));
            }
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
