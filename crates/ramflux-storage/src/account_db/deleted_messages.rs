// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transactional erasure of identity-bearing fields from deleted message records.

use super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const SCRUB_VERSION: i64 = 2;
const SCRUB_BATCH: i64 = 256;

impl AccountDb {
    /// Completes bounded deletion upgrades after the SDK has attached its verified identity.
    ///
    /// # Errors
    /// Returns storage errors without advancing rows whose scrub did not commit.
    pub fn scrub_deleted_messages(
        &self,
        own_device_ids: &BTreeSet<String>,
    ) -> Result<usize, StorageError> {
        let mut total = 0usize;
        loop {
            let rows = {
                let mut statement = self.connection.prepare(
                "SELECT conversation_id,message_id FROM direct_message_projection WHERE deleted=1 AND scrub_version<?1 ORDER BY rowid LIMIT ?2",
            )?;
                statement
                    .query_map(params![SCRUB_VERSION, SCRUB_BATCH], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            if rows.is_empty() {
                break;
            }
            self.write_transaction(|| {
                let mut projections = BTreeMap::new();
                for (conversation, message) in &rows {
                    let projection = self.scrub_message_for_deletion_inner(
                        conversation,
                        message,
                        None,
                        own_device_ids,
                        false,
                    )?;
                    if let Some(projection) = projection {
                        projections.insert(message.clone(), projection);
                    }
                }
                self.scrub_message_journal_batch(&projections)?;
                Ok::<(), StorageError>(())
            })?;
            total = total.saturating_add(rows.len());
        }
        self.checkpoint_retired_secrets_if_committed()?;
        Ok(total)
    }

    pub(super) fn scrub_message_for_deletion(
        &self,
        conversation: &str,
        message: &str,
        own_override: Option<bool>,
    ) -> Result<bool, StorageError> {
        let was_deleted = self.connection.query_row(
            "SELECT deleted FROM direct_message_projection WHERE conversation_id=?1 AND message_id=?2",
            params![conversation, message],
            |row| row.get::<_, i64>(0),
        ).optional()?.is_some_and(|deleted| deleted != 0);
        let found = self
            .scrub_message_for_deletion_inner(
                conversation,
                message,
                own_override,
                &BTreeSet::new(),
                true,
            )?
            .is_some();
        Ok(found && !was_deleted)
    }

    fn scrub_message_for_deletion_inner(
        &self,
        conversation: &str,
        message: &str,
        own_override: Option<bool>,
        own_device_ids: &BTreeSet<String>,
        scrub_journal: bool,
    ) -> Result<Option<Value>, StorageError> {
        let Some((sender, stored_own, created_at)) = self
            .connection
            .query_row(
                "SELECT sender_id,is_own,created_at FROM direct_message_projection WHERE conversation_id=?1 AND message_id=?2",
                params![conversation, message],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
        let is_own = own_override.unwrap_or(
            stored_own
                || own_device_ids.contains(&sender)
                || self.message_sender_is_local(conversation, message, &sender)?,
        );
        self.connection.execute(
            "UPDATE direct_message_projection SET sender_id='',encrypted_body=x'',metadata_json=x'7b7d',deleted=1,is_own=?3,scrub_version=?4 WHERE conversation_id=?1 AND message_id=?2",
            params![conversation, message, i64::from(is_own), SCRUB_VERSION],
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
        let projection = deleted_projection(conversation, message, created_at, is_own);
        self.connection.execute(
            "UPDATE runtime_actor_state SET state_json=?2 WHERE state_kind=?1",
            params![format!("directory/message/{message}"), serde_json::to_vec(&projection)?],
        )?;
        if scrub_journal {
            self.scrub_message_journal_batch(&BTreeMap::from([(
                message.to_owned(),
                projection.clone(),
            )]))?;
        }
        self.persist_deletion_marker(message)?;
        self.scrub_replay_copies(message)?;
        self.remove_message_origin(conversation, message)?;
        Ok(Some(projection))
    }

    /// Returns the verified device identifiers bound to this account root.
    ///
    /// # Errors
    /// Returns storage errors while reading the verified directory.
    pub fn verified_own_device_ids(&self) -> Result<BTreeSet<String>, StorageError> {
        let mut ids = BTreeSet::new();
        let mut statement = self.connection.prepare(
            "SELECT device_id,COALESCE(raw_device_id,device_id) FROM device_directory WHERE principal_commitment=?1",
        )?;
        for row in statement.query_map(params![self.principal_commitment], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (qualified, raw) = row?;
            ids.insert(qualified);
            ids.insert(raw);
        }
        if let Some(device) = self.device_signer() {
            // These are comparison aliases only; no bare identifier becomes a storage key.
            ids.extend([device.device_id.clone(), device.principal_id.clone()]);
        }
        Ok(ids)
    }

    /// Whether a sticky deletion marker or deleted projection rejects redelivery.
    ///
    /// # Errors
    /// Returns storage errors while reading deletion state.
    pub fn message_is_deleted(&self, message: &str) -> Result<bool, StorageError> {
        if self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM direct_message_projection WHERE message_id=?1 AND deleted=1)",
            params![message],
            |row| row.get::<_, i64>(0),
        )? != 0
        {
            return Ok(true);
        }
        self.actor_state_exists(&deletion_marker_key(message))
    }

    fn persist_deletion_marker(&self, message: &str) -> Result<(), StorageError> {
        self.persist_actor_state(&deletion_marker_key(message), &json!({"version":1}))
    }

    fn scrub_replay_copies(&self, message: &str) -> Result<(), StorageError> {
        self.remove_actor_state(&format!("routed/message-owner/{message}"))?;
        let mut envelope_ids = BTreeSet::from([message.to_owned()]);
        for key in self.actor_state_keys("routed/committed/")? {
            let Some(mut value) = self.load_actor_state::<Value>(&key)? else { continue };
            if value.pointer("/routing/message_id").and_then(Value::as_str) != Some(message) {
                continue;
            }
            if let Some(envelope) = value.pointer_mut("/entry/envelope") {
                if let Some(id) = envelope.get("envelope_id").and_then(Value::as_str) {
                    envelope_ids.insert(id.to_owned());
                }
                for field in [
                    "source_principal_id",
                    "source_device_id",
                    "encrypted_payload",
                    "signing_key_id",
                    "signature",
                ] {
                    if envelope.get(field).is_some() {
                        envelope[field] = Value::String(String::new());
                    }
                }
            }
            self.persist_actor_state(&key, &value)?;
        }
        let events = {
            let mut statement = self.connection.prepare(
                "SELECT event_id,event_body FROM local_event_log WHERE event_type='gateway.deliver.opaque' AND signature_status!='scrubbed'",
            )?;
            statement
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (event_id, body) in events {
            let Ok(envelope) = serde_json::from_slice::<Value>(&body) else { continue };
            if !envelope
                .get("envelope_id")
                .and_then(Value::as_str)
                .is_some_and(|id| envelope_ids.contains(id))
            {
                continue;
            }
            self.connection.execute(
                "UPDATE local_event_log SET event_body=?2,signature=x'',signature_status='scrubbed' WHERE event_id=?1",
                params![event_id, serde_json::to_vec(&json!({"deleted_message_hash":deletion_hash(message)}))?],
            )?;
        }
        Ok(())
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

    fn scrub_message_journal_batch(
        &self,
        projections: &BTreeMap<String, Value>,
    ) -> Result<(), StorageError> {
        let mut envelope_messages = BTreeMap::new();
        for key in self.actor_state_keys("routed/committed/")? {
            let Some(value) = self.load_actor_state::<Value>(&key)? else { continue };
            let Some(message) = value.pointer("/routing/message_id").and_then(Value::as_str) else {
                continue;
            };
            if !projections.contains_key(message) {
                continue;
            }
            if let Some(envelope) =
                value.pointer("/entry/envelope/envelope_id").and_then(Value::as_str)
            {
                envelope_messages.insert(envelope.to_owned(), message.to_owned());
            }
        }
        let rows = {
            let mut statement = self.connection.prepare(
                "SELECT seq,topic,body_json FROM runtime_journal WHERE topic IN ('message.received','group.message.received','message.updated','message.unrouted')",
            )?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (seq, topic, bytes) in rows {
            let mut body: Value = serde_json::from_slice(&bytes)?;
            let nested = body
                .pointer("/message/message_id")
                .or_else(|| body.pointer("/message/id"))
                .and_then(Value::as_str);
            let direct = body.get("message_id").and_then(Value::as_str);
            let envelope = body.get("envelope_id").and_then(Value::as_str);
            if let Some((message, projection)) = projections.iter().find(|(message, _)| {
                nested == Some(message.as_str())
                    || direct == Some(message.as_str())
                    || topic == "message.unrouted"
                        && (envelope == Some(message.as_str())
                            || envelope.is_some_and(|id| {
                                envelope_messages.get(id).is_some_and(|mapped| mapped == *message)
                            }))
            }) {
                body = if topic == "message.unrouted" {
                    json!({"message_id":message,"deleted":true})
                } else {
                    body["message"] = projection.clone();
                    body
                };
                self.connection.execute(
                    "UPDATE runtime_journal SET body_json=?2 WHERE seq=?1",
                    params![seq, serde_json::to_vec(&body)?],
                )?;
            }
        }
        Ok(())
    }
}

fn deletion_hash(message: &str) -> String {
    ramflux_crypto::blake3_256_base64url("ramflux.deleted-message.v1", message.as_bytes())
}

fn deletion_marker_key(message: &str) -> String {
    format!("message/deleted/{}", deletion_hash(message))
}

fn deleted_projection(conversation: &str, message: &str, created_at: i64, is_own: bool) -> Value {
    json!({
        "message_id": message,
        "deleted": true,
        "created_at": created_at,
        "conversation_id": conversation,
        "is_own": is_own,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountDbKey, AccountIndex, EventStore, MessageMetadata};

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
            Some(deleted_projection("thread", "message", message.created_at, false))
        );
        let event = db
            .journal_after(0, 10)?
            .into_iter()
            .find(|event| event.topic == "message.received")
            .ok_or(StorageError::AuthorizationRejected)?;
        assert_eq!(
            event.body["message"],
            deleted_projection("thread", "message", message.created_at, false)
        );
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
            let scrubbed = db.scrub_deleted_messages(&BTreeSet::new())?;
            assert_eq!(scrubbed, usize::from(pass == 0));
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
                Some(deleted_projection("thread", "own-message", message.created_at, true))
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

    #[test]
    fn post_identity_scrub_recognizes_every_owned_sender_shape() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-owned-scrub")?;
        let db = db.with_device_signer(ramflux_crypto::create_device_branch(
            "principal",
            "current-device",
            1,
            [0x44; 32],
        ));
        db.upsert_device_directory_entry("sibling-device", "principal", "verified", 1)?;
        for (message, sender) in [
            ("current-message", "current-device"),
            ("sibling-message", "sibling-device"),
            ("principal-message", "principal"),
        ] {
            db.send_direct_message("thread", message, sender, b"secret")?;
        }
        db.connection.execute("UPDATE direct_message_projection SET deleted=1", [])?;
        let own_devices = db.verified_own_device_ids()?;
        assert!(own_devices.contains("current-device"));
        assert!(own_devices.contains("sibling-device"));
        assert_eq!(db.scrub_deleted_messages(&own_devices)?, 3);
        for message in ["current-message", "sibling-message", "principal-message"] {
            assert!(db.direct_message_by_id(message)?.is_some_and(|row| row.is_own));
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn deletion_is_sticky_across_redelivery_and_scrubs_replay_copies() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-sticky-replay")?;
        db.send_direct_message("thread", "message", "peer-secret", b"body-secret")?;
        db.persist_actor_state("routed/message-owner/message", &"peer-secret")?;
        db.persist_actor_state(
            "routed/committed/receipt",
            &json!({
                "routing":{"message_id":"message"},
                "entry":{"envelope":{
                    "envelope_id":"wire-message",
                    "source_principal_id":"peer-secret",
                    "source_device_id":"peer-device-secret",
                    "encrypted_payload":"body-secret",
                    "signing_key_id":"peer-key-secret",
                    "signature":"signature-secret",
                    "payload_hash":"dedup-hash"
                }}
            }),
        )?;
        db.append_event(
            "gateway/delivery/v2/admission",
            "gateway.deliver.opaque",
            &serde_json::to_vec(&json!({
                "envelope_id":"wire-message",
                "source_principal_id":"peer-secret",
                "encrypted_payload":"body-secret"
            }))?,
        )?;
        db.append_journal(
            "unrouted:wire-message",
            "message.unrouted",
            &json!({
                "envelope_id":"wire-message",
                "claimed_source_device_id":"peer-device-secret"
            }),
            1,
            None,
        )?;

        db.delete_direct_message("thread", "message", "local", "tombstone")?;
        db.send_direct_message("thread", "message", "peer-secret", b"restored-secret")?;
        db.store_message_content("thread", "message", b"plaintext-restored")?;

        let row = db.direct_message_by_id("message")?.ok_or(StorageError::AuthorizationRejected)?;
        assert!(row.deleted && !row.is_own);
        assert_eq!(db.message_content("message")?, None);
        assert!(!db.actor_state_exists("routed/message-owner/message")?);
        let replay = db
            .load_actor_state::<Value>("routed/committed/receipt")?
            .ok_or(StorageError::AuthorizationRejected)?;
        let rendered = serde_json::to_string(&replay)?;
        assert!(!rendered.contains("peer-secret"));
        assert!(!rendered.contains("body-secret"));
        assert!(rendered.contains("dedup-hash"));
        let event = db
            .event_body("gateway/delivery/v2/admission")?
            .ok_or(StorageError::AuthorizationRejected)?;
        assert!(!String::from_utf8_lossy(&event).contains("peer-secret"));
        let unrouted = db
            .journal_after(0, 10)?
            .into_iter()
            .find(|row| row.topic == "message.unrouted")
            .ok_or(StorageError::AuthorizationRejected)?;
        assert_eq!(unrouted.body, json!({"message_id":"message","deleted":true}));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn startup_skips_ten_thousand_current_scrub_rows() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-current-scrub")?;
        db.connection.execute_batch(
            "WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<10000)
             INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,scrub_version,created_at)
             SELECT 'thread','message-'||n,'',x'',x'7b7d',1,0,2,n FROM rows;",
        )?;
        assert_eq!(db.scrub_deleted_messages(&BTreeSet::new())?, 0);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn imported_tombstone_deletes_live_copy_and_cannot_restore_content() -> Result<(), StorageError>
    {
        let (root, db) = crate::tests::test_db("deleted-import-tombstone")?;
        db.send_direct_message("thread", "message", "sibling", b"live-secret")?;
        db.store_message_content("thread", "message", b"plaintext-secret")?;
        db.import_deleted_message_projection("thread", "message", true, 7)?;
        db.send_direct_message("thread", "message", "sibling", b"replayed-secret")?;
        let row = db.direct_message_by_id("message")?.ok_or(StorageError::AuthorizationRejected)?;
        assert!(row.deleted && row.is_own);
        assert_eq!(row.sender_id, "");
        assert_eq!(db.message_content("message")?, None);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn disappearing_expiry_uses_the_same_sticky_scrub() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-disappearing")?;
        db.send_direct_message_at_with_metadata(crate::DirectMessageWrite {
            conversation_id: "thread",
            message_id: "expiring",
            sender_id: "peer-secret",
            encrypted_body: b"ciphertext-secret",
            metadata: &MessageMetadata::default(),
            created_at: 1,
        })?;
        db.store_message_content("thread", "expiring", b"plaintext-secret")?;
        db.set_disappearing_policy("thread", 5, "on_send", "all_devices", 1)?;
        assert_eq!(db.expire_disappearing_messages("thread", 6)?.len(), 1);
        let row =
            db.direct_message_by_id("expiring")?.ok_or(StorageError::AuthorizationRejected)?;
        assert!(row.deleted);
        assert_eq!(row.sender_id, "");
        assert_eq!(db.message_content("expiring")?, None);
        assert!(db.message_is_deleted("expiring")?);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn group_delete_uses_the_same_narrow_projection() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-group")?;
        let identity = ramflux_crypto::create_identity_root("owner", [0x72; 32]);
        let actor = ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
            &identity,
            "owner-device",
        )?;
        db.create_group("group", actor.device_id())?;
        db.persist_group_member_device_key("group", &actor, "owner-key")?;
        db.send_direct_message("group", "group-message", actor.device_id(), b"secret")?;
        db.store_message_content("group", "group-message", b"plaintext")?;
        db.apply_group_message_delete(
            &crate::GroupMessageDeleteWrite {
                group_id: "group".into(),
                event_id: "delete-event".into(),
                actor_device_id: actor.device_id().into(),
                target_message_id: "group-message".into(),
                group_epoch: 1,
                delete_scope: "all_devices".into(),
                tombstone_id: "group-tombstone".into(),
                reason: "user".into(),
            },
            &actor,
        )?;
        let row =
            db.direct_message_by_id("group-message")?.ok_or(StorageError::AuthorizationRejected)?;
        assert!(row.deleted);
        assert_eq!(row.sender_id, "");
        assert_eq!(db.message_content("group-message")?, None);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
