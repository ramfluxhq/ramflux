// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transactional erasure of identity-bearing fields from deleted message records.

use super::AccountDb;
use crate::StorageError;
use hmac::{Hmac, Mac};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::BTreeSet;

type HmacSha256 = Hmac<Sha256>;

impl AccountDb {
    pub(super) fn scrub_message_for_deletion(
        &self,
        conversation: &str,
        message: &str,
        own_override: Option<bool>,
    ) -> Result<bool, StorageError> {
        let Some((sender,stored_own,was_deleted))=self.connection.query_row(
            "SELECT sender_id,is_own,deleted FROM direct_message_projection WHERE conversation_id=?1 AND message_id=?2",
            params![conversation,message],|row|Ok((row.get::<_,String>(0)?,row.get::<_,bool>(1)?,row.get::<_,bool>(2)?)),
        ).optional()? else {return Ok(false)};
        let is_own = match own_override {
            Some(is_own) => is_own,
            None => {
                stored_own
                    || self.verified_own_device_ids()?.contains(&sender)
                    || self.message_sender_is_local(conversation, message, &sender)?
            }
        };
        // The update trigger drains only locators owned by this message, in this transaction.
        self.connection.execute("UPDATE direct_message_projection SET sender_id='',encrypted_body=x'',metadata_json=x'7b7d',deleted=1,is_own=?3 WHERE conversation_id=?1 AND message_id=?2",params![conversation,message,i64::from(is_own)])?;
        self.persist_deletion_marker(message)?;
        self.remove_message_origin(conversation, message)?;
        Ok(!was_deleted)
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
        Ok(self.actor_state_exists(&self.deletion_marker_key(message)?)?
            || self.actor_state_exists(&legacy_deletion_marker_key(message))?)
    }

    fn persist_deletion_marker(&self, message: &str) -> Result<(), StorageError> {
        self.persist_actor_state(&self.deletion_marker_key(message)?, &json!({"version":2}))?;
        self.remove_actor_state(&legacy_deletion_marker_key(message))
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

    pub(super) fn account_mac(&self, info: &[u8], value: &[u8]) -> Result<String, StorageError> {
        let mut derived = zeroize::Zeroizing::new([0_u8; 32]);
        hkdf::Hkdf::<Sha256>::new(None, self.current_key.bytes())
            .expand(info, derived.as_mut())
            .map_err(|_| StorageError::AuthorizationRejected)?;
        let mut mac = HmacSha256::new_from_slice(derived.as_ref())
            .map_err(|_| StorageError::AuthorizationRejected)?;
        mac.update(value);
        Ok(ramflux_protocol::encode_base64url(mac.finalize().into_bytes()))
    }

    fn deletion_hash(&self, message: &str) -> Result<String, StorageError> {
        self.account_mac(b"ramflux/tombstone-key/v1", message.as_bytes())
    }

    fn deletion_marker_key(&self, message: &str) -> Result<String, StorageError> {
        Ok(format!("message/deleted/{}", self.deletion_hash(message)?))
    }
}

fn legacy_deletion_hash(message: &str) -> String {
    ramflux_crypto::blake3_256_base64url("ramflux.deleted-message.v1", message.as_bytes())
}

fn legacy_deletion_marker_key(message: &str) -> String {
    format!("message/deleted/{}", legacy_deletion_hash(message))
}

#[cfg(test)]
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
    fn legacy_deleted_rows_and_corrupt_journal_open_without_rewrites() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("legacy-deletion-no-upgrade")?;
        db.connection.execute_batch(
            "WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<10000)
             INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,created_at)
             SELECT 'thread','legacy-'||n,'legacy-sender',x'01',x'7b7d',1,0,n FROM rows;
             INSERT INTO runtime_journal(at,topic,body_json,source_key) VALUES(1,'message.received',x'ff','corrupt-legacy');
             CREATE INDEX idx_direct_message_scrub ON direct_message_projection(deleted,scrub_version);
             CREATE INDEX runtime_actor_receipt_message ON runtime_actor_state(state_kind);",
        )?;
        let before: u64 = db.connection.query_row(
            "SELECT count(*) FROM runtime_outbox WHERE table_name='direct_message_projection'",
            [],
            |r| r.get(0),
        )?;
        drop(db);
        let key = AccountDbKey::derive("acct", b"storage-test-secret");
        let db = AccountDb::open(&AccountIndex::open(&root)?, "acct", &key)?;
        let after: u64 = db.connection.query_row(
            "SELECT count(*) FROM runtime_outbox WHERE table_name='direct_message_projection'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(before, after, "opening legacy rows must never run deletion work");
        assert_eq!(db.connection.query_row("SELECT count(*) FROM sqlite_master WHERE type='index' AND name IN ('idx_direct_message_scrub','runtime_actor_receipt_message')", [], |r| r.get::<_,u64>(0))?, 0);
        assert_eq!(db.connection.query_row("SELECT count(*) FROM direct_message_projection WHERE sender_id='legacy-sender' AND deleted=1", [], |r| r.get::<_,u64>(0))?, 10000);
        assert_eq!(
            db.connection.query_row(
                "SELECT body_json FROM runtime_journal WHERE source_key='corrupt-legacy'",
                [],
                |r| r.get::<_, Vec<u8>>(0)
            )?,
            vec![0xff]
        );
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn deletion_recognizes_every_owned_sender_shape() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-owned-scrub")?;
        let db = db.with_device_signer(ramflux_crypto::create_device_branch(
            "principal-id-realistic",
            "current-device",
            1,
            [0x44; 32],
        ));
        db.upsert_device_directory_entry("sibling-device", "principal", "verified", 1)?;
        for (message, sender) in [
            ("current-message", "current-device"),
            ("sibling-message", "sibling-device"),
            ("principal-message", "principal-id-realistic"),
        ] {
            db.send_direct_message("thread", message, sender, b"secret")?;
            db.delete_direct_message("thread", message, "local", &format!("delete-{message}"))?;
        }
        let own_devices = db.verified_own_device_ids()?;
        assert!(own_devices.contains("current-device"));
        assert!(own_devices.contains("sibling-device"));
        assert!(own_devices.contains("principal-id-realistic"));
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
        let seen = db.routed_seen_key(b"canonical-inbound-envelope")?;
        db.persist_actor_state(&seen, &json!({"payload_hash":"dedup-hash"}))?;
        db.append_event(
            "gateway/delivery/v2/admission",
            "gateway.deliver.opaque",
            &serde_json::to_vec(&json!({
                "envelope_id":"wire-message",
                "source_principal_id":"peer-secret",
                "encrypted_payload":"body-secret","payload_hash":"dedup-hash"
            }))?,
        )?;
        db.append_journal(
            "unrouted:wire-message",
            "message.unrouted",
            &json!({
                "envelope_id":"wire-message",
                "claimed_source_device_id":"peer-device-secret","payload_hash":"dedup-hash"
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
        assert!(!db.actor_state_exists("routed/committed/receipt")?);
        assert_eq!(
            db.load_actor_state::<Value>(&seen)?,
            Some(json!({"payload_hash":"dedup-hash"}))
        );
        assert_eq!(db.event_body("gateway/delivery/v2/admission")?, None);
        let unrouted = db
            .journal_after(0, 10)?
            .into_iter()
            .find(|row| row.topic == "message.unrouted")
            .ok_or(StorageError::AuthorizationRejected)?;
        assert_eq!(
            unrouted.body["message"],
            deleted_projection("thread", "message", row.created_at, false)
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn deletion_uses_indexed_replay_and_event_lookups_at_scale() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-indexed-lookup")?;
        db.connection.execute_batch(
            "WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<10000)
             INSERT INTO runtime_actor_state(state_kind,state_json)
             SELECT 'routed/committed/unrelated-'||n,
                    CAST('{\"routing\":{\"message_id\":\"unrelated-'||n||'\"}}' AS BLOB)
             FROM rows;
             WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<10000)
             INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,created_at) SELECT 'thread','unrelated-'||n,'peer',x'01',x'7b7d',0,0,n FROM rows;
             WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<10000)
             INSERT INTO runtime_journal(at,topic,body_json,source_key) SELECT n,'message.received',CAST(json_object('message_id','unrelated-'||n) AS BLOB),'unrelated-journal-'||n FROM rows;
             WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM rows WHERE n<10000)
             INSERT INTO local_event_log SELECT 'unrelated-event-'||n,'message.received','peer','peer-device',n,n,n,NULL,CAST(json_object('message_id','unrelated-'||n) AS BLOB),x'','fixture','applied' FROM rows;",
        )?;
        db.send_direct_message("thread", "target", "peer", b"secret")?;
        db.append_journal(
            "target-journal",
            "message.received",
            &json!({"message_id":"target","sender_id":"peer"}),
            1,
            None,
        )?;
        db.append_event(
            "target-event",
            "gateway.deliver.opaque",
            &serde_json::to_vec(&json!({"message_id":"target","sender":"peer"}))?,
        )?;
        for (query, index) in [
            (
                "SELECT locator FROM message_footprint WHERE message_id='target' AND kind='journal'",
                "message_footprint",
            ),
            (
                "SELECT seq FROM runtime_journal WHERE seq IN (SELECT CAST(locator AS INTEGER) FROM message_footprint WHERE message_id='target' AND kind='journal')",
                "INTEGER PRIMARY KEY",
            ),
            (
                "SELECT state_kind FROM runtime_actor_state WHERE state_kind IN (SELECT locator FROM message_footprint WHERE message_id='target' AND kind='actor')",
                "sqlite_autoindex_runtime_actor_state",
            ),
            (
                "SELECT event_id FROM local_event_log WHERE event_id IN (SELECT locator FROM message_footprint WHERE message_id='target' AND kind='event')",
                "sqlite_autoindex_local_event_log",
            ),
        ] {
            let mut statement = db.connection.prepare(&format!("EXPLAIN QUERY PLAN {query}"))?;
            let plans = statement
                .query_map([], |row| row.get::<_, String>(3))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            assert!(
                plans.iter().any(|detail| detail.contains(index)),
                "unexpected query plan: {plans:?}"
            );
            assert!(
                plans.iter().all(|detail| !detail.contains("SCAN runtime_")
                    && !detail.contains("SCAN local_event_log")),
                "{plans:?}"
            );
            eprintln!("indexed erasure plan: {plans:?}");
        }
        // Measure deletion against an established store; fixture construction WAL is separate.
        db.checkpoint_retired_secrets()?;
        let total_started = std::time::Instant::now();
        let transaction = db.connection.immediate_transaction()?;
        let erasure_started = std::time::Instant::now();
        db.delete_direct_message("thread", "target", "local", "tombstone")?;
        let erasure = erasure_started.elapsed();
        let commit_started = std::time::Instant::now();
        transaction.commit()?;
        let commit = commit_started.elapsed();
        let total = total_started.elapsed();
        eprintln!(
            "10k-copy-store deletion: erasure={erasure:?}, durable_commit={commit:?}, total={total:?}"
        );
        let erasure_budget = if cfg!(debug_assertions) {
            std::time::Duration::from_secs(2)
        } else {
            std::time::Duration::from_millis(10)
        };
        assert!(erasure <= erasure_budget, "erasure budget exceeded: {erasure:?}");
        assert!(
            commit <= std::time::Duration::from_millis(250),
            "durable commit budget exceeded: {commit:?}"
        );
        db.checkpoint_retired_secrets()?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn deletion_keys_are_account_scoped_and_receipt_retry_work_is_erased()
    -> Result<(), StorageError> {
        let first_root = crate::tests::temp_root("deleted-key-first");
        let second_root = crate::tests::temp_root("deleted-key-second");
        let mut keys = Vec::new();
        for (root, secret) in
            [(&first_root, b"first".as_slice()), (&second_root, b"second".as_slice())]
        {
            let index = AccountIndex::open(root)?;
            index.create_account("acct", "root")?;
            let db = AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", secret))?;
            db.send_direct_message("thread", "same-message", "peer", b"secret")?;
            db.persist_actor_state(
                "delivery-receipt/pending/status-id",
                &json!({"status_id":"status-id","conversation":"thread","message":"same-message"}),
            )?;
            db.persist_actor_state(
                "delivery-receipt/status/status-id",
                &json!({"state":"failed","retry_work":{"message":"same-message","sender":"peer-secret"}}),
            )?;
            db.delete_direct_message("thread", "same-message", "local", "tombstone")?;
            keys.push(
                db.actor_state_key_page("message/deleted/", 1)?
                    .into_iter()
                    .next()
                    .ok_or(StorageError::AuthorizationRejected)?,
            );
            assert!(!db.actor_state_exists("delivery-receipt/pending/status-id")?);
            assert!(!db.actor_state_exists("delivery-receipt/status/status-id")?);
        }
        assert_ne!(keys[0], keys[1]);
        std::fs::remove_dir_all(first_root)?;
        std::fs::remove_dir_all(second_root)?;
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
