// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-keyed routed replay markers and identity-free failure retention.

use super::AccountDb;
use crate::StorageError;

fn canonical_envelope(entry: &[u8]) -> Result<Option<(String, Vec<u8>)>, StorageError> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(entry) else { return Ok(None) };
    let envelope = value.get("envelope").unwrap_or(&value);
    if envelope.get("encrypted_payload").is_none() || envelope.get("payload_hash").is_none() {
        return Ok(None);
    }
    let Some(envelope_id) = envelope.get("envelope_id").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    Ok(Some((envelope_id.to_owned(), ramflux_protocol::canonical_json_bytes(envelope)?)))
}

impl AccountDb {
    /// Derives a private marker from the SHA-256 digest of canonical envelope bytes.
    ///
    /// # Errors
    /// Returns a key derivation error.
    pub fn routed_seen_key(&self, canonical_envelope: &[u8]) -> Result<String, StorageError> {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(canonical_envelope);
        Ok(format!("routed/seen/{}", self.account_mac(b"ramflux/replay-key/v1", &digest)?))
    }

    /// Extracts a canonical-envelope marker from a retained wire entry without identity lookup.
    ///
    /// # Errors
    /// Returns canonical encoding or key derivation errors.
    pub fn inbox_envelope_marker(&self, entry: &[u8]) -> Result<Option<String>, StorageError> {
        canonical_envelope(entry)?.map(|(_, envelope)| self.routed_seen_key(&envelope)).transpose()
    }

    /// Returns canonical bytes only when the entry names a deleted message.
    ///
    /// # Errors
    /// Returns storage or canonical encoding errors.
    pub(crate) fn deleted_inbox_envelope(
        &self,
        entry: &[u8],
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let Some((envelope_id, canonical)) = canonical_envelope(entry)? else {
            return Ok(None);
        };
        Ok(self.envelope_refers_to_deleted_message(&envelope_id)?.then_some(canonical))
    }

    /// Retains only an envelope's keyed marker when routed processing fails.
    ///
    /// # Errors
    /// Returns storage errors without persisting envelope bytes or addressing.
    pub fn dead_letter_routed(
        &self,
        canonical_envelope: &[u8],
        code: &str,
        at: i64,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| self.insert_routed_dead_letter(canonical_envelope, code, at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountDbKey, AccountIndex, DirectMessageWrite, MessageMetadata};
    use rusqlite::params;
    use serde_json::json;

    #[test]
    fn seen_markers_are_private_and_only_mismatches_keep_marker_only_dead_letters()
    -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("seen-private-failure")?;
        let index = AccountIndex::open(root.join("second"))?;
        index.create_account("second", "second-root")?;
        let other = AccountDb::open(&index, "second", &AccountDbKey::generate()?)?;
        let committed = "routed/committed/public-dictionary-hash";
        let marker = db.routed_seen_key(committed.as_bytes())?;
        assert_ne!(marker, other.routed_seen_key(committed.as_bytes())?);
        db.persist_actor_state(&marker, &"payload-hash")?;
        let entry = br#"{"source_principal_id":"private-principal","source_device_id":"private-device","envelope_id":"private-envelope","payload_hash":"hash","encrypted_payload":"ciphertext"}"#;
        let marker = db.inbox_envelope_marker(entry)?.ok_or(StorageError::AuthorizationRejected)?;
        db.persist_actor_state(&marker, &json!({"payload_hash":"hash"}))?;
        db.hold_unrouted(committed, 1, entry, 1)?;
        assert_eq!(db.unrouted_count()?, 0);
        assert_eq!(db.defer_inbox_entry(committed, entry, 1)?, 0);
        db.dead_letter_inbox(
            committed,
            entry,
            &json!({"error_code":"authentication_failed","envelope_id":"private-envelope"}),
            1,
        )?;
        assert!(db.latest_journal_event("message.undeliverable")?.is_none());
        // A never-seen envelope retains bounded diagnostics.
        let changed = br#"{"source_principal_id":"private-principal","source_device_id":"private-device","envelope_id":"private-envelope","payload_hash":"other","encrypted_payload":"changed"}"#;
        let marker =
            db.inbox_envelope_marker(changed)?.ok_or(StorageError::AuthorizationRejected)?;
        db.dead_letter_inbox(
            "never-seen",
            changed,
            &json!({"error_code":"authentication_failed","envelope_id":"private-envelope"}),
            1,
        )?;
        let diagnostic: Vec<u8> = db.connection.query_row(
            "SELECT entry_json FROM runtime_inbox_dead_letter WHERE envelope_key='never-seen'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(diagnostic, changed);
        db.connection
            .execute("DELETE FROM runtime_inbox_dead_letter WHERE envelope_key='never-seen'", [])?;
        db.connection.execute(
            "DELETE FROM runtime_journal WHERE source_key='undeliverable:never-seen'",
            [],
        )?;
        // A replay mismatch uses only the opaque marker.
        db.dead_letter_routed(
            &ramflux_protocol::canonical_json_bytes(&serde_json::from_slice::<serde_json::Value>(
                changed,
            )?)?,
            "authentication_failed",
            1,
        )?;
        let failure: (String, Vec<u8>) = db.connection.query_row(
            "SELECT envelope_key,entry_json FROM runtime_inbox_dead_letter",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        assert_eq!(failure.0, marker);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&failure.1)?,
            json!({"marker":marker})
        );
        let policy: String = db.connection.query_row(
            "SELECT source FROM runtime_inbox_policy WHERE envelope_key=?1",
            params![marker],
            |r| r.get(0),
        )?;
        let journal = serde_json::to_string(&db.journal_after(0, 128)?)?;
        for forbidden in ["private-principal", "private-device", "private-envelope", committed] {
            assert!(!String::from_utf8_lossy(&failure.1).contains(forbidden));
            assert!(!policy.contains(forbidden));
            assert!(!journal.contains(forbidden));
        }
        assert!(!db.has_inbox_retry(committed)?);
        drop(db);
        drop(other);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn seen_marker_rolls_back_with_its_commit() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("seen-rollback")?;
        let marker = db.routed_seen_key(b"routed/committed/rollback")?;
        let result: Result<(), StorageError> = db.write_transaction(|| {
            db.persist_actor_state(&marker, &"payload-hash")?;
            Err(StorageError::AuthorizationRejected)
        });
        assert!(result.is_err());
        assert!(!db.actor_state_exists(&marker)?);
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn deleted_envelope_reuse_keeps_only_keyed_markers_for_any_bytes() -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("deleted-envelope-marker-only")?;
        let metadata = MessageMetadata::default();
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "thread",
            message_id: "deleted-projection",
            sender_id: "private-sender",
            encrypted_body: b"private-body",
            metadata: &metadata,
            created_at: 1,
        })?;
        db.connection.execute(
            "INSERT INTO message_copy_binding VALUES('envelope:deleted-envelope','deleted-projection')",
            [],
        )?;
        db.delete_direct_message("thread", "deleted-projection", "local", "delete")?;
        let entries = [
            br#"{"source_principal_id":"private-principal","source_device_id":"private-device","envelope_id":"deleted-envelope","payload_hash":"signed-hash","encrypted_payload":"signed-ciphertext","signed":{"signature":"valid-looking"}}"#.as_slice(),
            br#"{"source_principal_id":"forged-principal","source_device_id":"forged-device","envelope_id":"deleted-envelope","payload_hash":"forged-hash","encrypted_payload":"forged-ciphertext","signed":{"signature":"invalid"}}"#.as_slice(),
        ];
        for (at, entry) in [0_i64, 1].into_iter().zip(entries) {
            db.dead_letter_inbox(
                "routed/committed/public-unkeyed",
                entry,
                &json!({
                    "error_code":"authentication_failed",
                    "envelope_id":"deleted-envelope",
                    "claimed_source_device_id":format!("source-{at}"),
                }),
                at,
            )?;
        }
        let mut query = db.connection.prepare(
            "SELECT envelope_key,entry_json FROM runtime_inbox_dead_letter ORDER BY envelope_key",
        )?;
        let rows = query
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(rows.len(), 2);
        for (marker, entry) in rows {
            assert!(marker.starts_with("routed/seen/"));
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&entry)?,
                json!({"marker":marker})
            );
        }
        assert!(!db.actor_state_exists("routed/committed/public-unkeyed")?);
        let retained = serde_json::to_string(&db.journal_after(0, 128)?)?;
        for forbidden in [
            "private-principal",
            "private-device",
            "forged-principal",
            "forged-device",
            "deleted-envelope",
            "public-unkeyed",
        ] {
            assert!(!retained.contains(forbidden), "retained {forbidden}");
        }
        drop(query);
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
