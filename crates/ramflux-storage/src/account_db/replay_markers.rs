// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-keyed routed replay markers and identity-free failure retention.

use super::AccountDb;
use crate::StorageError;
use serde_json::json;

impl AccountDb {
    /// Derives the private seen-marker address from an authenticated commit key.
    ///
    /// # Errors
    /// Returns a key derivation error.
    pub fn routed_seen_key(&self, committed: &str) -> Result<String, StorageError> {
        Ok(format!(
            "routed/seen/{}",
            self.account_mac(b"ramflux/replay-key/v1", committed.as_bytes())?
        ))
    }

    /// Retains only the private marker when a previously committed entry fails admission.
    /// Returns false if the entry has never committed.
    ///
    /// # Errors
    /// Returns storage errors without persisting the incoming envelope.
    pub fn dead_letter_seen_routed(&self, committed: &str, at: i64) -> Result<bool, StorageError> {
        self.write_transaction(|| {
            let marker = self.routed_seen_key(committed)?;
            if !self.actor_state_exists(&marker)? {
                return Ok(false);
            }
            self.remove_inbox_retry(committed)?;
            self.remove_unrouted(committed)?;
            self.dead_letter_inbox(
                &marker,
                &serde_json::to_vec(&json!({"marker":marker}))?,
                &json!({"marker":marker,"error_code":"replay_mismatch"}),
                at,
            )?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountDbKey, AccountIndex};
    use rusqlite::params;

    #[test]
    fn seen_markers_are_account_private_and_dead_letters_keep_only_the_marker()
    -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("seen-private-failure")?;
        let index = AccountIndex::open(root.join("second"))?;
        index.create_account("second", "second-root")?;
        let other = AccountDb::open(&index, "second", &AccountDbKey::generate()?)?;
        let committed = "routed/committed/public-dictionary-hash";
        let marker = db.routed_seen_key(committed)?;
        assert_ne!(marker, other.routed_seen_key(committed)?);
        db.persist_actor_state(&marker, &"payload-hash")?;
        let entry = br#"{"source_principal_id":"private-principal","source_device_id":"private-device","envelope_id":"private-envelope"}"#;
        assert_eq!(db.defer_inbox_entry(committed, entry, 1)?, 0);
        db.dead_letter_inbox(
            committed,
            entry,
            &json!({"error_code":"authentication_failed","envelope_id":"private-envelope"}),
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
        let marker = db.routed_seen_key("routed/committed/rollback")?;
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
}
