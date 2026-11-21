// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::GroupSenderKeyCounterRecord;
use rusqlite::OptionalExtension;

impl AccountDb {
    /// # Errors
    /// Returns an error when the sender-key replay table cannot be queried.
    pub fn group_sender_key_counter_seen(
        &self,
        group_id: &str,
        group_key_epoch: u64,
        sender: &ramflux_crypto::RootQualifiedDeviceRef,
        session_id: &str,
        counter: u64,
    ) -> Result<bool, StorageError> {
        let group_key_epoch = i64::try_from(group_key_epoch)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        let counter = i64::try_from(counter)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        let exists = self
            .connection
            .query_row(
                "SELECT 1
                   FROM root_group_sender_key_counter_seen
                  WHERE group_id = ?1 AND group_key_epoch = ?2
                    AND sender_reference = ?3 AND session_id = ?4 AND counter = ?5",
                params![group_id, group_key_epoch, sender.storage_key(), session_id, counter],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(exists)
    }

    /// Returns `true` when this call records a new counter and `false` when it was replayed.
    ///
    /// # Errors
    /// Returns an error when the sender-key replay table cannot be updated.
    pub fn record_group_sender_key_counter(
        &self,
        record: &GroupSenderKeyCounterRecord,
        sender: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<bool, StorageError> {
        if record.sender_id != sender.device_id() {
            return Err(StorageError::AuthorizationRejected);
        }
        let group_key_epoch = i64::try_from(record.group_key_epoch)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        let counter = i64::try_from(record.counter)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        let rows = self.connection.execute(
            "INSERT OR IGNORE INTO root_group_sender_key_counter_seen (
                group_id, group_key_epoch, sender_reference, session_id, counter, message_id, seen_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.group_id,
                group_key_epoch,
                sender.storage_key(),
                record.session_id,
                counter,
                record.message_id,
                record.seen_at
            ],
        )?;
        Ok(rows == 1)
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    fn device(seed: u8) -> Result<ramflux_crypto::RootQualifiedDeviceRef, StorageError> {
        Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
            &ramflux_crypto::create_identity_root("owner", [seed; 32]),
            "bob",
        )?)
    }
    #[test]
    fn group_counters_separate_equal_names_and_distinct_ratchet_sessions()
    -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("root-group-counter")?;
        let bob = device(11)?;
        let mallory = device(21)?;
        let record = GroupSenderKeyCounterRecord {
            group_id: "group".into(),
            group_key_epoch: 1,
            sender_id: "bob".into(),
            session_id: "ratchet-1".into(),
            counter: 0,
            message_id: "same-id".into(),
            seen_at: 100,
        };
        assert!(db.record_group_sender_key_counter(&record, &mallory)?);
        assert!(!db.group_sender_key_counter_seen("group", 1, &bob, "ratchet-1", 0)?);
        assert!(db.record_group_sender_key_counter(&record, &bob)?);
        assert!(!db.record_group_sender_key_counter(&record, &bob)?);
        assert!(!db.group_sender_key_counter_seen("group", 1, &bob, "ratchet-2", 0)?);
        let restored = GroupSenderKeyCounterRecord { session_id: "ratchet-2".into(), ..record };
        assert!(db.record_group_sender_key_counter(&restored, &bob)?);
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn old_counter_names_cannot_impersonate_a_qualified_reference_after_restart()
    -> Result<(), StorageError> {
        let (root, db) = crate::tests::test_db("legacy-group-counter")?;
        let bob = device(11)?;
        db.connection.execute(
            "INSERT INTO group_sender_key_counter_seen VALUES('group',1,?1,0,'old-message',100)",
            rusqlite::params![bob.storage_key()],
        )?;
        db.connection.execute("INSERT INTO projection_checkpoint(projection_name,projection_version,last_event_id,updated_at) VALUES('group_sender_key:v2/forged',1,'old-private-state',100)",[])?;
        db.connection.execute("DELETE FROM group_sender_identity_upgrade", [])?;
        drop(db);
        let db = AccountDb::open(
            &crate::AccountIndex::open(&root)?,
            "acct",
            &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
        )?;
        assert!(!db.group_sender_key_counter_seen("group", 1, &bob, "ratchet-1", 0)?);
        assert_eq!(
            db.connection.query_row(
                "SELECT count(*) FROM legacy_group_sender_key_counter_seen",
                [],
                |row| row.get::<_, u32>(0)
            )?,
            1
        );
        assert_eq!(db.projection_checkpoint("group_sender_key:v2/forged")?, None);
        assert_eq!(
            db.projection_checkpoint("legacy/group_sender_key/group_sender_key:v2/forged")?
                .as_deref(),
            Some("old-private-state")
        );
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
