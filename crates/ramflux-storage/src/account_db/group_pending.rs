// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::{GroupPendingUndecryptedRecord, GroupSenderKeyCounterRecord};
use rusqlite::OptionalExtension;

impl AccountDb {
    pub fn upsert_group_pending_undecrypted(
        &self,
        record: &GroupPendingUndecryptedRecord,
    ) -> Result<(), StorageError> {
        let group_key_epoch = i64::try_from(record.group_key_epoch)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        let inbox_seq = i64::try_from(record.inbox_seq)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        self.connection.execute(
            "INSERT INTO group_pending_undecrypted (
                message_id, group_id, conversation_id, group_key_epoch, sender_id,
                inbox_seq, envelope_json, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(message_id)
             DO UPDATE SET
                group_id = excluded.group_id,
                conversation_id = excluded.conversation_id,
                group_key_epoch = excluded.group_key_epoch,
                sender_id = excluded.sender_id,
                inbox_seq = excluded.inbox_seq,
                envelope_json = excluded.envelope_json,
                created_at = excluded.created_at",
            params![
                record.message_id,
                record.group_id,
                record.conversation_id,
                group_key_epoch,
                record.sender_id,
                inbox_seq,
                record.envelope_json,
                record.created_at
            ],
        )?;
        self.prune_group_pending_undecrypted(&record.group_id, record.created_at)?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when pending group messages cannot be queried.
    pub fn group_pending_undecrypted(
        &self,
        group_id: &str,
        group_key_epoch: u64,
    ) -> Result<Vec<GroupPendingUndecryptedRecord>, StorageError> {
        let group_key_epoch = i64::try_from(group_key_epoch)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        let mut statement = self.connection.prepare(
            "SELECT group_id, conversation_id, group_key_epoch, message_id, sender_id,
                    inbox_seq, envelope_json, created_at
               FROM group_pending_undecrypted
              WHERE group_id = ?1 AND group_key_epoch = ?2
              ORDER BY inbox_seq ASC, message_id ASC",
        )?;
        let rows = statement.query_map(params![group_id, group_key_epoch], |row| {
            let group_key_epoch_i64: i64 = row.get(2)?;
            let inbox_seq_i64: i64 = row.get(5)?;
            Ok(GroupPendingUndecryptedRecord {
                group_id: row.get(0)?,
                conversation_id: row.get(1)?,
                group_key_epoch: u64::try_from(group_key_epoch_i64).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Integer,
                        Box::new(err),
                    )
                })?,
                message_id: row.get(3)?,
                sender_id: row.get(4)?,
                inbox_seq: u64::try_from(inbox_seq_i64).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Integer,
                        Box::new(err),
                    )
                })?,
                envelope_json: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StorageError::from)
    }

    /// # Errors
    /// Returns an error when pending group messages cannot be counted.
    pub fn group_pending_undecrypted_count(&self, group_id: &str) -> Result<usize, StorageError> {
        let count = self.connection.query_row(
            "SELECT COUNT(*) FROM group_pending_undecrypted WHERE group_id = ?1",
            params![group_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    /// # Errors
    /// Returns an error when pending group messages cannot be counted.
    pub fn group_pending_undecrypted_total_count(&self) -> Result<usize, StorageError> {
        let count = self.connection.query_row(
            "SELECT COUNT(*) FROM group_pending_undecrypted",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    /// # Errors
    /// Returns an error when the pending group message cannot be removed.
    pub fn remove_group_pending_undecrypted(&self, message_id: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM group_pending_undecrypted WHERE message_id = ?1",
            params![message_id],
        )?;
        Ok(())
    }

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

    fn prune_group_pending_undecrypted(
        &self,
        group_id: &str,
        reference_time: i64,
    ) -> Result<(), StorageError> {
        let ttl_cutoff = reference_time.saturating_sub(GROUP_PENDING_UNDECRYPTED_TTL_SECONDS);
        let expired = self.connection.execute(
            "DELETE FROM group_pending_undecrypted WHERE created_at < ?1",
            params![ttl_cutoff],
        )?;
        if expired > 0 {
            tracing::warn!(expired, "evicted expired group pending-UTD rows before retry");
        }

        let per_group_overflow = self
            .group_pending_undecrypted_count(group_id)?
            .saturating_sub(GROUP_PENDING_UNDECRYPTED_PER_GROUP_LIMIT);
        if per_group_overflow > 0 {
            let limit = i64::try_from(per_group_overflow).unwrap_or(i64::MAX);
            let rows = self.connection.execute(
                "DELETE FROM group_pending_undecrypted
                  WHERE message_id IN (
                    SELECT message_id
                      FROM group_pending_undecrypted
                     WHERE group_id = ?1
                     ORDER BY inbox_seq ASC, created_at ASC, message_id ASC
                     LIMIT ?2
                  )",
                params![group_id, limit],
            )?;
            tracing::warn!(
                group_id,
                evicted = rows,
                limit = GROUP_PENDING_UNDECRYPTED_PER_GROUP_LIMIT,
                "evicted oldest group pending-UTD rows over per-group limit"
            );
        }

        let global_overflow = self
            .group_pending_undecrypted_total_count()?
            .saturating_sub(GROUP_PENDING_UNDECRYPTED_GLOBAL_LIMIT);
        if global_overflow > 0 {
            let limit = i64::try_from(global_overflow).unwrap_or(i64::MAX);
            let rows = self.connection.execute(
                "DELETE FROM group_pending_undecrypted
                  WHERE message_id IN (
                    SELECT message_id
                      FROM group_pending_undecrypted
                     ORDER BY inbox_seq ASC, created_at ASC, message_id ASC
                     LIMIT ?1
                  )",
                params![limit],
            )?;
            tracing::warn!(
                evicted = rows,
                limit = GROUP_PENDING_UNDECRYPTED_GLOBAL_LIMIT,
                "evicted oldest group pending-UTD rows over global limit"
            );
        }
        Ok(())
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
