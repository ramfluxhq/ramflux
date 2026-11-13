// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Consistent encrypted account snapshots, including every table and attachment BLOB.

use super::AccountDb;
use crate::{AccountDbKey, StorageError};
use std::path::Path;
mod tail;

/// Per-category counts read from the exact snapshot, with no row-count limit.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BackupCounts {
    pub contacts: u64,
    pub conversations: u64,
    pub messages: u64,
    pub groups: u64,
    pub surfaces: u64,
    pub tasks: u64,
    pub attachments: u64,
    pub attachment_bytes: u64,
}

/// The snapshot database key is secret and remains with its local snapshot/archive owner.
/// Full pairing transfers encode logical records only; this key must never cross that channel.
/// Deliberately does not implement Debug or Serialize.
pub struct AccountBackupSnapshot {
    pub key: AccountDbKey,
    pub counts: BackupCounts,
}

/// Device-local pinned encrypted read view. Pinning and copying are separate operations so
/// the generation/writer owner releases queued writes before any bulk disk work.
/// Neither its source key nor the eventual database file belongs on the pairing wire.
pub struct FullTransferCut {
    reader: AccountDb,
    unlocked_owner: crate::database::WeakConnection,
}
impl FullTransferCut {
    /// Copy the previously pinned view to A-private encrypted storage in bounded page batches.
    /// # Errors
    /// Refuses unresolved scratch, cancellation, low space and snapshot I/O errors.
    pub fn write_private_snapshot(
        self,
        destination: &Path,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<AccountBackupSnapshot, StorageError> {
        self.reader.require_selected_transfer_source()?;
        self.require_unlocked_owner()?;
        let copied = self.reader.write_snapshot(
            destination,
            cancel,
            SnapshotPolicy::NativeFullTransfer(self.unlocked_owner.clone()),
        )?;
        self.reader.require_selected_transfer_source()?;
        self.require_unlocked_owner()?;
        Ok(copied)
    }
    /// Inspect this same pinned read transaction without copying a raw database/key.
    /// Only account-db transfer owners can use these data-only frozen observations.
    pub(in crate::account_db) fn inspect_full_profile_cut(
        &self,
    ) -> Result<(super::full_transfer::FullTransferSchema, u64, u64), StorageError> {
        self.reader.require_selected_transfer_source()?;
        self.require_unlocked_owner()?;
        let schema = super::full_transfer::inspect_pinned_full_transfer(
            &self.reader.connection,
            super::full_transfer::full_transfer_catalog(),
        )?;
        let storage_generation = self.reader.connection.query_row(
            "SELECT max(schema_version) FROM schema_migration",
            [],
            |row| row.get::<_, u64>(0),
        )?;
        let erasure_generation = self.reader.connection.query_row(
            "SELECT generation FROM account_erasure_generation WHERE singleton=1",
            [],
            |row| row.get::<_, u64>(0),
        )?;
        self.reader.require_selected_transfer_source()?;
        self.require_unlocked_owner()?;
        Ok((schema, storage_generation, erasure_generation))
    }
    fn require_unlocked_owner(&self) -> Result<(), StorageError> {
        if self.unlocked_owner.upgrade_account_writer().is_none() {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(())
    }
}

#[derive(Clone)]
enum SnapshotPolicy {
    Backup,
    NativeFullTransfer(crate::database::WeakConnection),
}

impl AccountDb {
    /// Reads an unambiguous preserved historical event which could not enter the live event log.
    /// A local record, including an explicitly retired record, always takes precedence.
    /// # Errors
    /// Returns SQL errors or refuses conflicting archived bodies for one event ID.
    pub fn archived_backup_event_body(&self, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let exists:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='backup_archived_local_event')",[],|r|r.get(0))?;
        if !exists {
            return Ok(None);
        }
        let variants:u64=self.connection.query_row("SELECT count(DISTINCT event_body) FROM backup_archived_local_event WHERE event_id=?1 AND signature_status!='retired' AND NOT EXISTS(SELECT 1 FROM local_event_log WHERE event_id=?1)",rusqlite::params![id],|r|r.get(0))?;
        if variants > 1 {
            return Err(StorageError::AuthorizationRejected);
        }
        if variants == 0 {
            return Ok(None);
        }
        Ok(Some(self.connection.query_row("SELECT event_body FROM backup_archived_local_event WHERE event_id=?1 AND signature_status!='retired' LIMIT 1",rusqlite::params![id],|r|r.get(0))?))
    }
    /// Returns a conservative encrypted snapshot size without enumerating domain rows.
    /// # Errors
    /// Returns SQL errors reading the current pinned snapshot page metadata.
    pub fn backup_estimated_bytes(&self) -> Result<u64, StorageError> {
        Ok(self.connection.query_row(
            "SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size()",
            [],
            |row| row.get(0),
        )?)
    }

    /// Writes a consistent encrypted snapshot without materializing rows or BLOBs.
    /// The destination must be inside a private staging directory and must not exist.
    /// On any error the caller must discard the private staging directory.
    ///
    /// # Errors
    /// Rejects existing destinations, an active writer transaction, a busy source,
    /// and SQLCipher/SQLite or filesystem failures.
    pub fn write_backup_snapshot(
        &self,
        destination: &Path,
    ) -> Result<AccountBackupSnapshot, StorageError> {
        self.write_backup_snapshot_cancellable(
            destination,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
    }
    /// Writes a snapshot with cancellation checked between bounded page batches.
    /// # Errors
    /// Returns snapshot errors or SQLite interruption when cancellation is requested.
    pub fn write_backup_snapshot_cancellable(
        &self,
        destination: &Path,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<AccountBackupSnapshot, StorageError> {
        self.write_snapshot(destination, cancel, SnapshotPolicy::Backup)
    }

    /// Take an A-private consistent cut for the full logical transfer encoder.
    /// Unlike a backup, this cut preserves every source record for typed T/E/R projection.
    /// It includes source-local secrets: neither its file nor its key may be transmitted.
    /// # Errors
    /// Refuses unresolved restore scratch, cancellation, a busy source or snapshot I/O errors.
    pub fn write_full_transfer_snapshot_cancellable(
        &self,
        destination: &Path,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<AccountBackupSnapshot, StorageError> {
        self.pin_full_transfer_cut()?.write_private_snapshot(destination, cancel)
    }

    /// Pin an independent read-only cut under the caller's generation/writer owner.
    /// Callers must commit the exact J6 acknowledgement before taking a tail cut,
    /// then release that owner before calling `write_private_snapshot`.
    /// # Errors
    /// Refuses stale account generations and encrypted read transaction failures.
    pub fn pin_full_transfer_cut(&self) -> Result<FullTransferCut, StorageError> {
        self.require_selected_transfer_source()?;
        let unlocked_owner = self.connection.downgrade();
        if unlocked_owner.upgrade_account_writer().is_none() {
            return Err(StorageError::AuthorizationRejected);
        }
        let cut = FullTransferCut { reader: self.open_backup_reader()?, unlocked_owner };
        cut.reader.require_selected_transfer_source()?;
        Ok(cut)
    }

    pub(super) fn require_selected_transfer_source(&self) -> Result<(), StorageError> {
        let selected = match self.account_index.account(&self.local_account_id) {
            Err(StorageError::AccountNotFound(_)) => {
                return Err(StorageError::PairingField("SnapshotInvalidated"));
            }
            value => value?,
        };
        if selected.account_state == "removed"
            || self.account_index.root().join(&selected.db_relative_path) != self.path
            || selected.principal_commitment != self.principal_commitment
        {
            return Err(StorageError::PairingField("SnapshotInvalidated"));
        }
        Ok(())
    }

    fn write_snapshot(
        &self,
        destination: &Path,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
        policy: SnapshotPolicy,
    ) -> Result<AccountBackupSnapshot, StorageError> {
        let parent = destination
            .parent()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?
            .to_owned();
        let estimate = self.connection.query_row(
            "SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size()",
            [],
            |row| row.get::<_, u64>(0),
        )?;
        super::backup_database::require_space(&parent, estimate.saturating_add(20 * 1024 * 1024))?;
        let file = std::fs::OpenOptions::new().create_new(true).write(true).open(destination)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        drop(file);
        let key = AccountDbKey::generate()?;
        let key_hex = zeroize::Zeroizing::new(key.sqlcipher_hex());
        let fingerprint = key.fingerprint();
        let path = destination.to_owned();
        let counts = self.connection.call(move |source| {
            if !source.is_autocommit() && source.query_row("PRAGMA query_only",[],|row|row.get::<_,u32>(0))?!=1 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let mut target = rusqlite::Connection::open(path)?;
            target.execute_batch(&zeroize::Zeroizing::new(format!("PRAGMA key = \"x'{}'\"; PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA cache_size=-2048; PRAGMA secure_delete=ON;", key_hex.as_str())))?;
            {
                let snapshot = rusqlite::backup::Backup::new(source, &mut target)?;
                loop {
                    if cancel.load(std::sync::atomic::Ordering::Acquire)
                        || matches!(&policy, SnapshotPolicy::NativeFullTransfer(owner) if owner.upgrade_account_writer().is_none()) {return Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT),None));}
                    match snapshot.step(128)? {
                        rusqlite::backup::StepResult::Done => break,
                        rusqlite::backup::StepResult::More => {
                            if fs2::available_space(&parent).unwrap_or(0)<2*1024*1024 {
                                return Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),None));
                            }
                        },
                        _ => return Err(rusqlite::Error::SqliteFailure(
                            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                            Some("account backup snapshot busy".into()),
                        )),
                    }
                }
            }
            target.execute("UPDATE account_key_check SET key_fingerprint=?1 WHERE singleton_id=1", rusqlite::params![fingerprint])?;
            if matches!(policy, SnapshotPolicy::NativeFullTransfer(_)) {
                if let Err(error) = super::backup_native::full_transfer_snapshot_preflight(&target) {
                    return Ok(Err(error));
                }
                let counts = read_counts(&target)?;
                target.close().map_err(|(_, error)| error)?;
                return Ok(Ok(counts));
            }
            super::backup_selector_admission::drop_scratch(&target)?;
            super::home_migration::strip_from_backup(&target)?;
            if let Err(error) = super::receive::ledger_backup::sanitize_backup(&target) {
                return Ok(Err(error));
            }
            if let Err(error) = super::pairing::sanitize_backup(&target) {
                return Ok(Err(error));
            }
            super::backup_retirement::strip_own_copy_locators(&target)?;
            target.execute("DELETE FROM object_segment_resource", [])?;
            // Historical archives have no native physical progress to clear.
            let native:bool=target.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='object_segment_file')",[],|r|r.get(0))?;
            if native {
                target.execute("UPDATE object_segment_file SET received_bitmap=0,chunk_digests=zeroblob(256),cipher_verified=0",[])?;
                target.execute("UPDATE object_transfer_state SET done_bytes=0,segment_sequence=0 WHERE segment_generation IS NOT NULL",[])?;
            }
            // Domain history, keys and object payloads were copied by SQLite itself.
            let counts=read_counts(&target)?;
            target.close().map_err(|(_, error)| error)?;
            Ok(Ok(counts))
        })??;
        std::fs::File::open(destination)?.sync_all()?;
        Ok(AccountBackupSnapshot { key, counts })
    }
}

pub(super) fn read_counts(db: &rusqlite::Connection) -> rusqlite::Result<BackupCounts> {
    let count = |sql| db.query_row(sql, [], |row| row.get::<_, u64>(0));
    Ok(BackupCounts {
        contacts: count("SELECT count(*) FROM friend_link_projection")?,
        conversations: count(
            "SELECT (SELECT count(*) FROM runtime_actor_state WHERE state_kind LIKE 'directory/conversation/%')+(SELECT count(*) FROM conversation_projection c WHERE NOT EXISTS(SELECT 1 FROM runtime_actor_state r WHERE r.state_kind='directory/conversation/'||c.conversation_id))+(SELECT count(*) FROM conversation_list_state c WHERE NOT EXISTS(SELECT 1 FROM runtime_actor_state r WHERE r.state_kind='directory/conversation/'||c.conversation_id) AND NOT EXISTS(SELECT 1 FROM conversation_projection p WHERE p.conversation_id=c.conversation_id))+(SELECT count(*) FROM (SELECT conversation_id FROM direct_message_projection GROUP BY conversation_id) c WHERE NOT EXISTS(SELECT 1 FROM runtime_actor_state r WHERE r.state_kind='directory/conversation/'||c.conversation_id) AND NOT EXISTS(SELECT 1 FROM conversation_projection p WHERE p.conversation_id=c.conversation_id) AND NOT EXISTS(SELECT 1 FROM conversation_list_state l WHERE l.conversation_id=c.conversation_id))",
        )?,
        messages: count(
            "SELECT (SELECT count(*) FROM direct_message_projection)+(SELECT count(*) FROM message_projection m WHERE NOT EXISTS(SELECT 1 FROM direct_message_projection d WHERE d.message_id=m.message_id))",
        )?,
        groups: count("SELECT count(*) FROM group_projection")?,
        surfaces: count(
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind LIKE 'surface/state/%'",
        )?,
        tasks: count(
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind LIKE 'task/view/%'",
        )?,
        attachments: count("SELECT count(*) FROM object_index WHERE backup_excluded=0")?,
        attachment_bytes: count(
            "SELECT coalesce(sum(length(ciphertext)),0) FROM object_index WHERE backup_excluded=0",
        )?,
    })
}

#[cfg(all(test, feature = "sqlcipher"))]
mod tests {
    use super::*;
    use crate::{AccountIndex, EncryptionMode};

    #[test]
    fn encrypted_snapshot_includes_uncheckpointed_wal_and_all_rows_without_decoding_blobs()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "rf-backup-snapshot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = AccountIndex::open(&path)?;
        index.create_account("account", "root")?;
        let key = AccountDbKey::generate()?;
        let db = AccountDb::open(&index, "account", &key)?;
        assert_eq!(db.encryption_mode(), EncryptionMode::SqlCipher);
        // The database worker never transfers SQLite rows or large BLOBs to Rust.
        db.connection.execute_batch("CREATE TABLE backup_blob_fixture(id INTEGER PRIMARY KEY,payload BLOB); INSERT INTO backup_blob_fixture VALUES(1,zeroblob(2000000));")?;
        for number in 0..1100 {
            db.persist_actor_state(&format!("backup-fixture/{number}"), &number)?;
        }
        db.persist_actor_state("surface/state/fixture", &serde_json::json!({"surface_id":"s"}))?;
        db.persist_actor_state("task/view/fixture", &serde_json::json!({"task_id":"t"}))?;
        let target = path.join("snapshot.db");
        let snapshot = db.write_backup_snapshot(&target)?;
        assert_ne!(snapshot.key, key);
        assert_eq!(snapshot.counts.surfaces, 1);
        assert_eq!(snapshot.counts.tasks, 1);
        let old_key_reader = rusqlite::Connection::open(&target)?;
        old_key_reader.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key.sqlcipher_hex()))?;
        assert!(
            old_key_reader
                .query_row("SELECT count(*) FROM backup_blob_fixture", [], |row| row
                    .get::<_, u64>(0))
                .is_err()
        );
        old_key_reader.close().map_err(|(_, error)| error)?;
        assert!(db.write_backup_snapshot(&target).is_err());
        let raw = rusqlite::Connection::open(&target)?;
        assert!(
            raw.query_row("SELECT count(*) FROM backup_blob_fixture", [], |row| row
                .get::<_, u64>(0))
                .is_err()
        );
        raw.execute_batch(&format!("PRAGMA key = \"x'{}'\";", snapshot.key.sqlcipher_hex()))?;
        assert_eq!(
            raw.query_row("SELECT length(payload) FROM backup_blob_fixture", [], |row| row
                .get::<_, u64>(0))?,
            2_000_000
        );
        assert_eq!(
            raw.query_row(
                "SELECT count(*) FROM runtime_actor_state WHERE state_kind LIKE 'backup-fixture/%'",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            1100
        );
        assert_eq!(
            raw.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?,
            "ok"
        );
        raw.close().map_err(|(_, error)| error)?;
        drop(db);
        drop(index);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
}

#[cfg(test)]
mod archived_event_tests {
    use super::*;
    use crate::{AccountIndex, EventStore};
    #[test]
    fn archived_history_never_revives_retired_events_or_guesses_conflicting_bodies()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-backup-archive-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = AccountIndex::open(&root)?;
        index.create_account("account", "root")?;
        let key = AccountDbKey::generate()?;
        let db = AccountDb::open(&index, "account", &key)?;
        db.append_event("retired", "test.history", b"retired secret")?;
        db.append_event("archive-only", "test.history", b"historical state")?;
        db.connection.execute_batch("CREATE TABLE backup_archived_local_event AS SELECT 'source' AS source,* FROM local_event_log; UPDATE local_event_log SET signature_status='retired',event_body=x'' WHERE event_id='retired'; DELETE FROM local_event_log WHERE event_id='archive-only';")?;
        assert_eq!(db.archived_backup_event_body("retired")?, None);
        assert_eq!(
            db.archived_backup_event_body("archive-only")?,
            Some(b"historical state".to_vec())
        );
        db.connection.execute_batch("INSERT INTO backup_archived_local_event SELECT 'conflict',event_id,event_type,actor_principal_id,actor_device_id,device_counter,lamport_time,created_at,causal_prev_json,x'0102',signature,signature_status,projection_status FROM backup_archived_local_event WHERE event_id='archive-only';")?;
        assert!(matches!(
            db.archived_backup_event_body("archive-only"),
            Err(StorageError::AuthorizationRejected)
        ));
        drop(db);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
