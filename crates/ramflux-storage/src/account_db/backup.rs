// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Consistent encrypted account snapshots, including every table and attachment BLOB.

use super::AccountDb;
use crate::{AccountDbKey, StorageError};
use std::path::Path;

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

/// The snapshot database key is secret and must enter only the encrypted archive.
/// Deliberately does not implement Debug or Serialize.
pub struct AccountBackupSnapshot {
    pub key: AccountDbKey,
    pub counts: BackupCounts,
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
        let key_hex = key.sqlcipher_hex();
        let fingerprint = key.fingerprint();
        let path = destination.to_owned();
        let counts = self.connection.call(move |source| {
            if !source.is_autocommit() && source.query_row("PRAGMA query_only",[],|row|row.get::<_,u32>(0))?!=1 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let mut target = rusqlite::Connection::open(path)?;
            target.execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\"; PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA cache_size=-2048;"))?;
            {
                let snapshot = rusqlite::backup::Backup::new(source, &mut target)?;
                loop {
                    if cancel.load(std::sync::atomic::Ordering::Acquire){return Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT),None));}
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
            target.execute_batch("DELETE FROM runtime_actor_state WHERE state_kind LIKE 'x3dh/private-state/%'; DELETE FROM projection_checkpoint WHERE projection_name LIKE 'x3dh_private:%' OR projection_name LIKE 'x3dh_private:v2/%'; UPDATE local_event_log SET event_body=x'7b7d',signature=x'',signature_status='retired' WHERE event_type='x3dh.prekey.private';")?;
            let archive_exists: bool = target.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='backup_archived_local_event')", [], |row| row.get(0))?;
            if archive_exists {
                target.execute("UPDATE backup_archived_local_event SET event_body=x'7b7d',signature=x'',signature_status='retired' WHERE event_type='x3dh.prekey.private'", [])?;
            }
            target.execute("UPDATE account_key_check SET key_fingerprint=?1 WHERE singleton_id=1", rusqlite::params![fingerprint])?;
            // All domain tables, keys and object payloads were copied by SQLite itself.
            let counts=read_counts(&target)?;
            target.close().map_err(|(_, error)| error)?;
            Ok(counts)
        })?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountIndex, EncryptionMode, EventStore, ProjectionStore};

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
        db.persist_actor_state(
            "x3dh/private-state/v3/device",
            &serde_json::json!({"signed_prekey_seed": vec![7_u8; 32]}),
        )?;
        db.append_event("legacy-private-prekey", "x3dh.prekey.private", b"private seed")?;
        db.set_projection_checkpoint("x3dh_private:v2/device", "legacy-private-prekey")?;
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
            raw.query_row(
                "SELECT count(*) FROM runtime_actor_state WHERE state_kind LIKE 'x3dh/private-state/%'",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            0
        );
        assert_eq!(
            raw.query_row(
                "SELECT CAST(event_body AS TEXT)||':'||signature_status FROM local_event_log WHERE event_id='legacy-private-prekey'",
                [],
                |row| row.get::<_, String>(0)
            )?,
            "{}:retired"
        );
        assert_eq!(
            raw.query_row(
                "SELECT count(*) FROM projection_checkpoint WHERE projection_name LIKE 'x3dh_private:%'",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            0
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
