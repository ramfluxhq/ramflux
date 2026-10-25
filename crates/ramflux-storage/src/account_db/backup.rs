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
        let file = std::fs::OpenOptions::new().create_new(true).write(true).open(destination)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        drop(file);
        let key = self.current_key.clone();
        let key_hex = key.sqlcipher_hex();
        let path = destination.to_owned();
        let counts = self.connection.call(move |source| {
            if !source.is_autocommit() {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let mut target = rusqlite::Connection::open(path)?;
            target.execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\"; PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA cache_size=-2048;"))?;
            {
                let snapshot = rusqlite::backup::Backup::new(source, &mut target)?;
                loop {
                    match snapshot.step(128)? {
                        rusqlite::backup::StepResult::Done => break,
                        rusqlite::backup::StepResult::More => {},
                        _ => return Err(rusqlite::Error::SqliteFailure(
                            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                            Some("account backup snapshot busy".into()),
                        )),
                    }
                }
            }
            // All domain tables, keys and object payloads were copied by SQLite itself.
            let counts = BackupCounts {
                contacts: target.query_row("SELECT count(*) FROM friend_link_projection", [], |row| row.get(0))?,
                conversations: target.query_row("SELECT count(*) FROM conversation_projection", [], |row| row.get(0))?,
                messages: target.query_row("SELECT count(*) FROM message_projection", [], |row| row.get(0))?,
                groups: target.query_row("SELECT count(*) FROM group_projection", [], |row| row.get(0))?,
                attachments: target.query_row("SELECT count(*) FROM object_index", [], |row| row.get(0))?,
                attachment_bytes: target.query_row("SELECT coalesce(sum(length(ciphertext)),0) FROM object_index", [], |row| row.get(0))?,
            };
            target.close().map_err(|(_, error)| error)?;
            Ok(counts)
        })?;
        std::fs::File::open(destination)?.sync_all()?;
        Ok(AccountBackupSnapshot { key, counts })
    }
}

#[cfg(test)]
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
        let target = path.join("snapshot.db");
        let snapshot = db.write_backup_snapshot(&target)?;
        assert_eq!(snapshot.key, key);
        assert!(db.write_backup_snapshot(&target).is_err());
        let raw = rusqlite::Connection::open(&target)?;
        assert!(
            raw.query_row("SELECT count(*) FROM backup_blob_fixture", [], |row| row
                .get::<_, u64>(0))
                .is_err()
        );
        raw.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key.sqlcipher_hex()))?;
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
