// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-local repair identity, deliberately absent from account backup and restore inputs.
use super::AccountDb;
use crate::StorageError;

pub(super) fn initialize(connection: &crate::database::Connection) -> Result<(), StorageError> {
    let value = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    connection.execute_batch("CREATE TABLE IF NOT EXISTS reach_local_incarnation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),value TEXT NOT NULL);")?;
    connection.execute(
        "INSERT OR IGNORE INTO reach_local_incarnation(singleton,value) VALUES(1,?1)",
        rusqlite::params![value],
    )?;
    Ok(())
}

pub(super) fn strip(connection: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    connection.execute_batch("DROP TABLE IF EXISTS reach_local_incarnation")
}

impl AccountDb {
    /// Return the creation/restore incarnation used only for derived roster repair receipts.
    /// # Errors
    /// Refuses malformed local state and returns storage errors.
    pub fn reach_local_incarnation(&self) -> Result<String, StorageError> {
        let value: String = self.connection.query_row(
            "SELECT value FROM reach_local_incarnation WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let bytes = ramflux_protocol::decode_base64url(&value)
            .map_err(|_| StorageError::AuthorizationRejected)?;
        if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != value {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cr_reach_incarnation_survives_reopen_but_not_account_snapshot() -> Result<(), StorageError> {
        let temp = tempfile::TempDir::new()?;
        let index = crate::AccountIndex::open(temp.path())?;
        index.create_account("acct", "principal")?;
        let key = crate::AccountDbKey::derive("acct", b"reach-incarnation-test");
        let db = AccountDb::open(&index, "acct", &key)?;
        let first = db.reach_local_incarnation()?;
        db.persist_actor_state(
            "reach-group-roster/cache",
            &serde_json::json!({"incarnation":first}),
        )?;
        let path = temp.path().join("snapshot.db");
        let snapshot = db.write_backup_snapshot(&path)?;
        drop(db);
        let db = AccountDb::open(&index, "acct", &key)?;
        assert_eq!(
            db.reach_local_incarnation()?,
            first,
            "ordinary reopening must retain repair success bindings"
        );
        let backup = rusqlite::Connection::open(&path)?;
        backup.execute_batch(&format!("PRAGMA key=\"x'{}'\";", snapshot.key.sqlcipher_hex()))?;
        let exists: bool = backup.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='reach_local_incarnation')",
            [],
            |row| row.get(0),
        )?;
        assert!(!exists, "the actual account snapshot must never carry local repair identity");
        let restored_root = temp.path().join("restored");
        let restored_index = crate::AccountIndex::open(&restored_root)?;
        restored_index.create_account("acct", "principal")?;
        drop(AccountDb::open(&restored_index, "acct", &snapshot.key)?);
        let restored_path = restored_root.join(restored_index.account("acct")?.db_relative_path);
        std::fs::copy(&path, &restored_path)?;
        let restored = AccountDb::open(&restored_index, "acct", &snapshot.key)?;
        let cache: serde_json::Value = restored
            .load_actor_state("reach-group-roster/cache")?
            .ok_or(StorageError::AuthorizationRejected)?;
        assert_eq!(
            cache.get("incarnation").and_then(serde_json::Value::as_str),
            Some(first.as_str()),
            "the real snapshot restores the old cached roster success for the negative control"
        );
        assert_ne!(
            restored.reach_local_incarnation()?,
            first,
            "restoring the cache must not restore the authoritative local incarnation"
        );
        Ok(())
    }
    #[test]
    fn cr_reach_incarnation_backup_sanitizer_removes_local_identity() -> Result<(), StorageError> {
        let temp = tempfile::TempDir::new()?;
        let path = temp.path().join("backup.db");
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch("CREATE TABLE reach_local_incarnation(singleton INTEGER PRIMARY KEY,value TEXT NOT NULL); INSERT INTO reach_local_incarnation VALUES(1,'old');")?;
        strip(&connection)?;
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='reach_local_incarnation')",
            [],
            |row| row.get(0),
        )?;
        assert!(!exists, "backup/restore sanitization must remove the device-local incarnation");
        Ok(())
    }
}
