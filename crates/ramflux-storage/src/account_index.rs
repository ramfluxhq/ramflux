// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::wildcard_imports)]
use crate::*;
use rusqlite::{Connection, OptionalExtension, params};
use std::fs;
use std::path::{Path, PathBuf};

pub struct AccountIndex {
    root: PathBuf,
    connection: Connection,
}

impl AccountIndex {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        fs::create_dir_all(root.as_ref())?;
        let path = root.as_ref().join(ACCOUNT_INDEX_FILE);
        let connection = Connection::open(path)?;
        migrate_account_index(&connection)?;
        Ok(Self { root: root.as_ref().to_path_buf(), connection })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn create_account(
        &self,
        local_account_id: &str,
        principal_commitment: &str,
    ) -> Result<LocalAccountRecord, StorageError> {
        let db_relative_path = format!("accounts/{local_account_id}/{ACCOUNT_DB_FILE}");
        let object_dir_relative_path = format!("accounts/{local_account_id}/objects");
        let account_dir = self.root.join(format!("accounts/{local_account_id}"));
        fs::create_dir_all(account_dir.join("objects"))?;
        self.connection.execute(
            "INSERT OR REPLACE INTO local_account (
                local_account_id, principal_commitment, display_label, db_relative_path,
                object_dir_relative_path, key_wrapping_provider, key_wrapping_ref,
                account_state, created_at, last_opened_at
            ) VALUES (?1, ?2, NULL, ?3, ?4, 'platform-local-vault', ?5, 'active', ?6, NULL)",
            params![
                local_account_id,
                principal_commitment,
                db_relative_path,
                object_dir_relative_path,
                format!("platform-local-vault:{local_account_id}"),
                unix_now()
            ],
        )?;
        Ok(LocalAccountRecord {
            local_account_id: local_account_id.to_owned(),
            principal_commitment: principal_commitment.to_owned(),
            db_relative_path,
            object_dir_relative_path,
            account_state: "active".to_owned(),
        })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn account(&self, local_account_id: &str) -> Result<LocalAccountRecord, StorageError> {
        self.connection
            .query_row(
                "SELECT local_account_id, principal_commitment, db_relative_path,
                        object_dir_relative_path, account_state
                   FROM local_account
                  WHERE local_account_id = ?1",
                params![local_account_id],
                |row| {
                    Ok(LocalAccountRecord {
                        local_account_id: row.get(0)?,
                        principal_commitment: row.get(1)?,
                        db_relative_path: row.get(2)?,
                        object_dir_relative_path: row.get(3)?,
                        account_state: row.get(4)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::AccountNotFound(local_account_id.to_owned()))
    }

    /// # Errors
    /// Returns an error when the account is missing or the wrapped key cannot be persisted.
    pub fn store_wrapped_db_key(
        &self,
        local_account_id: &str,
        wrapped_key: &WrappedAccountDbKey,
    ) -> Result<(), StorageError> {
        self.account(local_account_id)?;
        self.connection.execute(
            "UPDATE local_account
                SET key_wrapping_provider = ?2,
                    key_wrapping_ref = ?3,
                    wrapped_key = ?4,
                    wrapped_key_nonce = ?5
              WHERE local_account_id = ?1",
            params![
                local_account_id,
                wrapped_key.key_wrapping_provider,
                wrapped_key.key_wrapping_ref,
                wrapped_key.wrapped_key,
                wrapped_key.nonce.as_slice()
            ],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the account is missing or the stored wrapped key is malformed.
    pub fn load_wrapped_db_key(
        &self,
        local_account_id: &str,
    ) -> Result<Option<WrappedAccountDbKey>, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT key_wrapping_provider, key_wrapping_ref, wrapped_key, wrapped_key_nonce
                   FROM local_account
                  WHERE local_account_id = ?1",
                params![local_account_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::AccountNotFound(local_account_id.to_owned()))?;
        let (key_wrapping_provider, key_wrapping_ref, Some(wrapped_key), Some(nonce)) = row else {
            return Ok(None);
        };
        let nonce: [u8; 12] = nonce.try_into().map_err(|bytes: Vec<u8>| {
            StorageError::KeyWrappingFailed(format!(
                "invalid wrapped account DB key nonce length: {}",
                bytes.len()
            ))
        })?;
        Ok(Some(WrappedAccountDbKey {
            key_wrapping_provider,
            key_wrapping_ref,
            nonce,
            wrapped_key,
        }))
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn set_active_account(&self, local_account_id: &str) -> Result<(), StorageError> {
        self.account(local_account_id)?;
        self.connection.execute(
            "INSERT INTO active_account_state (singleton_id, active_local_account_id, updated_at)
             VALUES (1, ?1, ?2)
             ON CONFLICT(singleton_id)
             DO UPDATE SET active_local_account_id = excluded.active_local_account_id,
                           updated_at = excluded.updated_at",
            params![local_account_id, unix_now()],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn active_account(&self) -> Result<Option<String>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT active_local_account_id FROM active_account_state WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn connection(&self) -> &Connection {
        &self.connection
    }
}

pub(crate) fn migrate_account_index(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS account_index_migration (
            schema_version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL,
            app_version TEXT NOT NULL,
            notes TEXT
        );
        CREATE TABLE IF NOT EXISTS local_account (
            local_account_id TEXT PRIMARY KEY,
            principal_commitment TEXT NOT NULL,
            display_label TEXT,
            db_relative_path TEXT NOT NULL,
            object_dir_relative_path TEXT NOT NULL,
            key_wrapping_provider TEXT NOT NULL,
            key_wrapping_ref TEXT NOT NULL,
            account_state TEXT NOT NULL CHECK (account_state IN ('active','locked','removed','pending_rekey')),
            created_at INTEGER NOT NULL,
            last_opened_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_local_account_principal
            ON local_account(principal_commitment);
        CREATE TABLE IF NOT EXISTS active_account_state (
            singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
            active_local_account_id TEXT,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(active_local_account_id) REFERENCES local_account(local_account_id)
        );
        CREATE TABLE IF NOT EXISTS app_setting (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        ",
    )?;
    connection.execute(
        "INSERT OR IGNORE INTO account_index_migration
            (schema_version, applied_at, app_version, notes)
         VALUES (1, ?1, 'mvp-1', 'initial account index schema')",
        params![unix_now()],
    )?;
    add_local_account_column_if_missing(connection, "wrapped_key", "BLOB")?;
    add_local_account_column_if_missing(connection, "wrapped_key_nonce", "BLOB")?;
    Ok(())
}

fn add_local_account_column_if_missing(
    connection: &Connection,
    column_name: &str,
    column_definition: &str,
) -> Result<(), StorageError> {
    let mut statement = connection.prepare("PRAGMA table_info(local_account)")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column_name {
            return Ok(());
        }
    }
    connection.execute_batch(&format!(
        "ALTER TABLE local_account ADD COLUMN {column_name} {column_definition};"
    ))?;
    Ok(())
}
