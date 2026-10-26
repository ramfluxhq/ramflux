// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WAL durability and consistent query-only read connections.

use super::super::AccountDb;
use crate::StorageError;
use crate::database::Connection;
use crate::encryption::{apply_key, verify_or_install_key_fingerprint};
use rusqlite::OpenFlags;
use std::cell::RefCell;
use std::collections::BTreeMap;

impl AccountDb {
    /// Enables the durable runtime contract before readers or network requests start.
    ///
    /// # Errors
    /// Returns an error if WAL/FULL cannot be enabled or the outbox cannot be installed.
    pub fn enable_runtime(&self) -> Result<(), StorageError> {
        self.connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA secure_delete=ON;",
        )?;
        let journal: String =
            self.connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        let sync: i64 = self.connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        if journal != "wal" || sync != 2 {
            return Err(StorageError::AuthorizationRejected);
        }
        self.install_journal_schema()?;
        self.install_runtime_schema()?;
        self.checkpoint_retired_secrets()
    }

    /// Checkpoints deleted secret pages after the surrounding writer transaction has committed.
    /// # Errors
    /// Returns SQLite errors. Busy readers may retain an older encrypted WAL generation.
    pub fn checkpoint_retired_secrets(&self) -> Result<(), StorageError> {
        self.connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Checkpoints retired pages only after the outer writer phase has committed.
    /// # Errors
    /// Returns SQLite errors; returns false while a surrounding transaction remains open.
    pub fn checkpoint_retired_secrets_if_committed(&self) -> Result<bool, StorageError> {
        if !self.connection.is_autocommit()? {
            return Ok(false);
        }
        self.checkpoint_retired_secrets()?;
        Ok(true)
    }

    /// Opens an independently owned, query-only encrypted connection with the same key.
    ///
    /// # Errors
    /// Returns an error when opening or authenticating the read connection fails.
    pub fn open_reader(&self) -> Result<Self, StorageError> {
        let connection = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        apply_key(&connection, &self.current_key)?;
        verify_or_install_key_fingerprint(&connection, &self.current_key)?;
        connection.execute_batch("PRAGMA query_only=ON; PRAGMA synchronous=FULL;")?;
        Ok(Self {
            local_account_id: self.local_account_id.clone(),
            path: self.path.clone(),
            mode: self.mode,
            current_key: self.current_key.clone(),
            device_signer: self.device_signer.clone(),
            clock: self.clock.clone(),
            connection,
            volatile_typing: RefCell::new(BTreeMap::new()),
            volatile_presence: RefCell::new(BTreeMap::new()),
        })
    }

    /// Whether this connection enforces query-only access.
    /// # Errors
    /// Returns an error when the SQLite connection mode cannot be queried.
    pub fn is_query_only(&self) -> Result<bool, StorageError> {
        Ok(self.connection.query_row("PRAGMA query_only", [], |row| row.get::<_, u32>(0))? != 0)
    }

    /// Pins a read snapshot for an account-ordered backup capture.
    /// # Errors
    /// Returns encrypted reader or transaction errors.
    pub fn open_backup_reader(&self) -> Result<Self, StorageError> {
        let reader = self.open_reader()?;
        reader.connection.execute_batch("BEGIN; SELECT key_fingerprint FROM account_key_check;")?;
        Ok(reader)
    }

    /// Groups all reads in the callback under one SQLite snapshot.
    ///
    /// # Errors
    /// Returns callback errors or errors beginning/ending the read transaction.
    pub fn read_snapshot<T, E>(&self, read: impl FnOnce() -> Result<T, E>) -> Result<T, E>
    where
        E: From<StorageError>,
    {
        let transaction = self.connection.unchecked_transaction().map_err(StorageError::from)?;
        let result = read()?;
        transaction.commit().map_err(StorageError::from)?;
        Ok(result)
    }
}

impl AccountDb {
    /// Runs a synchronous writer phase atomically; the closure must not perform network I/O.
    ///
    /// # Errors
    /// Returns callback, BEGIN or COMMIT errors; failed callbacks roll back.
    pub fn write_transaction<T, E>(&self, write: impl FnOnce() -> Result<T, E>) -> Result<T, E>
    where
        E: From<StorageError>,
    {
        let transaction = self.connection.unchecked_transaction().map_err(StorageError::from)?;
        let value = write()?;
        transaction.commit().map_err(StorageError::from)?;
        Ok(value)
    }
}
