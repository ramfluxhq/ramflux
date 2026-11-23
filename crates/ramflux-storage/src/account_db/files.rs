// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Close and reopen this account database without dropping the in-memory key.

use super::AccountDb;
use crate::StorageError;

impl AccountDb {
    /// Checkpoint, close the writer descriptor, and drop its lock files.
    /// The unwrapped key and the account value stay in memory.
    ///
    /// # Errors
    /// Returns an error when the checkpoint or the descriptor close fails.
    /// The descriptor is still closed when the checkpoint fails.
    pub fn release_files(&self) -> Result<(), StorageError> {
        let writer = self.connection.release_sqlite();
        let authority = self
            .erasure_authority
            .as_ref()
            .map_or(Ok(()), crate::database::Connection::release_sqlite);
        writer.and(authority).map_err(StorageError::from)
    }

    /// Reopen the writer and apply the key already held in memory.
    /// A database that was not released is left untouched.
    ///
    /// # Errors
    /// Returns an error when the lock, the descriptor, or the key pragma fails.
    /// A failed reopen stays released.
    pub fn reopen_files(&self) -> Result<(), StorageError> {
        self.reopen_connection(&self.connection)?;
        if let Some(authority) = &self.erasure_authority {
            self.reopen_connection(authority)?;
        }
        Ok(())
    }

    fn reopen_connection(
        &self,
        connection: &crate::database::Connection,
    ) -> Result<(), StorageError> {
        let mut sql = crate::encryption::key_pragma_sql(&self.current_key);
        sql.push_str(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA secure_delete=ON;",
        );
        connection.reopen_sqlite(Some(sql))?;
        Ok(())
    }
}
