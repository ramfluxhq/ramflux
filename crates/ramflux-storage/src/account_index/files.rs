// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Close and reopen the shared account-index descriptor. The index is not encrypted.

use super::AccountIndex;
use crate::StorageError;

const REOPEN_SQL: &str = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;";

impl AccountIndex {
    /// Checkpoint and close the index descriptor. Call this only after every
    /// account actor has stopped using the shared connection.
    ///
    /// # Errors
    /// Returns an error when the checkpoint or the descriptor close fails.
    pub fn release_files(&self) -> Result<(), StorageError> {
        self.connection.release_sqlite()?;
        Ok(())
    }

    /// Reopen the index descriptor and restore the WAL pragmas. No key is applied.
    ///
    /// # Errors
    /// Returns an error when the descriptor cannot be reopened.
    pub fn reopen_files(&self) -> Result<(), StorageError> {
        self.connection.reopen_sqlite(Some(zeroize::Zeroizing::new(REOPEN_SQL.to_owned())))?;
        Ok(())
    }
}
