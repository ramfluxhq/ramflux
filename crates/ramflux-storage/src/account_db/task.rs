// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic task projection phases, including nesting within a received-message transaction.
use super::AccountDb;
use crate::StorageError;
impl AccountDb {
    /// Applies a synchronous task phase atomically, without network I/O.
    /// # Errors
    /// Rolls back the entire phase on callback or database failure.
    pub fn task_transaction<T, E>(&self, apply: impl FnOnce() -> Result<T, E>) -> Result<T, E>
    where
        E: From<StorageError>,
    {
        self.connection.execute_batch("SAVEPOINT task_projection").map_err(StorageError::from)?;
        match apply() {
            Ok(result) => {
                if let Err(error) = self.connection.execute_batch("RELEASE task_projection") {
                    let _ = self
                        .connection
                        .execute_batch("ROLLBACK TO task_projection; RELEASE task_projection");
                    return Err(StorageError::from(error).into());
                }
                Ok(result)
            }
            Err(error) => {
                self.connection
                    .execute_batch("ROLLBACK TO task_projection; RELEASE task_projection")
                    .map_err(StorageError::from)?;
                Err(error)
            }
        }
    }
}
