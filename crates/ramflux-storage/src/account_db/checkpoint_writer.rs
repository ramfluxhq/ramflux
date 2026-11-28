// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A weak writer for one projection checkpoint. It lets a component that runs off the account
//! thread (a gateway session) save its own small state at the moment it changes, without keeping
//! the unlocked account DB alive.
use crate::{AccountClock, AccountDb, StorageError, database::WeakConnection};
use rusqlite::params;

#[derive(Clone)]
pub struct ProjectionCheckpointWriter {
    projection_name: &'static str,
    clock: AccountClock,
    connection: WeakConnection,
}

impl std::fmt::Debug for ProjectionCheckpointWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectionCheckpointWriter")
            .field("projection_name", &self.projection_name)
            .finish_non_exhaustive()
    }
}

impl AccountDb {
    /// A writer bound to one checkpoint name of this unlocked DB worker. No key or connection is
    /// copied; writes fail once the account is locked or its generation is retired.
    #[must_use]
    pub fn projection_checkpoint_writer(
        &self,
        projection_name: &'static str,
    ) -> ProjectionCheckpointWriter {
        ProjectionCheckpointWriter {
            projection_name,
            clock: self.clock.clone(),
            connection: self.connection.downgrade(),
        }
    }
}

impl ProjectionCheckpointWriter {
    /// Upserts the checkpoint value, exactly as `ProjectionStore::set_projection_checkpoint`.
    ///
    /// # Errors
    /// Returns `AuthorizationRejected` when the account DB is locked or its generation retired,
    /// and the storage error when the write fails.
    pub fn write(&self, value: &str) -> Result<(), StorageError> {
        let connection =
            self.connection.upgrade_account_writer().ok_or(StorageError::AuthorizationRejected)?;
        connection.execute(
            "INSERT INTO projection_checkpoint (
                projection_name, projection_version, last_event_id, checkpoint_hash, updated_at
            ) VALUES (?1, 1, ?2, NULL, ?3)
             ON CONFLICT(projection_name)
             DO UPDATE SET last_event_id = excluded.last_event_id, updated_at = excluded.updated_at",
            params![self.projection_name, value, self.clock.now_unix()],
        )?;
        Ok(())
    }
}
