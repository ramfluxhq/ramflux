// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted control records and atomic multi-record state updates.

use super::super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};

impl AccountDb {
    /// Tests actor-state presence without decoding a private snapshot.
    /// # Errors
    /// Returns SQLite errors.
    pub fn actor_state_exists(&self, kind: &str) -> Result<bool, StorageError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=?1)",
            params![kind],
            |row| row.get(0),
        )?)
    }

    /// # Errors
    /// Returns an error when the account-owned control state cannot be committed.
    pub fn persist_actor_state<T: serde::Serialize>(
        &self,
        kind: &str,
        state: &T,
    ) -> Result<(), StorageError> {
        self.connection.execute("INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json WHERE state_json<>excluded.state_json", params![kind,serde_json::to_vec(state)?])?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when a control-state batch or its outbox rows cannot commit together.
    pub fn persist_actor_state_batch<T: serde::Serialize>(
        &self,
        states: &[(String, T)],
    ) -> Result<(), StorageError> {
        if states.is_empty() {
            return Ok(());
        }
        let transaction = self.connection.unchecked_transaction()?;
        for (kind, state) in states {
            self.persist_actor_state(kind, state)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the requested persisted control-state list cannot be decoded.
    pub fn list_actor_states<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
    ) -> Result<Vec<T>, StorageError> {
        let mut statement = self.connection.prepare("SELECT state_json FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 ORDER BY state_kind")?;
        statement
            .query_map(params![prefix], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| Ok(serde_json::from_slice(&row?)?))
            .collect()
    }

    /// # Errors
    /// Returns an error when the account-owned control state cannot be reconstructed.
    pub fn load_actor_state<T: serde::de::DeserializeOwned>(
        &self,
        kind: &str,
    ) -> Result<Option<T>, StorageError> {
        let body: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
                params![kind],
                |row| row.get(0),
            )
            .optional()?;
        body.map(|body| serde_json::from_slice(&body).map_err(StorageError::from)).transpose()
    }
}

impl AccountDb {
    /// Removes private actor state in the caller's transaction.
    /// # Errors
    /// Returns SQLite errors.
    pub fn remove_actor_state(&self, key: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM runtime_actor_state WHERE state_kind=?1",
            rusqlite::params![key],
        )?;
        Ok(())
    }
}
