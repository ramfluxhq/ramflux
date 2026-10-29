// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Write-time ownership of per-message copies; deletion visits indexed locators only.
mod erasure;
mod schema;

use super::AccountDb;
use crate::StorageError;
use rusqlite::params;

pub(super) fn install(db: &rusqlite::Connection) -> rusqlite::Result<()> {
    schema::install(db)
}

impl AccountDb {
    /// Reads live actor copies reached by an erasure alias; this grants no admission authority.
    ///
    /// # Errors
    /// Returns SQLite or stored-state deserialization errors.
    pub fn message_copy_actor_states<T: serde::de::DeserializeOwned>(
        &self,
        copy: &str,
        prefix: &str,
    ) -> Result<Vec<T>, StorageError> {
        let mut query = self.connection.prepare(
            "SELECT a.state_json FROM message_copy_binding b \
             JOIN message_footprint f ON f.message_id=b.message_id AND f.kind='actor' \
             JOIN runtime_actor_state a ON a.state_kind=f.locator \
             WHERE b.copy_id=?1 AND substr(a.state_kind,1,length(?2))=?2",
        )?;
        query
            .query_map(params![copy, prefix], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| Ok(serde_json::from_slice(&row?)?))
            .collect()
    }

    /// Persists an opaque message copy and its erasure locator atomically.
    ///
    /// # Errors
    /// Returns serialization or transaction errors.
    pub fn persist_message_actor_state(
        &self,
        message: &str,
        key: &str,
        value: &impl serde::Serialize,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            self.connection.execute(
                "DELETE FROM message_copy_binding WHERE copy_id=?1",
                params![format!("actor:{key}")],
            )?;
            self.connection.execute(
                "DELETE FROM message_footprint WHERE kind='actor' AND locator=?1",
                params![key],
            )?;
            self.connection.execute(
                "INSERT OR IGNORE INTO message_copy_binding VALUES(?1,?2)",
                params![format!("actor:{key}"), message],
            )?;
            self.connection.execute(
                "INSERT OR IGNORE INTO message_footprint VALUES(?1,'actor',?2)",
                params![message, key],
            )?;
            self.persist_actor_state(key, value)?;
            self.connection.execute(
                "UPDATE direct_message_projection SET deleted=1 WHERE deleted=1 AND message_id=?1",
                params![message],
            )?;
            Ok(())
        })
    }
}

impl AccountDb {
    /// Stores a conversation's latest commit pointer with its message's erasure footprint.
    /// # Errors
    /// Returns serialization or transaction errors.
    pub fn persist_message_watermark(
        &self,
        message: &str,
        conversation: &str,
        key: &str,
        value: &impl serde::Serialize,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            if self.message_is_deleted(message)? {
                return Ok(());
            }
            self.persist_message_actor_state(message, key, value)?;
            self.connection.execute(
                "DELETE FROM message_footprint WHERE kind='watermark' AND locator=?1",
                params![conversation],
            )?;
            self.connection.execute(
                "INSERT OR IGNORE INTO message_footprint VALUES(?1,'watermark',?2)",
                params![message, conversation],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
