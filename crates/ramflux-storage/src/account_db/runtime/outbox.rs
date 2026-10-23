// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded unpublished pages and durable router acceptance markers.

use super::super::AccountDb;
use super::AccountOutboxEntry;
use crate::StorageError;
use rusqlite::params;

impl AccountDb {
    /// # Errors
    /// Returns an error if the bounded unpublished outbox page cannot be read.
    pub fn pending_outbox(&self, limit: u32) -> Result<Vec<AccountOutboxEntry>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence,table_name,change_kind,row_id,keys_json FROM runtime_outbox WHERE published=0 ORDER BY sequence LIMIT ?1"
        )?;
        Ok(statement
            .query_map(params![limit.min(256)], |row| {
                Ok(AccountOutboxEntry {
                    sequence: row.get(0)?,
                    table_name: row.get(1)?,
                    change_kind: row.get(2)?,
                    row_id: row.get(3)?,
                    keys: row
                        .get::<_, Option<String>>(4)?
                        .map(|value| serde_json::from_str(&value))
                        .transpose()
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                4,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?
                        .unwrap_or(serde_json::Value::Null),
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// # Errors
    /// Returns an error when an acknowledged outbox page cannot be marked published.
    pub fn mark_outbox_published(&self, sequence: i64) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE runtime_outbox SET published=1 WHERE published=0 AND sequence<=?1",
            params![sequence],
        )?;
        Ok(())
    }
}
