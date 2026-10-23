// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable acknowledgement backing for the bounded in-memory hint cache.

use super::super::AccountDb;
use crate::StorageError;
use rusqlite::params;

impl AccountDb {
    /// # Errors
    /// Returns an error if the durable acknowledgement cannot be recorded.
    pub fn remember_gateway_ack(&self, envelope_id: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO runtime_ack(envelope_id) VALUES(?1)",
            params![envelope_id],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error if the durable acknowledgement cannot be checked.
    pub fn has_gateway_ack(&self, envelope_id: &str) -> Result<bool, StorageError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM runtime_ack WHERE envelope_id=?1)",
            params![envelope_id],
            |row| row.get(0),
        )?)
    }
}
