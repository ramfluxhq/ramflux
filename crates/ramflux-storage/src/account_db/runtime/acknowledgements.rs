// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable ACKs identify an authenticated receiver and a node-assigned mailbox position.

use super::super::AccountDb;
use crate::StorageError;
use ramflux_crypto::RootQualifiedDeviceRef;
use rusqlite::params;

impl AccountDb {
    /// # Errors
    /// Returns an error if the durable acknowledgement cannot be recorded.
    pub fn remember_gateway_ack(
        &self,
        receiver: &RootQualifiedDeviceRef,
        target: &str,
        inbox_seq: u64,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO runtime_scoped_ack(receiver,target,inbox_seq) VALUES(?1,?2,?3)",
            params![receiver.storage_key(), target, inbox_seq],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error if the durable acknowledgement cannot be checked.
    pub fn has_gateway_ack(
        &self,
        receiver: &RootQualifiedDeviceRef,
        target: &str,
        inbox_seq: u64,
    ) -> Result<bool, StorageError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM runtime_scoped_ack WHERE receiver=?1 AND target=?2 AND inbox_seq=?3)",
            params![receiver.storage_key(), target, inbox_seq],
            |row| row.get(0),
        )?)
    }
}
