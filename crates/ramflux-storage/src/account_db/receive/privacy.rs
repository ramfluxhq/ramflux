// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Late binding of staged receive work to its logical message (W1), with deletion re-checked.
use super::ReceiveTransaction;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};

/// Outcome of binding staged work to a logical message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveBind {
    /// The payload now belongs to the message; deleting the message will erase the work.
    Bound,
    /// The message was already deleted: the work was erased instead of bound.
    Erased,
}

impl ReceiveTransaction<'_> {
    /// Binds the staged or held input at `sequence` to `message`, or erases it when that
    /// message is already deleted. Erasure marks the receipt before deleting the work and
    /// re-arms WAL retirement in the same transaction.
    ///
    /// # Errors
    /// Requires the writer transaction; refuses a missing or terminal receipt and missing work.
    pub fn bind_logical_message(
        &self,
        sequence: u64,
        message: &str,
    ) -> Result<ReceiveBind, StorageError> {
        self.require_writer()?;
        let connection = &self.db.connection;
        let seq = sequence.to_be_bytes();
        let key = params![self.target, self.incarnation, seq.as_slice()];
        let disposition: Option<String> = connection
            .query_row(
                "SELECT disposition FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
                key,
                |row| row.get(0),
            )
            .optional()?;
        if !matches!(disposition.as_deref(), Some("staged" | "held")) {
            return Err(StorageError::Integrity("receive bind requires a staged or held receipt"));
        }
        let (payload, entry): (String, Vec<u8>) = connection
            .query_row(
                "SELECT json_extract(CAST(entry_json AS TEXT),'$.envelope.payload_hash'),CAST(entry_json AS BLOB) FROM gateway_receive_work WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
                key,
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StorageError::Integrity("receive bind requires staged work"))?;
        if self.db.message_is_deleted(message)? {
            connection.execute(
                "UPDATE gateway_receive_receipt SET disposition='erased' WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
                key,
            )?;
            connection.execute(
                "DELETE FROM gateway_receive_work WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
                key,
            )?;
            // Same statement the erase body runs (FP/erasure.rs), so a settled WAL is re-armed.
            connection.execute(
                "INSERT INTO runtime_privacy_maintenance VALUES(1,1) ON CONFLICT(singleton) DO UPDATE SET erasure_pending=1",
                [],
            )?;
            return Ok(ReceiveBind::Erased);
        }
        connection.execute(
            "INSERT INTO message_copy_binding VALUES('payload:'||?1,?2) ON CONFLICT DO NOTHING",
            params![payload, message],
        )?;
        // Binding (i): keep the authenticated tuple until the message's deletion is captured.
        let message = message.to_owned();
        let now = crate::unix_now();
        connection.call(move |raw| {
            Ok(super::erased_capture::write_work_bindings(raw, &message, &entry, now))
        })??;
        Ok(ReceiveBind::Bound)
    }
}
