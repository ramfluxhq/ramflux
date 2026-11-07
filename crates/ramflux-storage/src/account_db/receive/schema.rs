// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant ledger storage. Installation does not activate a receive executor.
use crate::{AccountDb, StorageError};
use rusqlite::{OptionalExtension, params};

pub(crate) const VERSION: i64 = 15;
const CHECKSUM: &str = "2026-11-06-receive-ledger-v1";

pub(crate) const SCHEMA: &str = r"
CREATE TABLE gateway_receive_receipt (
 target_delivery_id TEXT NOT NULL, incarnation_id TEXT NOT NULL,
 inbox_seq BLOB NOT NULL CHECK(typeof(inbox_seq)='blob' AND length(inbox_seq)=8 AND inbox_seq>x'0000000000000000'),
 disposition TEXT NOT NULL CHECK(disposition IN ('staged','held','quarantined','completed','rejected','erased')),
 retain_until INTEGER NOT NULL, first_seen INTEGER NOT NULL,
 PRIMARY KEY(target_delivery_id,incarnation_id,inbox_seq)
) WITHOUT ROWID;
CREATE TABLE gateway_receive_work (
 target_delivery_id TEXT NOT NULL, incarnation_id TEXT NOT NULL,
 inbox_seq BLOB NOT NULL CHECK(typeof(inbox_seq)='blob' AND length(inbox_seq)=8 AND inbox_seq>x'0000000000000000'),
 entry_json BLOB NOT NULL, admission_key TEXT NOT NULL, byte_len INTEGER NOT NULL CHECK(byte_len>=0 AND byte_len=length(entry_json)),
 PRIMARY KEY(target_delivery_id,incarnation_id,inbox_seq),
 FOREIGN KEY(target_delivery_id,incarnation_id,inbox_seq) REFERENCES gateway_receive_receipt(target_delivery_id,incarnation_id,inbox_seq)
) WITHOUT ROWID;
CREATE TABLE gateway_ack_intent (
 target_delivery_id TEXT NOT NULL, incarnation_id TEXT NOT NULL,
 inbox_seq BLOB NOT NULL CHECK(typeof(inbox_seq)='blob' AND length(inbox_seq)=8 AND inbox_seq>x'0000000000000000'),
 created_at INTEGER NOT NULL, attempts INTEGER NOT NULL CHECK(attempts>=0), next_attempt_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 PRIMARY KEY(target_delivery_id,incarnation_id,inbox_seq)
) WITHOUT ROWID;
CREATE INDEX gateway_ack_intent_due ON gateway_ack_intent(target_delivery_id,incarnation_id,next_attempt_at,inbox_seq);
CREATE TABLE gateway_inbox_loss (
 target_delivery_id TEXT NOT NULL, incarnation_id TEXT NOT NULL,
 from_seq BLOB NOT NULL CHECK(typeof(from_seq)='blob' AND length(from_seq)=8 AND from_seq>x'0000000000000000'),
 to_seq BLOB NOT NULL CHECK(typeof(to_seq)='blob' AND length(to_seq)=8 AND to_seq>=from_seq),
 count BLOB NOT NULL CHECK(typeof(count)='blob' AND length(count)=8 AND count>x'0000000000000000'),
 reason TEXT NOT NULL, recorded_at INTEGER NOT NULL, classification TEXT NOT NULL,
 PRIMARY KEY(target_delivery_id,incarnation_id,from_seq,to_seq)
) WITHOUT ROWID;
CREATE TABLE gateway_receive_epoch (
 target_delivery_id TEXT PRIMARY KEY NOT NULL, incarnation_id TEXT NOT NULL,
 incarnation_verified INTEGER NOT NULL CHECK(incarnation_verified IN (0,1)), retired_incarnations BLOB NOT NULL,
 activated_cursor BLOB NOT NULL CHECK(typeof(activated_cursor)='blob' AND length(activated_cursor)=8),
 legacy_uncertain_through BLOB NOT NULL CHECK(typeof(legacy_uncertain_through)='blob' AND length(legacy_uncertain_through)=8)
) WITHOUT ROWID;
";

impl AccountDb {
    /// Installs the forward-only ledger schema without activating any receive path.
    ///
    /// # Errors
    /// Returns migration checksum or SQLite errors. The schema and writer floor commit together.
    pub fn install_receive_ledger_schema(&self) -> Result<(), StorageError> {
        self.write_transaction(|| {
            let existing: Option<String> = self.connection.query_row(
                "SELECT checksum FROM schema_migration WHERE schema_version=?1", params![VERSION],
                |r| r.get(0),
            ).optional()?;
            if let Some(actual) = existing {
                if actual != CHECKSUM {
                    return Err(StorageError::MigrationChecksumMismatch {
                        schema_version: VERSION, expected: CHECKSUM.into(), actual,
                    });
                }
                return Ok(());
            }
            self.connection.execute_batch(SCHEMA)?;
            self.connection.execute(
                "INSERT INTO schema_migration VALUES(?1,?2,'receive-ledger',?3,'dormant receive ledger writer floor')",
                params![VERSION, crate::unix_now(), CHECKSUM],
            )?;
            // The footprint triggers for the new table install in the same transaction.
            self.connection.call(|db| super::super::message_footprint::install(db))?;
            Ok(())
        })
    }
}

/// Read-only admission precedes migrations, including opens by private restore workers.
pub(crate) fn validate(db: &rusqlite::Connection, newest: i64) -> Result<(), StorageError> {
    if newest < VERSION {
        return Ok(());
    }
    let actual: String = db.query_row(
        "SELECT checksum FROM schema_migration WHERE schema_version=?1",
        params![VERSION],
        |r| r.get(0),
    )?;
    if actual != CHECKSUM {
        return Err(StorageError::MigrationChecksumMismatch {
            schema_version: VERSION,
            expected: CHECKSUM.into(),
            actual,
        });
    }
    Ok(())
}
