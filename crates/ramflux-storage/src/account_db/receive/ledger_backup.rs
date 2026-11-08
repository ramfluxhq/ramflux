// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Strip the receive ledger from a published backup, merged generation or restore copy.
//! Tombstones and `erased-input:` bindings stay; C/E and work do not.
use crate::StorageError;
use rusqlite::{Connection, params};

const LEDGER_TABLES: [&str; 5] = [
    "gateway_receive_work",
    "gateway_receive_receipt",
    "gateway_ack_intent",
    "gateway_inbox_loss",
    "gateway_receive_epoch",
];

/// Carries bound work tuples into `receive_erased_input`, then deletes ledger rows, receive-work
/// footprints and receive cursor/conflict checkpoints. Schema rows stay so a later installer is
/// checksum-idempotent.
///
/// # Errors
/// Returns storage, MAC or SQLite errors.
pub(crate) fn sanitize_backup(db: &Connection) -> rusqlite::Result<()> {
    super::erased_capture::carry_work_tombstones(db, crate::unix_now()).map_err(storage_sql)?;
    strip_receive_ledger(db)
}

fn storage_sql(error: StorageError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

fn strip_receive_ledger(db: &Connection) -> rusqlite::Result<()> {
    for table in LEDGER_TABLES {
        if table_exists(db, table)? {
            db.execute(&format!("DELETE FROM {table}"), [])?;
        }
    }
    if table_exists(db, "message_footprint")? {
        db.execute("DELETE FROM message_footprint WHERE kind='receive_work'", [])?;
    }
    if table_exists(db, "projection_checkpoint")? {
        db.execute(
            "DELETE FROM projection_checkpoint WHERE projection_name GLOB 'gateway_receive_*'",
            params![],
        )?;
    }
    Ok(())
}

fn table_exists(db: &Connection, table: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        params![table],
        |row| row.get(0),
    )
}

#[cfg(test)]
mod tests {
    use super::table_exists;
    use rusqlite::Connection;

    #[test]
    fn missing_ledger_tables_are_not_an_error() -> rusqlite::Result<()> {
        let db = Connection::open_in_memory()?;
        super::strip_receive_ledger(&db)?;
        assert!(!table_exists(&db, "gateway_receive_work")?);
        Ok(())
    }
}
