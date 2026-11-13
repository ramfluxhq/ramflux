// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Backup classification: ceremony rows never restore; target floors are retained.

use super::schema::TABLES;
use crate::StorageError;
use rusqlite::{Connection, OptionalExtension, params};

const STRIP: [&str; 5] =
    ["pairing_live", "pairing_head", "pairing_terminal", "pairing_adoption", "pairing_full_tail"];

/// True when a pairing table must not be row-merged from an incoming backup.
#[must_use]
pub(crate) fn skip_merge(table: &str) -> bool {
    TABLES.contains(&table)
}

/// Strip live/head/terminal/adoption from a published backup. Floor stays.
///
/// # Errors
/// Returns SQLite errors.
pub(crate) fn sanitize_backup(db: &Connection) -> Result<(), StorageError> {
    for table in STRIP {
        if table_exists(db, table)? {
            db.execute(&format!("DELETE FROM {table}"), [])?;
        }
    }
    Ok(())
}

/// Merge incoming floor into local: copy when missing, take maxima, refuse a foreign anchor.
///
/// # Errors
/// Returns `PairingField("account_anchor")` or `PairingField("account_id")` on conflict.
pub(crate) fn merge_floor(db: &Connection) -> Result<(), StorageError> {
    merge_floor_for(db, local_pairing_account(db)?.as_deref())
}

/// Merge bound to an explicit local account id, including when the local floor is missing.
///
/// # Errors
/// Returns `PairingField("account_anchor")` or `PairingField("account_id")` on conflict.
pub(crate) fn merge_floor_for(
    db: &Connection,
    local_account_id: Option<&str>,
) -> Result<(), StorageError> {
    if !incoming_floor_exists(db)? {
        return Ok(());
    }
    if !table_exists(db, "pairing_floor")? {
        return Ok(());
    }
    let incoming: (String, String, i64, i64) = db.query_row(
        "SELECT account_id,account_anchor,issued_seq,next_generation FROM incoming.pairing_floor LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if let Some(local_id) = local_account_id
        && incoming.0 != local_id
    {
        return Err(StorageError::PairingField("account_id"));
    }
    let local: Option<(String, String, i64, i64)> = db
        .query_row(
            "SELECT account_id,account_anchor,issued_seq,next_generation FROM pairing_floor WHERE account_id=?1",
            params![incoming.0],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    match local {
        None => {
            let other: i64 =
                db.query_row("SELECT count(*) FROM pairing_floor", [], |row| row.get(0))?;
            if other > 0 {
                return Err(StorageError::PairingField("account_id"));
            }
            db.execute(
                "INSERT INTO pairing_floor(account_id,account_anchor,issued_seq,next_generation)
                 VALUES(?1,?2,?3,?4)",
                params![incoming.0, incoming.1, incoming.2, incoming.3],
            )?;
        }
        Some(local) => {
            if local.0 != incoming.0 {
                return Err(StorageError::PairingField("account_id"));
            }
            if local.1 != incoming.1 {
                return Err(StorageError::PairingField("account_anchor"));
            }
            let issued = local.2.max(incoming.2);
            let generation = local.3.max(incoming.3);
            db.execute(
                "UPDATE pairing_floor SET issued_seq=?1,next_generation=?2 WHERE account_id=?3",
                params![issued, generation, local.0],
            )?;
        }
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

fn local_pairing_account(db: &Connection) -> Result<Option<String>, StorageError> {
    for table in TABLES {
        if !table_exists(db, table)? {
            continue;
        }
        let id: Option<String> = db
            .query_row(&format!("SELECT account_id FROM {table} LIMIT 1"), [], |row| row.get(0))
            .optional()?;
        if let Some(id) = id {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

fn incoming_floor_exists(db: &Connection) -> rusqlite::Result<bool> {
    let attached: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_database_list WHERE name='incoming')",
        [],
        |row| row.get(0),
    )?;
    if !attached {
        return Ok(false);
    }
    let present: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE type='table' AND name='pairing_floor')",
        [],
        |row| row.get(0),
    )?;
    if !present {
        return Ok(false);
    }
    db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.pairing_floor)", [], |row| row.get(0))
}
