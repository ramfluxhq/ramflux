// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local B-to-B row differences. This never accepts a peer database or wire schema.
use crate::{AccountDbKey, StorageError};
use rusqlite::{Connection, config::DbConfig, params};
use std::{
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn bounded(error: rusqlite::Error) -> StorageError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted) {
        StorageError::PairingField("Busy")
    } else {
        error.into()
    }
}

pub(super) fn attach(
    target: &Connection,
    source: &Path,
    key: &AccountDbKey,
) -> Result<(), StorageError> {
    drop(super::super::stage::open_regular(source, false)?);
    let hex = Zeroizing::new(key.sqlcipher_hex());
    let encoded = Zeroizing::new(format!("x'{}'", hex.as_str()));
    target.execute(
        "ATTACH DATABASE ?1 AS current_b KEY ?2",
        params![source.to_str().ok_or_else(super::wrong)?, encoded.as_str()],
    )?;
    target.execute_batch(
        "PRAGMA current_b.cache_size=-2048; PRAGMA cache_size=-2048; PRAGMA temp_store=FILE;",
    )?;
    target.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    target.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, false)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    target.progress_handler(1000, Some(move || Instant::now() >= deadline));
    Ok(())
}

pub(super) fn table(target: &Connection, table: &'static str) -> Result<(), StorageError> {
    crate::database::require_generation_rebase_deadline()?;
    // Names and column bounds have already been checked against the compiled census.
    let mut statement = target.prepare(&format!("SELECT CASE WHEN length(CAST(name AS BLOB))<=128 THEN name END FROM pragma_table_xinfo('{table}') WHERE hidden=0 LIMIT 257"))?;
    let mut columns = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if columns.is_empty()
        || columns.len() > 256
        || columns.iter().any(|name| {
            name.len() > 128 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    {
        return Err(super::wrong());
    }
    let without_rowid:bool=target.query_row("SELECT instr(upper(sql),'WITHOUT ROWID')>0 FROM main.sqlite_schema WHERE type='table' AND name=?1",params![table],|row|row.get(0))?;
    if !without_rowid {
        if columns.iter().any(|name| name.eq_ignore_ascii_case("_rowid_")) {
            return Err(super::wrong());
        }
        columns.insert(0, "_rowid_".into());
    }
    let names = columns.iter().map(|name| format!("\"{name}\"")).collect::<Vec<_>>().join(",");
    let equal = columns
        .iter()
        .map(|name| format!("old.\"{name}\" IS fresh.\"{name}\""))
        .collect::<Vec<_>>()
        .join(" AND ");
    target.execute(&format!("DELETE FROM main.\"{table}\" AS old WHERE NOT EXISTS(SELECT 1 FROM current_b.\"{table}\" AS fresh WHERE {equal})"), []).map_err(bounded)?;
    target.execute(&format!("INSERT INTO main.\"{table}\"({names}) SELECT {names} FROM current_b.\"{table}\" AS fresh WHERE NOT EXISTS(SELECT 1 FROM main.\"{table}\" AS old WHERE {equal})"), []).map_err(bounded)?;
    crate::database::require_generation_rebase_deadline()
}

pub(super) fn sequences(target: &Connection) -> Result<(), StorageError> {
    let exists:bool=target.query_row("SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name='sqlite_sequence') AND EXISTS(SELECT 1 FROM current_b.sqlite_schema WHERE name='sqlite_sequence')",[],|row|row.get(0))?;
    if exists {
        table(target, "sqlite_sequence")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
