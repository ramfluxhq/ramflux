// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Copy B-local pairing rows onto an installed export file.
//! The rows come from B's open account, never from the export snapshot.
//! Empty canonical tables are the product schema; this module inserts no stand-in rows.

use crate::account_db::pairing::schema::TABLES;
use crate::{AccountDbKey, StorageError};
use rusqlite::params_from_iter;
use rusqlite::types::Value;
use std::path::Path;

const ROW_CAP: usize = 1024;
const BYTE_CAP: usize = 8 * 1024 * 1024;

struct TableDump {
    name: &'static str,
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
}

fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
fn head_changed() -> StorageError {
    StorageError::PairingField("HeadChanged")
}

/// Install the pairing schema on `scratch` and copy the rows B already has.
/// `pairing_live` must already hold a row. Nothing is written to `scratch` until that is true.
/// # Errors
/// `HeadChanged` when `pairing_live` is missing or empty; `NoSpace` over 1024 rows in one
/// table or 8 MiB of cell bytes; `ManifestMismatch` for a real cell, an unsafe name, or a
/// foreign-key violation. Those caps are local.
pub(super) fn carry_local_pairing(
    source: &crate::database::Connection,
    scratch: &Path,
    key: &AccountDbKey,
) -> Result<(), StorageError> {
    let dumps = dump_local(source)?;
    write_carried(scratch, key, &dumps)?;
    super::stage::sync_regular(scratch)
}

/// Pairing rows read from a pinned private copy before that file is replaced.
pub(super) struct CopiedPairing {
    dumps: Vec<TableDump>,
}

/// Read pairing rows from an already keyed private copy.
/// # Errors
/// `HeadChanged` when `pairing_live` is missing or empty; `NoSpace` over the local caps;
/// SQL and cipher errors.
pub(super) fn read_copied_pairing(
    source: &Path,
    key: &AccountDbKey,
) -> Result<CopiedPairing, StorageError> {
    let db = open_keyed(source, key)?;
    Ok(CopiedPairing { dumps: read_dumps(&db)? })
}

/// Write pairing rows previously read from B's copy onto the installed export.
/// # Errors
/// `ManifestMismatch` for a real cell, an unsafe name, or a foreign-key violation;
/// SQL and cipher errors.
pub(super) fn write_copied_pairing(
    dest: &Path,
    key: &AccountDbKey,
    copied: &CopiedPairing,
) -> Result<(), StorageError> {
    write_carried(dest, key, &copied.dumps)?;
    super::stage::sync_regular(dest)
}

fn dump_local(source: &crate::database::Connection) -> Result<Vec<TableDump>, StorageError> {
    source.call(|db| Ok(read_dumps(db)))?
}

fn read_dumps(db: &rusqlite::Connection) -> Result<Vec<TableDump>, StorageError> {
    let mut budget = 0_usize;
    let mut dumps = Vec::new();
    for name in TABLES {
        if let Some(table) = read_table(db, name, &mut budget)? {
            dumps.push(table);
        }
    }
    let live = dumps.iter().find(|table| table.name == "pairing_live");
    if live.is_some_and(|table| !table.rows.is_empty()) { Ok(dumps) } else { Err(head_changed()) }
}

fn read_table(
    db: &rusqlite::Connection,
    name: &'static str,
    budget: &mut usize,
) -> Result<Option<TableDump>, StorageError> {
    identifier(name)?;
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [name],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let columns = column_names(db, name)?;
    let listed = columns.iter().map(|column| format!("\"{column}\"")).collect::<Vec<_>>().join(",");
    let mut statement = db.prepare(&format!("SELECT {listed} FROM \"{name}\""))?;
    let mut query = statement.query([])?;
    let mut rows = Vec::new();
    while let Some(row) = query.next()? {
        if rows.len() == ROW_CAP {
            return Err(StorageError::PairingField("NoSpace"));
        }
        let mut cells = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            let value: Value = row.get(index)?;
            *budget = budget.saturating_add(cell_len(&value)?);
            if *budget > BYTE_CAP {
                return Err(StorageError::PairingField("NoSpace"));
            }
            cells.push(value);
        }
        rows.push(cells);
    }
    Ok(Some(TableDump { name, columns, rows }))
}

fn column_names(db: &rusqlite::Connection, name: &str) -> Result<Vec<String>, StorageError> {
    let mut info = db.prepare(&format!("PRAGMA table_info(\"{name}\")"))?;
    let mut rows = info.query([])?;
    let mut columns = Vec::new();
    while let Some(row) = rows.next()? {
        let column: String = row.get(1)?;
        identifier(&column)?;
        if columns.iter().any(|seen| seen == &column) {
            return Err(mismatch());
        }
        columns.push(column);
    }
    if columns.is_empty() { Err(mismatch()) } else { Ok(columns) }
}

fn write_carried(path: &Path, key: &AccountDbKey, dumps: &[TableDump]) -> Result<(), StorageError> {
    let mut db = open_keyed(path, key)?;
    crate::account_db::pairing::install(&db)?;
    db.execute_batch("PRAGMA foreign_keys=OFF;")?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    for dump in dumps {
        insert_dump(&tx, dump)?;
    }
    for name in TABLES {
        if fk_violations(&tx, name)? != 0 {
            return Err(mismatch());
        }
    }
    tx.commit()?;
    drop(db);
    for suffix in ["db-journal", "db-wal", "db-shm"] {
        let _ = std::fs::remove_file(path.with_extension(suffix));
    }
    Ok(())
}

fn insert_dump(tx: &rusqlite::Transaction<'_>, dump: &TableDump) -> Result<(), StorageError> {
    identifier(dump.name)?;
    tx.execute(&format!("DELETE FROM \"{}\"", dump.name), [])?;
    if dump.rows.is_empty() {
        return Ok(());
    }
    let columns =
        dump.columns.iter().map(|column| format!("\"{column}\"")).collect::<Vec<_>>().join(",");
    let marks =
        (1..=dump.columns.len()).map(|index| format!("?{index}")).collect::<Vec<_>>().join(",");
    let sql = format!("INSERT INTO \"{}\" ({columns}) VALUES ({marks})", dump.name);
    for row in &dump.rows {
        if row.len() != dump.columns.len() {
            return Err(mismatch());
        }
        tx.execute(&sql, params_from_iter(row.iter()))?;
    }
    Ok(())
}

fn fk_violations(tx: &rusqlite::Transaction<'_>, name: &str) -> Result<i64, StorageError> {
    identifier(name)?;
    let sql = format!("SELECT count(*) FROM pragma_foreign_key_check('{name}')");
    Ok(tx.query_row(&sql, [], |row| row.get(0))?)
}

pub(super) fn open_keyed(
    path: &Path,
    key: &AccountDbKey,
) -> Result<rusqlite::Connection, StorageError> {
    let db = rusqlite::Connection::open(path)?;
    let hex = zeroize::Zeroizing::new(key.sqlcipher_hex());
    let pragma = zeroize::Zeroizing::new(format!(
        "PRAGMA key=\"x'{}'\"; PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA cache_size=-2048; PRAGMA secure_delete=ON;",
        hex.as_str()
    ));
    db.execute_batch(pragma.as_str())?;
    Ok(db)
}

fn identifier(name: &str) -> Result<(), StorageError> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(mismatch());
    };
    let ok = name.len() <= 64
        && first.is_ascii_alphabetic()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if ok { Ok(()) } else { Err(mismatch()) }
}

fn cell_len(value: &Value) -> Result<usize, StorageError> {
    match value {
        Value::Null => Ok(0),
        Value::Integer(_) => Ok(8),
        Value::Real(_) => Err(mismatch()),
        Value::Text(text) => Ok(text.len()),
        Value::Blob(blob) => Ok(blob.len()),
    }
}
