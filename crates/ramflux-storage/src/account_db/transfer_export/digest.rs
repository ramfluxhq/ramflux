// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keyed row digest of one exported row (audit A6). The input is the table name and the
//! typed, length-prefixed encoding of the exported columns, in list order. The caller
//! retains only the table name, the primary-key encoding and the digest.
use super::contract::{Class, Column, Table};
use super::tables::EXPORT_TABLES;
use crate::StorageError;
use rusqlite::types::{Value, ValueRef};

/// Encoded primary keys retained for one cut stay under this byte budget.
const KEY_BUDGET: usize = 32 * 1024 * 1024;
/// One primary-key encoding. Longer keys refuse rather than being truncated.
const KEY_LIMIT: usize = 2048;
const ROW_LIMIT: usize = 1_048_576;
const ROW_DOMAIN: &[u8] = b"ramflux.transfer.retained.row.v1";

/// One retained row: no column bodies.
pub(in crate::account_db) struct RowDigest {
    pub(in crate::account_db) table: &'static str,
    pub(in crate::account_db) key: Vec<u8>,
    pub(in crate::account_db) digest: [u8; 32],
}

/// Keyed BLAKE3 of every exported row. `mac` is the stage's digest key.
/// # Errors
/// `PairingField("NoSpace")` when the key budget or the row cap is exceeded;
/// `TransferExportRefused("storage_class")` for a non-integer/text/blob cell.
pub(in crate::account_db) fn rows(
    db: &rusqlite::Connection,
    mac: &[u8; 32],
) -> Result<Vec<RowDigest>, StorageError> {
    let mut out = Vec::new();
    let mut key_bytes = 0_usize;
    for table in EXPORT_TABLES {
        append_table(db, mac, table, &mut out, &mut key_bytes)?;
    }
    Ok(out)
}

fn append_table(
    db: &rusqlite::Connection,
    mac: &[u8; 32],
    table: &Table,
    out: &mut Vec<RowDigest>,
    key_bytes: &mut usize,
) -> Result<(), StorageError> {
    let columns = table
        .columns
        .iter()
        .map(|column| format!("\"{}\"", column.name))
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = db.prepare(&format!("SELECT {columns} FROM \"{}\"", table.name))?;
    let mut query = statement.query([])?;
    while let Some(row) = query.next()? {
        if out.len() == ROW_LIMIT {
            return Err(StorageError::PairingField("NoSpace"));
        }
        let key = primary_key(table, row)?;
        *key_bytes = key_bytes.saturating_add(key.len());
        if *key_bytes > KEY_BUDGET {
            return Err(StorageError::PairingField("NoSpace"));
        }
        out.push(RowDigest { table: table.name, digest: row_digest(mac, table, row)?, key });
    }
    Ok(())
}

fn row_digest(
    mac: &[u8; 32],
    table: &Table,
    row: &rusqlite::Row<'_>,
) -> Result<[u8; 32], StorageError> {
    let mut hasher = blake3::Hasher::new_keyed(mac);
    feed(&mut hasher, ROW_DOMAIN);
    feed(&mut hasher, table.name.as_bytes());
    for (index, _) in table.columns.iter().enumerate() {
        feed_cell(&mut hasher, row.get_ref(index)?)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

fn primary_key(table: &Table, row: &rusqlite::Row<'_>) -> Result<Vec<u8>, StorageError> {
    let mut key = Vec::new();
    for name in table.key {
        let index = table
            .columns
            .iter()
            .position(|column| column.name == *name)
            .ok_or(StorageError::TransferExportRefused("schema"))?;
        feed_cell_buf(&mut key, row.get_ref(index)?)?;
    }
    if key.len() > KEY_LIMIT {
        return Err(StorageError::PairingField("NoSpace"));
    }
    Ok(key)
}

fn feed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn feed_cell(hasher: &mut blake3::Hasher, value: ValueRef<'_>) -> Result<(), StorageError> {
    match value {
        ValueRef::Null => {
            hasher.update(&[0]);
            hasher.update(&0_u64.to_be_bytes());
        }
        ValueRef::Integer(number) => {
            hasher.update(&[1]);
            let bytes = number.to_be_bytes();
            hasher.update(&(bytes.len() as u64).to_be_bytes());
            hasher.update(&bytes);
        }
        ValueRef::Text(bytes) => {
            hasher.update(&[2]);
            feed(hasher, bytes);
        }
        ValueRef::Blob(bytes) => {
            hasher.update(&[3]);
            feed(hasher, bytes);
        }
        ValueRef::Real(_) => return Err(StorageError::TransferExportRefused("storage_class")),
    }
    Ok(())
}

fn feed_cell_buf(out: &mut Vec<u8>, value: ValueRef<'_>) -> Result<(), StorageError> {
    match value {
        ValueRef::Null => {
            out.push(0);
            out.extend_from_slice(&0_u64.to_be_bytes());
        }
        ValueRef::Integer(number) => {
            out.push(1);
            let bytes = number.to_be_bytes();
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
            let tag = if matches!(value, ValueRef::Text(_)) { 2 } else { 3 };
            let next = out.len().saturating_add(1).saturating_add(8).saturating_add(bytes.len());
            if next > KEY_LIMIT {
                return Err(StorageError::PairingField("NoSpace"));
            }
            out.push(tag);
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        ValueRef::Real(_) => return Err(StorageError::TransferExportRefused("storage_class")),
    }
    Ok(())
}

/// One exported primary key, without the row body.
pub(in crate::account_db) struct PrimaryKey {
    pub(in crate::account_db) table: &'static str,
    pub(in crate::account_db) key: Vec<u8>,
}

/// One exported row the tail may insert. `values` follows the declared column order.
pub(in crate::account_db) struct ExportedRow {
    pub(in crate::account_db) table: &'static str,
    pub(in crate::account_db) key: Vec<u8>,
    pub(in crate::account_db) digest: [u8; 32],
    pub(in crate::account_db) values: Vec<Value>,
}

/// SQL for one declared table. Identifiers come only from the export list.
pub(in crate::account_db) struct RowSql {
    pub(in crate::account_db) insert: String,
    pub(in crate::account_db) delete_sql: String,
    pub(in crate::account_db) exists_sql: String,
}

/// Primary keys of every exported row. Same caps as [`rows`].
/// # Errors
/// `PairingField("NoSpace")` over the row cap or the key budget;
/// `TransferExportRefused("storage_class")` for a real cell.
pub(in crate::account_db) fn primary_keys(
    db: &rusqlite::Connection,
) -> Result<Vec<PrimaryKey>, StorageError> {
    let mut out = Vec::new();
    let mut key_bytes = 0_usize;
    for table in EXPORT_TABLES {
        append_keys(db, table, &mut out, &mut key_bytes)?;
    }
    Ok(out)
}

/// Keyed digests plus the declared cell values. The tail uses this to insert A's row.
/// # Errors
/// The same refusals as [`rows`].
pub(in crate::account_db) fn rows_with_values(
    db: &rusqlite::Connection,
    mac: &[u8; 32],
) -> Result<Vec<ExportedRow>, StorageError> {
    let mut out = Vec::new();
    let mut key_bytes = 0_usize;
    for table in EXPORT_TABLES {
        append_values(db, mac, table, &mut out, &mut key_bytes)?;
    }
    Ok(out)
}

/// Decode a primary-key encoding into the declared key cells.
/// # Errors
/// `PairingField("ManifestMismatch")` when the bytes are not that table's key.
pub(in crate::account_db) fn key_values(
    table: &str,
    key: &[u8],
) -> Result<Vec<Value>, StorageError> {
    let table = declared(table)?;
    let mut rest = key;
    let mut values = Vec::with_capacity(table.key.len());
    for name in table.key {
        let column = table
            .columns
            .iter()
            .find(|column| column.name == *name)
            .ok_or(StorageError::TransferExportRefused("schema"))?;
        let (value, next) = take_cell(column, rest)?;
        rest = next;
        values.push(value);
    }
    if rest.is_empty() { Ok(values) } else { Err(StorageError::PairingField("ManifestMismatch")) }
}

/// Insert, delete and existence SQL for one declared table.
/// # Errors
/// `PairingField("ManifestMismatch")` when `table` is not an exported name.
pub(in crate::account_db) fn row_sql(table: &str) -> Result<RowSql, StorageError> {
    let table = declared(table)?;
    let columns = table
        .columns
        .iter()
        .map(|column| format!("\"{}\"", column.name))
        .collect::<Vec<_>>()
        .join(",");
    let slots =
        (1..=table.columns.len()).map(|index| format!("?{index}")).collect::<Vec<_>>().join(",");
    let key = table
        .key
        .iter()
        .enumerate()
        .map(|(index, name)| format!("\"{name}\" IS ?{}", index + 1))
        .collect::<Vec<_>>()
        .join(" AND ");
    Ok(RowSql {
        insert: format!("INSERT INTO \"{}\" ({columns}) VALUES ({slots})", table.name),
        delete_sql: format!("DELETE FROM \"{}\" WHERE {key}", table.name),
        exists_sql: format!("SELECT EXISTS(SELECT 1 FROM \"{}\" WHERE {key})", table.name),
    })
}

fn declared(name: &str) -> Result<&'static Table, StorageError> {
    EXPORT_TABLES
        .iter()
        .find(|table| table.name == name)
        .ok_or(StorageError::PairingField("ManifestMismatch"))
}

fn append_keys(
    db: &rusqlite::Connection,
    table: &Table,
    out: &mut Vec<PrimaryKey>,
    key_bytes: &mut usize,
) -> Result<(), StorageError> {
    let mut statement = db.prepare(&format!("SELECT {} FROM \"{}\"", listed(table), table.name))?;
    let mut query = statement.query([])?;
    while let Some(row) = query.next()? {
        if out.len() == ROW_LIMIT {
            return Err(StorageError::PairingField("NoSpace"));
        }
        let key = primary_key(table, row)?;
        charge(key_bytes, &key)?;
        out.push(PrimaryKey { table: table.name, key });
    }
    Ok(())
}

fn append_values(
    db: &rusqlite::Connection,
    mac: &[u8; 32],
    table: &Table,
    out: &mut Vec<ExportedRow>,
    key_bytes: &mut usize,
) -> Result<(), StorageError> {
    let mut statement = db.prepare(&format!("SELECT {} FROM \"{}\"", listed(table), table.name))?;
    let mut query = statement.query([])?;
    while let Some(row) = query.next()? {
        if out.len() == ROW_LIMIT {
            return Err(StorageError::PairingField("NoSpace"));
        }
        let key = primary_key(table, row)?;
        charge(key_bytes, &key)?;
        let digest = row_digest(mac, table, row)?;
        let mut values = Vec::with_capacity(table.columns.len());
        for index in 0..table.columns.len() {
            values.push(row.get(index)?);
        }
        out.push(ExportedRow { table: table.name, key, digest, values });
    }
    Ok(())
}

fn listed(table: &Table) -> String {
    table.columns.iter().map(|column| format!("\"{}\"", column.name)).collect::<Vec<_>>().join(",")
}

fn charge(key_bytes: &mut usize, key: &[u8]) -> Result<(), StorageError> {
    *key_bytes = key_bytes.saturating_add(key.len());
    if *key_bytes > KEY_BUDGET { Err(StorageError::PairingField("NoSpace")) } else { Ok(()) }
}

fn cell_mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}

fn take_cell<'a>(column: &Column, bytes: &'a [u8]) -> Result<(Value, &'a [u8]), StorageError> {
    let tag = *bytes.first().ok_or_else(cell_mismatch)?;
    let len_bytes: [u8; 8] =
        bytes.get(1..9).ok_or_else(cell_mismatch)?.try_into().map_err(|_| cell_mismatch())?;
    let len = usize::try_from(u64::from_be_bytes(len_bytes)).map_err(|_| cell_mismatch())?;
    let end = 9usize.checked_add(len).ok_or_else(cell_mismatch)?;
    let payload = bytes.get(9..end).ok_or_else(cell_mismatch)?;
    let value = match tag {
        0 if column.nullable && len == 0 => Value::Null,
        1 if column.cell.class() == Class::Integer && len == 8 => {
            let raw: [u8; 8] = payload.try_into().map_err(|_| cell_mismatch())?;
            Value::Integer(i64::from_be_bytes(raw))
        }
        2 if column.cell.class() == Class::Text => {
            Value::Text(std::str::from_utf8(payload).map_err(|_| cell_mismatch())?.to_owned())
        }
        3 if column.cell.class() == Class::Blob => Value::Blob(payload.to_vec()),
        _ => return Err(cell_mismatch()),
    };
    Ok((value, bytes.get(end..).ok_or_else(cell_mismatch)?))
}
