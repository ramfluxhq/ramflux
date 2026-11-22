// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keyed row digest of one exported row (audit A6). The input is the table name and the
//! typed, length-prefixed encoding of the exported columns, in list order. The caller
//! retains only the table name, the primary-key encoding and the digest.
use super::contract::Table;
use super::tables::EXPORT_TABLES;
use crate::StorageError;
use rusqlite::types::ValueRef;

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
