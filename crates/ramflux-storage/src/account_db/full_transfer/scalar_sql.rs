// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Borrowed, field-declared SQL cells; no generic JSON/value tree or peer-sized scratch.
use super::{FamilyRule, FamilySelector, copy_full_scalar_record};
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{
    CellType, MAX_STABLE_KEY_BYTES, RecordHeader, RecordOp, U64, encode_stable_key,
    write_record_header,
};
use rusqlite::types::ValueRef;
use std::io::{Read, Write};
use zeroize::{Zeroize as _, Zeroizing};
fn unsupported() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
struct PrivateHeader(RecordHeader);
impl Drop for PrivateHeader {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}

enum Cell<'a> {
    Null,
    Integer([u8; 8]),
    Text(&'a [u8]),
    Bytes(&'a [u8]),
}
impl Cell<'_> {
    fn kind(&self) -> CellType {
        match self {
            Self::Null => CellType::Null,
            Self::Integer(_) => CellType::I64,
            Self::Text(_) => CellType::Utf8,
            Self::Bytes(_) => CellType::Bytes,
        }
    }
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Null => &[],
            Self::Integer(bytes) => bytes,
            Self::Text(bytes) | Self::Bytes(bytes) => bytes,
        }
    }
}
fn cells<'a>(rule: &FamilyRule, row: &'a rusqlite::Row<'_>) -> Result<Vec<Cell<'a>>, StorageError> {
    if rule.codec.iter().any(|field| {
        field.disposition
            == ramflux_protocol::custody::pairing::full_transfer::Disposition::Transfer
            && !super::catalog::scalar_sql_codec(&field.codec)
    }) {
        return Err(unsupported());
    }
    if !matches!(rule.selector, FamilySelector::Table(_))
        || rule.key.is_empty()
        || row.as_ref().column_count() != rule.cells.len()
    {
        return Err(unsupported());
    }
    let mut cells = Vec::with_capacity(rule.cells.len());
    for (index, declared) in rule.cells.iter().enumerate() {
        if row.as_ref().column_name(index)? != declared.name {
            return Err(StorageError::PairingField("SchemaMismatch"));
        }
        let cell = match row.get_ref(index)? {
            ValueRef::Null => Cell::Null,
            ValueRef::Integer(value) if declared.cell_type == CellType::I64 => {
                Cell::Integer(value.to_be_bytes())
            }
            ValueRef::Text(bytes) if declared.cell_type == CellType::Utf8 => Cell::Text(bytes),
            ValueRef::Blob(bytes) if declared.cell_type == CellType::Bytes => Cell::Bytes(bytes),
            _ => return Err(unsupported()),
        };
        cells.push(cell);
    }
    Ok(cells)
}
fn header(rule: &FamilyRule, cells: &[Cell<'_>]) -> Result<PrivateHeader, StorageError> {
    let mut key_columns = Vec::with_capacity(rule.key.len());
    let mut key_length = 0_usize;
    for name in rule.key {
        let index =
            rule.cells.iter().position(|cell| cell.name == *name).ok_or_else(unsupported)?;
        let value = cells.get(index).ok_or_else(unsupported)?;
        key_length = key_length
            .checked_add(5)
            .and_then(|size| size.checked_add(value.bytes().len()))
            .ok_or_else(unsupported)?;
        if key_length > MAX_STABLE_KEY_BYTES {
            return Err(unsupported());
        }
        key_columns.push((value.kind(), value.bytes()));
    }
    let key = encode_stable_key(key_columns).map_err(|_| unsupported())?;
    Ok(PrivateHeader(RecordHeader {
        family: rule.id.into(),
        codec_version: rule.codec_version,
        key: key.to_string(),
        op: RecordOp::Put,
        cell_types: cells.iter().map(Cell::kind).collect(),
        cell_lengths: cells.iter().map(|cell| U64(cell.bytes().len() as u64)).collect(),
    }))
}
struct CellReader<'a, 'b> {
    cells: &'a [Cell<'b>],
    index: usize,
    offset: usize,
}
impl<'a, 'b> CellReader<'a, 'b> {
    fn new(cells: &'a [Cell<'b>]) -> Self {
        Self { cells, index: 0, offset: 0 }
    }
}
impl Read for CellReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while let Some(cell) = self.cells.get(self.index) {
            let rest = cell
                .bytes()
                .get(self.offset..)
                .ok_or_else(|| std::io::Error::other("invalid SQL cell cursor"))?;
            if rest.is_empty() {
                self.index = self
                    .index
                    .checked_add(1)
                    .ok_or_else(|| std::io::Error::other("SQL cell cursor overflow"))?;
                self.offset = 0;
                continue;
            }
            let amount = output.len().min(rest.len());
            output
                .get_mut(..amount)
                .ok_or_else(|| std::io::Error::other("invalid SQL output"))?
                .copy_from_slice(
                    rest.get(..amount).ok_or_else(|| std::io::Error::other("invalid SQL input"))?,
                );
            self.offset = self
                .offset
                .checked_add(amount)
                .ok_or_else(|| std::io::Error::other("SQL cell offset overflow"))?;
            return Ok(amount);
        }
        Ok(0)
    }
}
/// Encode explicit SQL cell codecs without a row-sized scratch allocation. Values are
/// borrowed from the private immutable SQLite cut. The independent stream validator checks
/// every codec, key and byte before output. Neither SQL coercion nor opaque JSON is allowed.
/// # Errors
/// Refuses incomplete owners, columns/types/keys/codecs, invalid values and output failures.
pub fn write_full_scalar_sql_row(
    rule: &FamilyRule,
    row: &rusqlite::Row<'_>,
    writer: &mut impl Write,
) -> Result<u64, StorageError> {
    if rule.id == super::message_denial::FAMILY {
        return super::message_denial::encode(rule, row, writer);
    }
    rule.require_typed_codec()?;
    let cells = cells(rule, row)?;
    let header = header(rule, &cells)?;
    copy_full_scalar_record(rule, &header.0, &mut CellReader::new(&cells), &mut std::io::sink())?;
    let mut counted = Counted { writer, bytes: 0 };
    write_record_header(&mut counted, &header.0).map_err(|error| match error {
        ramflux_protocol::custody::pairing::full_transfer::StreamError::Io(error) => {
            StorageError::Io(error)
        }
        _ => unsupported(),
    })?;
    let mut scratch = Zeroizing::new([0_u8; 16_384]);
    let mut input = CellReader::new(&cells);
    loop {
        let count = input.read(scratch.as_mut_slice())?;
        if count == 0 {
            break;
        }
        let bytes = scratch.get_mut(..count).ok_or_else(unsupported)?;
        counted.write_all(bytes)?;
        bytes.zeroize();
    }
    Ok(counted.bytes)
}
struct Counted<'a, W> {
    writer: &'a mut W,
    bytes: u64,
}
impl<W: Write> Write for Counted<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.writer.write(bytes)?;
        self.bytes = self
            .bytes
            .checked_add(written as u64)
            .ok_or_else(|| std::io::Error::other("full record length overflow"))?;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
#[cfg(test)]
mod tests;
