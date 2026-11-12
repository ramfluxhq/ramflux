// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded source-row encoding for explicit fixed-width SQL owners only.
use super::{CodecRule, FamilyRule, FamilySelector, copy_full_scalar_record};
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{
    CellType, RecordHeader, RecordOp, U64, encode_stable_key, write_record_header,
};
use rusqlite::types::ValueRef;
use std::io::Write;
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

/// Encode one locally selected SQL row using only explicit fixed-width typed owners.
/// Borrows SQLite values directly and wipes bounded scratch; no generic `Value` row tree,
/// SQL coercion, rowid, or opaque JSON fallback. Invalid rows emit no bytes. The caller
/// owns the immutable source cut, complete census, ordering and private encrypted sink;
/// this primitive does not certify a manifest or authorize `DataVerified`.
/// # Errors
/// Refuses undeclared/result columns, unknown/variable-width owners, semantic mismatches,
/// oversized fixed declarations and output I/O failures.
pub fn write_full_scalar_sql_row(
    rule: &FamilyRule,
    row: &rusqlite::Row<'_>,
    writer: &mut impl Write,
) -> Result<u64, StorageError> {
    rule.require_typed_codec()?;
    if !matches!(rule.selector, FamilySelector::Table(_))
        || rule.key.is_empty()
        || row.as_ref().column_count() != rule.cells.len()
    {
        return Err(unsupported());
    }
    let mut scratch = Zeroizing::new([0_u8; 4096]);
    let mut length = 0_usize;
    let mut ranges = Vec::with_capacity(rule.cells.len());
    let mut kinds = Vec::with_capacity(rule.cells.len());
    for (index, cell) in rule.cells.iter().enumerate() {
        if row.as_ref().column_name(index)? != cell.name {
            return Err(StorageError::PairingField("SchemaMismatch"));
        }
        let codec =
            &rule.codec.iter().find(|field| field.name == cell.name).ok_or_else(unsupported)?.codec;
        let width = match codec {
            CodecRule::SqlMacSubkeys => 192,
            CodecRule::SqlDeviceRef => 512,
            CodecRule::SqlI64 { .. } => 8,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), .. } => 43,
            CodecRule::SqlBytes { length, .. } => {
                usize::try_from(length.0).map_err(|_| unsupported())?
            }
            _ => return Err(unsupported()),
        };
        let end = length.checked_add(width).ok_or_else(unsupported)?;
        let target = scratch.get_mut(length..end).ok_or_else(unsupported)?;
        let (kind, used) = match row.get_ref(index)? {
            ValueRef::Integer(value) if cell.cell_type == CellType::I64 && width == 8 => {
                target.copy_from_slice(&value.to_be_bytes());
                (CellType::I64, width)
            }
            ValueRef::Text(bytes)
                if cell.cell_type == CellType::Utf8
                    && (bytes.len() == width
                        || (matches!(codec, CodecRule::SqlDeviceRef) && bytes.len() <= width)) =>
            {
                target[..bytes.len()].copy_from_slice(bytes);
                (CellType::Utf8, bytes.len())
            }
            ValueRef::Blob(bytes) if cell.cell_type == CellType::Bytes && bytes.len() == width => {
                target.copy_from_slice(bytes);
                (CellType::Bytes, width)
            }
            ValueRef::Null => (CellType::Null, 0),
            _ => return Err(unsupported()),
        };
        ranges.push(length..length + used);
        kinds.push(kind);
        length += used;
    }
    let key_columns = rule
        .key
        .iter()
        .map(|name| rule.cells.iter().position(|cell| cell.name == *name).ok_or_else(unsupported))
        .collect::<Result<Vec<_>, _>>()?;
    let key = encode_stable_key(
        key_columns.iter().map(|index| (kinds[*index], &scratch[ranges[*index].clone()])),
    )
    .map_err(|_| unsupported())?;
    let header = PrivateHeader(RecordHeader {
        family: rule.id.into(),
        codec_version: rule.codec_version,
        key: key.to_string(),
        op: RecordOp::Put,
        cell_types: kinds,
        cell_lengths: ranges.iter().map(|range| U64(range.len() as u64)).collect(),
    });
    copy_full_scalar_record(rule, &header.0, &mut &scratch[..length], &mut std::io::sink())?;
    let mut counted = Counted { writer, bytes: 0 };
    write_record_header(&mut counted, &header.0).map_err(|error| match error {
        ramflux_protocol::custody::pairing::full_transfer::StreamError::Io(error) => {
            StorageError::Io(error)
        }
        _ => unsupported(),
    })?;
    counted.write_all(&scratch[..length])?;
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
