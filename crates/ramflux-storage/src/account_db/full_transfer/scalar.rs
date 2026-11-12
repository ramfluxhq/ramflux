// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact scalar-cell admission. No opaque JSON/native-owner fallback or application writes.
use super::catalog::{CodecRule, FamilyRule};
use crate::StorageError;
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{
        CellType, Disposition, MAX_STABLE_KEY_BYTES, RecordHeader, RecordOp, copy_record_cells,
        encode_stable_key,
    },
};
use std::io::{Read, Write};
use zeroize::{Zeroize as _, Zeroizing};

fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn schema() -> StorageError {
    StorageError::PairingField("SchemaMismatch")
}
/// Validate and copy one exact scalar record's cells into a PRIVATE encrypted staging sink.
/// A mismatch may leave private provisional bytes in that sink; they grant no `DataVerified`,
/// merge, native authority or application visibility. The caller owns transaction/discard.
/// No cell-sized buffer is allocated: physical validation uses 16 KiB, keys at most32KiB.
/// # Errors
/// Refuses unknown owners, non-scalar codecs, wrong fields/version/key/types, or invalid cells.
pub fn copy_full_scalar_record(
    rule: &FamilyRule,
    header: &RecordHeader,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<(), StorageError> {
    validate_scalar_schema(rule, header)?;
    let raw = canonical_key(header)?;
    validate_key_grammar(rule, &raw)?;
    if header.op == RecordOp::Absent {
        return Ok(());
    }
    let mut selected = Vec::with_capacity(rule.key.len());
    let mut key_bytes = 0_u64;
    for name in rule.key {
        let index = rule.cells.iter().position(|cell| cell.name == *name).ok_or_else(schema)?;
        let length = header.cell_lengths[index].0;
        key_bytes = key_bytes
            .checked_add(5)
            .and_then(|value| value.checked_add(length))
            .ok_or_else(invalid)?;
        if key_bytes > MAX_STABLE_KEY_BYTES as u64 {
            return Err(invalid());
        }
        selected.push((
            index,
            Zeroizing::new(Vec::with_capacity(usize::try_from(length).map_err(|_| invalid())?)),
        ));
    }
    let mut row_hash = Zeroizing::new(blake3::Hasher::new());
    let domain = b"ramflux.pairing.full.rowkey.v1";
    row_hash.update(&u32::try_from(domain.len()).map_err(|_| invalid())?.to_be_bytes());
    row_hash.update(domain);
    for (index, (kind, length)) in header.cell_types.iter().zip(&header.cell_lengths).enumerate() {
        if rule.key.is_empty() {
            row_hash.update(&[tag(*kind)]);
            row_hash.update(&u32::try_from(length.0).map_err(|_| invalid())?.to_be_bytes());
        }
        let key = selected.iter_mut().find(|(column, _)| *column == index).map(|(_, bytes)| bytes);
        let mut tee =
            CellSink { output: writer, key, hash: rule.key.is_empty().then_some(&mut *row_hash) };
        let one = CellHeader(RecordHeader {
            family: header.family.clone(),
            codec_version: header.codec_version,
            key: header.key.clone(),
            op: RecordOp::Put,
            cell_types: vec![*kind],
            cell_lengths: vec![*length],
        });
        let codec = &rule
            .codec
            .iter()
            .find(|field| field.name == rule.cells[index].name)
            .ok_or_else(schema)?
            .codec;
        if matches!(
            codec,
            CodecRule::SqlI64 { .. } | CodecRule::SqlBase64 { .. } | CodecRule::SqlMacSubkeys
        ) && *kind != CellType::Null
        {
            let count = usize::try_from(length.0).map_err(|_| invalid())?;
            let mut bytes = Zeroizing::new([0; 192]);
            let value = bytes.get_mut(..count).ok_or_else(invalid)?;
            reader.read_exact(value)?;
            validate_sql_value(codec, *kind, value)?;
            if matches!(codec, CodecRule::SqlMacSubkeys)
                && (raw.len() != 48
                    || raw[..5] != [3, 0, 0, 0, 43]
                    || super::super::mac_subkeys::bundle_id(value).as_bytes() != &raw[5..])
            {
                return Err(invalid());
            }
            tee.write_all(value)?;
        } else {
            copy_record_cells(reader, &mut tee, &one.0).map_err(|error| match error {
                ramflux_protocol::custody::pairing::full_transfer::StreamError::Io(error) => {
                    StorageError::Io(error)
                }
                _ => invalid(),
            })?;
        }
    }
    if rule.key.is_empty() {
        if row_hash.finalize().as_bytes() != &raw[..32] {
            return Err(invalid());
        }
    } else {
        let expected = encode_stable_key(
            selected.iter().map(|(index, value)| (header.cell_types[*index], value.as_slice())),
        )
        .map_err(|_| invalid())?;
        if expected.as_str() != header.key {
            return Err(invalid());
        }
    }
    Ok(())
}
fn validate_scalar_schema(rule: &FamilyRule, header: &RecordHeader) -> Result<(), StorageError> {
    rule.require_typed_codec()?;
    header.validate().map_err(|_| invalid())?;
    if rule.disposition != Disposition::Transfer
        || header.family != rule.id
        || header.codec_version != rule.codec_version
    {
        return Err(schema());
    }
    for cell in rule.cells {
        let field = rule.codec.iter().find(|field| field.name == cell.name).ok_or_else(schema)?;
        if !matches!(
            field.codec,
            CodecRule::Scalar { .. }
                | CodecRule::SqlMacSubkeys
                | CodecRule::SqlBytes { .. }
                | CodecRule::SqlBase64 { .. }
                | CodecRule::SqlI64 { .. }
        ) {
            return Err(invalid());
        }
    }
    if header.op == RecordOp::Put {
        if header.cell_types.len() != rule.cells.len() {
            return Err(schema());
        }
        for (((actual, length), expected), field) in
            header.cell_types.iter().zip(&header.cell_lengths).zip(rule.cells).zip(
                rule.cells.iter().map(|cell| {
                    rule.codec.iter().find(|field| field.name == cell.name).ok_or_else(schema)
                }),
            )
        {
            if (*actual != expected.cell_type && !(*actual == CellType::Null && expected.nullable))
                || (*actual == CellType::Null && length.0 != 0)
            {
                return Err(schema());
            }
            validate_sql_header(&field?.codec, *actual, length.0)?;
        }
    }
    Ok(())
}
struct CellHeader(RecordHeader);
impl Drop for CellHeader {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}

struct CellSink<'a, W> {
    output: &'a mut W,
    key: Option<&'a mut Zeroizing<Vec<u8>>>,
    hash: Option<&'a mut blake3::Hasher>,
}
impl<W: Write> Write for CellSink<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let amount = self.output.write(bytes)?;
        if let Some(key) = self.key.as_mut() {
            key.extend_from_slice(&bytes[..amount]);
        }
        if let Some(hash) = self.hash.as_mut() {
            hash.update(&bytes[..amount]);
        }
        Ok(amount)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}
fn canonical_key(header: &RecordHeader) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    if header.key.len() > (MAX_STABLE_KEY_BYTES * 4).div_ceil(3) {
        return Err(invalid());
    }
    let key =
        Zeroizing::new(ramflux_protocol::decode_base64url(&header.key).map_err(|_| invalid())?);
    if key.len() > MAX_STABLE_KEY_BYTES
        || ramflux_protocol::encode_base64url(key.as_slice()) != header.key
    {
        return Err(invalid());
    }
    Ok(key)
}
fn validate_key_grammar(rule: &FamilyRule, mut key: &[u8]) -> Result<(), StorageError> {
    if rule.key.is_empty() {
        return if key.len() == 36 { Ok(()) } else { Err(invalid()) };
    }
    for name in rule.key {
        if key.len() < 5 {
            return Err(invalid());
        }
        let kind = key[0];
        let length = u32::from_be_bytes(key[1..5].try_into().map_err(|_| invalid())?) as usize;
        key = &key[5..];
        if length > key.len() {
            return Err(invalid());
        }
        let field = rule.cells.iter().find(|cell| cell.name == *name).ok_or_else(schema)?;
        let codec = &rule.codec.iter().find(|field| field.name == *name).ok_or_else(schema)?.codec;
        validate_sql_value(
            codec,
            if kind == 0 { CellType::Null } else { field.cell_type },
            &key[..length],
        )?;
        if kind == 0 {
            if !field.nullable || length != 0 {
                return Err(invalid());
            }
        } else {
            if kind != tag(field.cell_type) {
                return Err(invalid());
            }
            match field.cell_type {
                CellType::I64 | CellType::F64 if length != 8 => return Err(invalid()),
                CellType::F64 => {
                    if !f64::from_be_bytes(key[..length].try_into().map_err(|_| invalid())?)
                        .is_finite()
                    {
                        return Err(invalid());
                    }
                }
                CellType::Utf8 if std::str::from_utf8(&key[..length]).is_err() => {
                    return Err(invalid());
                }
                _ => {}
            }
        }
        key = &key[length..];
    }
    if !key.is_empty() {
        return Err(invalid());
    }
    Ok(())
}
fn validate_sql_header(codec: &CodecRule, kind: CellType, length: u64) -> Result<(), StorageError> {
    let valid = match codec {
        CodecRule::SqlMacSubkeys => kind == CellType::Bytes && length == 192,
        CodecRule::SqlBytes { length: expected, nullable } => {
            (kind == CellType::Bytes && length == expected.0)
                || (kind == CellType::Null && *nullable && length == 0)
        }
        CodecRule::SqlI64 { nullable, .. } => {
            (kind == CellType::I64 && length == 8)
                || (kind == CellType::Null && *nullable && length == 0)
        }
        CodecRule::SqlBase64 { decoded_bytes, nullable } => {
            let expected = decoded_bytes.0.checked_mul(4).ok_or_else(invalid)?.div_ceil(3);
            (kind == CellType::Utf8 && length == expected)
                || (kind == CellType::Null && *nullable && length == 0)
        }
        _ => true,
    };
    if valid { Ok(()) } else { Err(invalid()) }
}
fn validate_sql_value(codec: &CodecRule, kind: CellType, bytes: &[u8]) -> Result<(), StorageError> {
    validate_sql_header(codec, kind, bytes.len() as u64)?;
    if kind == CellType::Null {
        return Ok(());
    }
    if let CodecRule::SqlBase64 { decoded_bytes, .. } = codec {
        let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
        let decoded =
            Zeroizing::new(ramflux_protocol::decode_base64url(text).map_err(|_| invalid())?);
        if decoded.len() as u64 != decoded_bytes.0
            || ramflux_protocol::encode_base64url(&decoded) != text
        {
            return Err(invalid());
        }
    }
    if let CodecRule::SqlI64 { min, max, .. } = codec {
        let value = i64::from_be_bytes(bytes.try_into().map_err(|_| invalid())?);
        let (low, high) = super::catalog::sql_i64_bounds(min, max)?;
        if value < low || value > high {
            return Err(invalid());
        }
    }
    Ok(())
}
const fn tag(kind: CellType) -> u8 {
    match kind {
        CellType::Null => 0,
        CellType::I64 => 1,
        CellType::F64 => 2,
        CellType::Utf8 => 3,
        CellType::Bytes => 4,
    }
}
