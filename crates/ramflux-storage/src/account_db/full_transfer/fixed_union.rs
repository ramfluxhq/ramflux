// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed-owner PRIVATE base projection only. No live selection, receipt or native authority.
use super::{FamilyRule, copy_full_scalar_record, full_transfer_catalog};
use crate::{BackupDatabase, StorageError};
use ramflux_protocol::custody::{
    DeviceRef,
    pairing::full_transfer::{RecordHeader, RecordOp},
};
use rusqlite::params;
use std::io::{Cursor, Read};
use zeroize::Zeroizing;

fn unsupported() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn conflict() -> StorageError {
    StorageError::PairingField("TransferConflict")
}

/// The metadata owner path never buffers payload bodies. Each input is size-checked
/// before allocation; content owners require their separate streaming path.
pub(super) const MAX_METADATA_BYTES: usize = 262_144;
#[derive(Clone)]
pub(super) struct Cells {
    bytes: Zeroizing<Vec<u8>>,
    ranges: [std::ops::Range<usize>; 16],
    kinds: [ramflux_protocol::custody::pairing::full_transfer::CellType; 16],
    count: usize,
}
pub(super) struct BoundValue<'a>(rusqlite::types::ValueRef<'a>);
impl rusqlite::ToSql for BoundValue<'_> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::Borrowed(self.0))
    }
}
impl Cells {
    pub(super) fn read(
        rule: &FamilyRule,
        header: &RecordHeader,
        input: &mut impl Read,
    ) -> Result<Self, StorageError> {
        if header.op != RecordOp::Put || header.cell_lengths.len() > 16 {
            return Err(unsupported());
        }
        let size = header.cell_lengths.iter().try_fold(0_usize, |sum, length| {
            sum.checked_add(usize::try_from(length.0).map_err(|_| unsupported())?)
                .filter(|size| *size <= MAX_METADATA_BYTES)
                .ok_or_else(unsupported)
        })?;
        let mut value = Self {
            bytes: Zeroizing::new(vec![0; size]),
            ranges: std::array::from_fn(|_| 0..0),
            kinds: [ramflux_protocol::custody::pairing::full_transfer::CellType::Null; 16],
            count: header.cell_lengths.len(),
        };
        let mut end = 0_usize;
        for (index, length) in header.cell_lengths.iter().enumerate() {
            let next = end
                .checked_add(usize::try_from(length.0).map_err(|_| unsupported())?)
                .ok_or_else(unsupported)?;
            if next > value.bytes.len() {
                return Err(unsupported());
            }
            *value.ranges.get_mut(index).ok_or_else(unsupported)? = end..next;
            *value.kinds.get_mut(index).ok_or_else(unsupported)? =
                *header.cell_types.get(index).ok_or_else(unsupported)?;
            end = next;
        }
        let mut output = Cursor::new(value.bytes.as_mut_slice());
        copy_full_scalar_record(rule, header, input, &mut output)?;
        if output.position() != end as u64 {
            return Err(unsupported());
        }
        Ok(value)
    }
    pub(super) fn bytes(&self, index: usize) -> Result<&[u8], StorageError> {
        if index >= self.count {
            return Err(unsupported());
        }
        self.bytes
            .get(self.ranges.get(index).ok_or_else(unsupported)?.clone())
            .ok_or_else(unsupported)
    }
    pub(super) fn text(&self, index: usize) -> Result<&str, StorageError> {
        std::str::from_utf8(self.bytes(index)?).map_err(|_| unsupported())
    }
    pub(super) fn integer(&self, index: usize) -> Result<i64, StorageError> {
        Ok(i64::from_be_bytes(self.bytes(index)?.try_into().map_err(|_| unsupported())?))
    }
    pub(super) fn set_integer(&mut self, index: usize, value: i64) -> Result<(), StorageError> {
        self.replace(
            index,
            ramflux_protocol::custody::pairing::full_transfer::CellType::I64,
            &value.to_be_bytes(),
        )
    }
    pub(super) fn kind(
        &self,
        index: usize,
    ) -> Result<ramflux_protocol::custody::pairing::full_transfer::CellType, StorageError> {
        if index >= self.count {
            return Err(unsupported());
        }
        self.kinds.get(index).copied().ok_or_else(unsupported)
    }
    pub(super) fn set_text(&mut self, index: usize, text: &str) -> Result<(), StorageError> {
        self.replace(
            index,
            ramflux_protocol::custody::pairing::full_transfer::CellType::Utf8,
            text.as_bytes(),
        )
    }
    pub(super) fn copy_cell(&mut self, index: usize, other: &Self) -> Result<(), StorageError> {
        self.replace(index, other.kind(index)?, other.bytes(index)?)
    }
    fn replace(
        &mut self,
        index: usize,
        kind: ramflux_protocol::custody::pairing::full_transfer::CellType,
        source: &[u8],
    ) -> Result<(), StorageError> {
        if index >= self.count {
            return Err(unsupported());
        }
        let range = self.ranges.get(index).ok_or_else(unsupported)?.clone();
        let size = self
            .bytes
            .len()
            .checked_sub(range.len())
            .and_then(|size| size.checked_add(source.len()))
            .filter(|size| *size <= MAX_METADATA_BYTES)
            .ok_or_else(unsupported)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(size));
        bytes.extend_from_slice(self.bytes.get(..range.start).ok_or_else(unsupported)?);
        bytes.extend_from_slice(source);
        bytes.extend_from_slice(self.bytes.get(range.end..).ok_or_else(unsupported)?);
        self.bytes = bytes;
        *self.kinds.get_mut(index).ok_or_else(unsupported)? = kind;
        let mut end = range.start;
        for position in index..self.count {
            let old = self.ranges.get(position).ok_or_else(unsupported)?.clone();
            let length = if position == index { source.len() } else { old.len() };
            let next = end.checked_add(length).ok_or_else(unsupported)?;
            *self.ranges.get_mut(position).ok_or_else(unsupported)? = end..next;
            end = next;
        }
        Ok(())
    }
    pub(super) fn value(&self, index: usize) -> Result<BoundValue<'_>, StorageError> {
        use ramflux_protocol::custody::pairing::full_transfer::CellType;
        use rusqlite::types::ValueRef;
        if index >= self.count {
            return Err(unsupported());
        }
        Ok(BoundValue(match self.kinds.get(index).ok_or_else(unsupported)? {
            CellType::Null => ValueRef::Null,
            CellType::I64 => ValueRef::Integer(self.integer(index)?),
            CellType::Utf8 => ValueRef::Text(self.bytes(index)?),
            CellType::Bytes => ValueRef::Blob(self.bytes(index)?),
            CellType::F64 => return Err(unsupported()),
        }))
    }
}

impl BackupDatabase {
    /// Project one exact typed base record into this PRIVATE, unselected generation.
    /// Requires an enclosing transaction; the caller must apply restrictive records first,
    /// retain contribution provenance, validate the complete input/counts/root/application,
    /// and commit the whole union before any semantic receipt. No E/R values are imported.
    /// This deliberately refuses absence/delta deletion until its contribution owner runs.
    /// A matching namespace MAC never supplies original-author or native permissions.
    /// # Errors
    /// Refuses no transaction, foreign account, unknown/nonfixed owners, invalid values,
    /// base absence, immutable lookup conflict or any private SQL write failure.
    pub fn apply_full_fixed_base_record(
        &mut self,
        source: &DeviceRef,
        header: &RecordHeader,
        input: &mut impl Read,
    ) -> Result<(), StorageError> {
        apply_fixed_base_in_transaction(&self.db, source, header, input)
    }
}

/// The caller owns a complete authenticated input and the encompassing all-or-nothing
/// transaction. Ordinary A reverse application additionally restricts its input catalog.
pub(super) fn apply_fixed_base_in_transaction(
    db: &rusqlite::Connection,
    source: &DeviceRef,
    header: &RecordHeader,
    input: &mut impl Read,
) -> Result<(), StorageError> {
    if db.is_autocommit() {
        return Err(StorageError::PairingField("WrongContext"));
    }
    super::super::mac_subkeys::full::source_key(source)?;
    let root: String = db.query_row(
        "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if root != source.account_anchor {
        return Err(unsupported());
    }
    if header.family == super::message_denial::FAMILY {
        return super::message_denial::apply(db, header, input);
    }
    let rule = full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == header.family)
        .ok_or_else(unsupported)?;
    let cells = Cells::read(rule, header, input)?;
    if let Some(owner) = super::monotonic::owner(rule.id) {
        return owner.apply(db, rule, &cells);
    }
    match rule.id {
        "sql/object_erasure_fence" => {
            db.execute(
                "INSERT INTO object_erasure_fence(commitment) VALUES(?1) ON CONFLICT DO NOTHING",
                params![cells.text(0)?],
            )?;
        }
        "sql/object_identity_replacement" => {
            db.execute("INSERT INTO object_identity_replacement(commitment) VALUES(?1) ON CONFLICT DO NOTHING",params![cells.text(0)?])?;
        }
        "sql/object_segment_reference_veto" => {
            db.execute("INSERT INTO object_segment_reference_veto(reference_id) VALUES(?1) ON CONFLICT DO NOTHING",params![cells.bytes(0)?])?;
        }
        "sql/object_erasure_lookup" => {
            let changed=db.execute("INSERT INTO object_erasure_lookup(lookup,commitment) VALUES(?1,?2) ON CONFLICT(lookup) DO UPDATE SET commitment=excluded.commitment WHERE object_erasure_lookup.commitment=excluded.commitment",params![cells.text(0)?,cells.text(1)?])?;
            if changed != 1 {
                return Err(conflict());
            }
        }
        "sql/object_payload_dependency" => {
            db.execute("INSERT INTO object_payload_dependency(parent_commitment,child_commitment) VALUES(?1,?2) ON CONFLICT DO NOTHING",params![cells.text(0)?,cells.text(1)?])?;
        }
        "sql/group_service_body_fence" => {
            let changed = db.execute(
                "INSERT INTO group_service_body_fence(message_id, body_hash) VALUES(?1, ?2)
                 ON CONFLICT(message_id) DO UPDATE SET body_hash=excluded.body_hash
                 WHERE group_service_body_fence.body_hash=excluded.body_hash",
                params![cells.text(0)?, cells.bytes(1)?],
            )?;
            if changed != 1 {
                return Err(conflict());
            }
        }
        "sql/account_mac_bundle/portable" => {
            super::super::mac_subkeys::full::import_into_private_generation(
                db,
                source,
                cells.text(0)?,
                cells.bytes(1)?,
            )?;
        }
        "sql/full_imported_mac_bundle" => {
            let original = super::super::mac_subkeys::full::decode_source_ref(cells.bytes(0)?)?;
            super::super::mac_subkeys::full::import_into_private_generation(
                db,
                &original,
                cells.text(1)?,
                cells.bytes(2)?,
            )?;
        }
        _ => return Err(unsupported()),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
