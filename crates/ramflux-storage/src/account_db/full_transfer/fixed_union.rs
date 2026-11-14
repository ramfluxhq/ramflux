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

pub(super) struct Cells {
    bytes: Zeroizing<[u8; 1024]>,
    ranges: [std::ops::Range<usize>; 3],
    count: usize,
}
impl Cells {
    pub(super) fn read(
        rule: &FamilyRule,
        header: &RecordHeader,
        input: &mut impl Read,
    ) -> Result<Self, StorageError> {
        if header.op != RecordOp::Put || header.cell_lengths.len() > 3 {
            return Err(unsupported());
        }
        let mut value = Self {
            bytes: Zeroizing::new([0; 1024]),
            ranges: std::array::from_fn(|_| 0..0),
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
            value.ranges[index] = end..next;
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
        self.bytes.get(self.ranges[index].clone()).ok_or_else(unsupported)
    }
    pub(super) fn text(&self, index: usize) -> Result<&str, StorageError> {
        std::str::from_utf8(self.bytes(index)?).map_err(|_| unsupported())
    }
    fn integer(&self, index: usize) -> Result<i64, StorageError> {
        Ok(i64::from_be_bytes(self.bytes(index)?.try_into().map_err(|_| unsupported())?))
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
    let rule = full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == header.family)
        .ok_or_else(unsupported)?;
    let cells = Cells::read(rule, header, input)?;
    match rule.id {
        "sql/account_erasure_generation" => {
            let changed=db.execute("UPDATE account_erasure_generation SET generation=max(generation,?1) WHERE singleton=1",params![cells.integer(1)?])?;
            if changed != 1 {
                return Err(StorageError::PairingField("SchemaMismatch"));
            }
        }
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
