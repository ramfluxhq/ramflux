// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Input erasure retains its verifier association and only extends a matching denial.
use super::{fixed_union::Cells, full_transfer_catalog, write_full_scalar_sql_row};
use crate::{BackupDatabase, StorageError};
use ramflux_protocol::custody::{DeviceRef, pairing::full_transfer::read_record_header};
use rusqlite::{Connection, params};
use zeroize::Zeroizing;

pub(super) const FAMILY: &str = "sql/receive_erased_input";
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}

pub(super) fn require_bundle(db: &Connection, bundle: &str) -> Result<(), StorageError> {
    let known: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM account_mac_bundle WHERE bundle_id=?1)
         OR EXISTS(SELECT 1 FROM full_imported_mac_bundle WHERE bundle_id=?1)",
        [bundle],
        |row| row.get(0),
    )?;
    if known { Ok(()) } else { Err(invalid()) }
}

pub(super) fn apply(
    db: &Connection,
    source: &DeviceRef,
    cells: &Cells,
) -> Result<(), StorageError> {
    super::super::mac_subkeys::full::source_key(source)?;
    let selector = cells.text(0)?;
    let bundle = cells.text(1)?;
    require_bundle(db, bundle)?;
    let changed = db.execute(
        "INSERT INTO receive_erased_input(selector,bundle_id,expires_at) VALUES(?1,?2,?3)
         ON CONFLICT(selector) DO UPDATE SET expires_at=max(expires_at,excluded.expires_at)
         WHERE receive_erased_input.bundle_id=excluded.bundle_id",
        params![selector, bundle, cells.integer(2)?],
    )?;
    if changed != 1 {
        return Err(StorageError::PairingField("TransferConflict"));
    }
    Ok(())
}

/// Normalize both original contributions to the actually merged max expiry.
pub(super) fn normalize(
    db: &Connection,
    nonce: &[u8; 32],
    private: &BackupDatabase,
) -> Result<(), StorageError> {
    let rule = full_transfer_catalog().iter().find(|rule| rule.id == FAMILY).ok_or_else(invalid)?;
    let mut query = db.prepare(
        "SELECT owner,key,record FROM full_union_record WHERE generation_nonce=?1 AND family=?2 ORDER BY owner,key",
    )?;
    let mut rows = query.query(params![nonce.as_slice(), FAMILY])?;
    while let Some(row) = rows.next()? {
        let owner = row.get_ref(0)?.as_str().map_err(|_| invalid())?;
        let key = row.get_ref(1)?.as_str().map_err(|_| invalid())?;
        let mut input = row.get_ref(2)?.as_blob().map_err(|_| invalid())?;
        let header = read_record_header(&mut input).map_err(|_| invalid())?.ok_or_else(invalid)?;
        let cells = Cells::read(rule, &header, &mut input)?;
        let mut normalized = Zeroizing::new(Vec::new());
        private.db.query_row(
            "SELECT selector,bundle_id,expires_at FROM receive_erased_input WHERE selector=?1 AND bundle_id=?2",
            params![cells.text(0)?,cells.text(1)?],
            |row| Ok(write_full_scalar_sql_row(rule,row,&mut *normalized)),
        )??;
        db.execute(
            "UPDATE full_union_record SET record=?1 WHERE generation_nonce=?2 AND owner=?3 AND family=?4 AND key=?5",
            params![normalized.as_slice(),nonce.as_slice(),owner,FAMILY,key],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
