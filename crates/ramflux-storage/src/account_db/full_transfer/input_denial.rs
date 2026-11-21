// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Input erasure retains its verifier association and only extends a matching denial.
use crate::StorageError;
use rusqlite::Connection;

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

#[cfg(test)]
mod tests;
