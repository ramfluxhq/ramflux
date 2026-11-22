// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-owner record budgets. Metadata never acquires the native payload allowance.
use super::{CodecRule, FamilyRule, NativePayload};
use crate::StorageError;
use ramflux_protocol::custody::pairing::{PairingWire as _, full_transfer::RecordHeader};
use zeroize::Zeroizing;

pub(super) const METADATA_LIMIT: usize = super::fixed_union::MAX_METADATA_BYTES;
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
pub(super) fn limit(rule: &FamilyRule) -> Result<usize, StorageError> {
    rule.require_typed_codec()?;
    let mut native = None;
    for field in rule.codec {
        if let CodecRule::SqlNativePayload { payload } = field.codec
            && native.replace(payload).is_some()
        {
            return Err(invalid());
        }
    }
    METADATA_LIMIT.checked_add(native.map_or(0, NativePayload::max_bytes)).ok_or_else(invalid)
}
pub(super) fn require_length(rule: &FamilyRule, length: u64) -> Result<(), StorageError> {
    if length == 0 || length > limit(rule)? as u64 {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn require_header(rule: &FamilyRule, header: &RecordHeader) -> Result<(), StorageError> {
    // Count the same canonical header as the wire encoder without a second
    // maximum-sized allocation whose spare capacity would also need wiping.
    let prefix = Zeroizing::new(header.to_wire_bytes().map_err(|_| invalid())?);
    let mut total = (prefix.len() as u64).checked_add(4).ok_or_else(invalid)?;
    let mut metadata = total;
    for (cell, length) in rule.cells.iter().zip(&header.cell_lengths) {
        total = total.checked_add(length.0).ok_or_else(invalid)?;
        let field = rule.codec.iter().find(|field| field.name == cell.name).ok_or_else(invalid)?;
        if !matches!(field.codec, CodecRule::SqlNativePayload { .. }) {
            metadata = metadata.checked_add(length.0).ok_or_else(invalid)?;
        }
    }
    if metadata > METADATA_LIMIT as u64 {
        return Err(invalid());
    }
    require_length(rule, total)
}
/// Only a compiled native family gets its named native byte budget. The SQL bound
/// complements, and never replaces, exact field/header/native semantic validation.
pub(super) fn sql_constraint() -> String {
    let payload = NativePayload::DirectHistoryV1;
    format!(
        "CHECK(length(record) BETWEEN 1 AND CASE family WHEN '{}' THEN {} ELSE {} END)",
        payload.family(),
        METADATA_LIMIT + payload.max_bytes(),
        METADATA_LIMIT,
    )
}
pub(super) fn require_storage_format(
    db: &rusqlite::Connection,
    schema: &'static str,
    table: &str,
) -> Result<(), StorageError> {
    use rusqlite::OptionalExtension as _;
    if !matches!(schema, "main" | "verifier") {
        return Err(invalid());
    }
    let stored: Option<String> = db.query_row(
        &format!("SELECT CASE WHEN length(sql)<=8192 THEN sql ELSE '' END FROM {schema}.sqlite_schema WHERE type='table' AND name=?1"),
        [table], |row| row.get(0),
    ).optional()?;
    let normalize = |text: &str| {
        text.chars()
            .filter(|ch| !ch.is_whitespace())
            .flat_map(char::to_lowercase)
            .collect::<String>()
    };
    if stored.is_some_and(|sql| !normalize(&sql).contains(&normalize(&sql_constraint()))) {
        return Err(StorageError::PairingField("SchemaMismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
