// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed-size incarnation/counter rows; append never decodes the ACK history JSON.
use super::incarnation::{StoredCursor, error, new_id, validate};
use crate::{CursorAckState, NodeCoreError, ROUTER_CURSOR_STATE_TABLE};
use redb::{ReadableTable, TableDefinition};
pub(crate) const TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_inbox_identity_v1");

pub(crate) fn decode(bytes: &[u8]) -> Result<(String, u64), NodeCoreError> {
    if bytes.len() != 40 {
        return Err(error("invalid inbox identity row length"));
    }
    let id = std::str::from_utf8(&bytes[..32]).map_err(error)?.to_owned();
    validate(&id)?;
    let issued = u64::from_le_bytes(bytes[32..].try_into().map_err(error)?);
    Ok((id, issued))
}
pub(crate) fn read(
    tx: &redb::WriteTransaction,
    target: &str,
) -> Result<Option<(String, u64)>, NodeCoreError> {
    tx.open_table(TABLE)
        .map_err(error)?
        .get(target)
        .map_err(error)?
        .map(|row| decode(row.value()))
        .transpose()
}
pub(super) fn set(
    tx: &redb::WriteTransaction,
    target: &str,
    issued: u64,
    id: Option<&str>,
    rotate: bool,
) -> Result<String, NodeCoreError> {
    let mut table = tx.open_table(TABLE).map_err(error)?;
    let previous = table.get(target).map_err(error)?.map(|row| decode(row.value())).transpose()?;
    let chosen = match (id, previous.as_ref()) {
        (Some(id), Some((old, _))) if !rotate && old != id => {
            return Err(error("inbox incarnation mismatch during persistence"));
        }
        (Some(id), _) => id.to_owned(),
        (None, Some((id, _))) => id.clone(),
        (None, None) => new_id()?,
    };
    validate(&chosen)?;
    let issued = previous.as_ref().map_or(issued, |(_, old)| issued.max(*old));
    if previous.as_ref().is_some_and(|(id, old)| id == &chosen && *old == issued) {
        return Ok(chosen);
    }
    let mut bytes = [0; 40];
    bytes[..32].copy_from_slice(chosen.as_bytes());
    bytes[32..].copy_from_slice(&issued.to_le_bytes());
    table.insert(target, bytes.as_slice()).map_err(error)?;
    #[cfg(test)]
    super::incarnation::work::metadata_write();
    Ok(chosen)
}
/// Imports the previous S6 cursor field once. E-less pre-S6 counters remain an upgrade.
pub(crate) fn import(tx: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    let cursors = tx.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(error)?;
    for row in cursors.iter().map_err(error)? {
        let (target, bytes) = row.map_err(error)?;
        if tx.open_table(TABLE).map_err(error)?.get(target.value()).map_err(error)?.is_some() {
            continue;
        }
        let stored: StoredCursor = serde_json::from_slice(bytes.value()).map_err(error)?;
        if let Some(id) = stored.inbox_incarnation_id {
            set(tx, target.value(), high_water(&stored.cursor), Some(&id), false)?;
        }
    }
    Ok(())
}
pub(crate) fn high_water(cursor: &CursorAckState) -> u64 {
    cursor.issued_inbox_seq.max(cursor.inbox_seq).max(cursor.settled_inbox_seq)
}
