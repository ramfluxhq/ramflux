// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Charged manifests include their own encoded row; shares cannot borrow from another root.

use super::{BTreeMap, ReadableTable, SendAuthorityError, TableDefinition, reservation, storage};
const CHARGES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("notification_resource_charges_v1");

/// Replace one actual row/mirror charge in the writer's authoritative transaction.
/// Each call's origin/notify partition is 48/16 units and 192/64 KiB.
pub(crate) fn charge(
    tx: &redb::WriteTransaction,
    root: &str,
    slot: Option<&str>,
    notify: bool,
    key: &str,
    (bytes, units): (usize, u64),
) -> Result<(), SendAuthorityError> {
    let bucket = ramflux_protocol::canonical_json_bytes(&(root, slot, notify)).map_err(storage)?;
    let bucket = String::from_utf8(bucket).map_err(storage)?;
    let mut table = tx.open_table(CHARGES).map_err(storage)?;
    let mut rows: BTreeMap<String, (u64, u64)> =
        match table.get(bucket.as_str()).map_err(storage)? {
            Some(value) => {
                if value.value().len() > 8 * 1024 * 1024 {
                    return Err(SendAuthorityError::Capacity);
                }
                ramflux_protocol::parse_i_json(value.value()).map_err(storage)?
            }
            None => BTreeMap::new(),
        };
    rows.insert(key.into(), (units, u64::try_from(bytes).map_err(storage)?));
    let encoded = ramflux_protocol::canonical_json_bytes(&rows).map_err(storage)?;
    let total_units = rows
        .values()
        .try_fold(1u64, |sum, (n, _)| sum.checked_add(*n))
        .ok_or(SendAuthorityError::Capacity)?;
    let total_bytes = rows
        .values()
        .try_fold(u64::try_from(encoded.len() + bucket.len()).map_err(storage)?, |sum, (_, n)| {
            sum.checked_add(*n)
        })
        .ok_or(SendAuthorityError::Capacity)?;
    let (max_units, max_bytes) = if root == reservation::system_root() {
        (8192, 32 * 1024 * 1024)
    } else if slot.is_some() {
        if notify { (16, 64 * 1024) } else { (48, 192 * 1024) }
    } else {
        (2048, 8 * 1024 * 1024)
    };
    if total_units > max_units || total_bytes > max_bytes {
        return Err(SendAuthorityError::Capacity);
    }
    table.insert(bucket.as_str(), encoded.as_slice()).map_err(storage)?;
    Ok(())
}

/// Charge actual origin call rows and indexes in the same transaction as their writes.
/// # Errors
/// Capacity refusal aborts every associated primary and auxiliary allocation.
pub(crate) fn origin_rows(
    tx: &redb::WriteTransaction,
    root: &str,
    slot: &str,
    rows: &[(String, usize)],
) -> Result<(), SendAuthorityError> {
    for (key, bytes) in rows {
        charge(tx, root, Some(slot), false, &format!("call:{key}"), (*bytes + key.len(), 1))?;
    }
    Ok(())
}

pub(crate) fn uncharge(
    tx: &redb::WriteTransaction,
    root: &str,
    slot: Option<&str>,
    notify: bool,
    key: &str,
) -> Result<(), SendAuthorityError> {
    let bucket = String::from_utf8(
        ramflux_protocol::canonical_json_bytes(&(root, slot, notify)).map_err(storage)?,
    )
    .map_err(storage)?;
    let mut table = tx.open_table(CHARGES).map_err(storage)?;
    let mut rows: BTreeMap<String, (u64, u64)> =
        match table.get(bucket.as_str()).map_err(storage)? {
            Some(value) => ramflux_protocol::parse_i_json(value.value()).map_err(storage)?,
            None => return Ok(()),
        };
    rows.remove(key);
    if rows.is_empty() {
        table.remove(bucket.as_str()).map_err(storage)?;
    } else {
        table
            .insert(
                bucket.as_str(),
                ramflux_protocol::canonical_json_bytes(&rows).map_err(storage)?.as_slice(),
            )
            .map_err(storage)?;
    }
    Ok(())
}

pub(crate) fn retire_origin_rows(
    tx: &redb::WriteTransaction,
    root: &str,
    slot: &str,
    keys: &[String],
) -> Result<(), SendAuthorityError> {
    for key in keys {
        uncharge(tx, root, Some(slot), false, &format!("call:{key}"))?;
    }
    Ok(())
}
