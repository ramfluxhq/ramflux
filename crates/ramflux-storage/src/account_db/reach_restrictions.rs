// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore stages independent restrictions for SDK authentication, never positive permissions.
use crate::StorageError;
use ramflux_protocol::contact_reach::{MAX_STATE_BYTES, StateRecord};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const KEY: &str = "reach/restore-restrictions";
const STATE_KEY: &str = "directory/reach/state";
// The private saved mirror contains the bounded canonical image and independent restrictions.
const MAX_SAVED_BYTES: usize = 2 * MAX_STATE_BYTES + 4096;
/// Negative-only private restore stage. It never carries a positive grant or an active lease.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachRestoreRestrictions {
    pub root: String,
    #[serde(deserialize_with = "bounded::records")]
    pub records: Vec<StateRecord>,
}
use ReachRestoreRestrictions as Restrictions;
// These are selected fields of SDK-private persistence, not a permissive wire decoder.
#[derive(Deserialize)]
struct Saved {
    root: String,
    #[serde(deserialize_with = "bounded::records")]
    records: Vec<StateRecord>,
    #[serde(deserialize_with = "bounded::restrictions")]
    restrictions: BTreeMap<String, StateRecord>,
}
fn invalid() -> StorageError {
    StorageError::Integrity("invalid retained reach restrictions")
}
fn read(
    connection: &Connection,
    database: &str,
    key: &str,
) -> Result<Option<Vec<u8>>, StorageError> {
    let query = match database {
        "main" => {
            "SELECT length(CAST(state_json AS BLOB)),CASE WHEN length(CAST(state_json AS BLOB))<=?2 THEN state_json ELSE NULL END FROM main.runtime_actor_state WHERE state_kind=?1"
        }
        "incoming" => {
            "SELECT length(CAST(state_json AS BLOB)),CASE WHEN length(CAST(state_json AS BLOB))<=?2 THEN state_json ELSE NULL END FROM incoming.runtime_actor_state WHERE state_kind=?1"
        }
        _ => return Err(invalid()),
    };
    let value: Option<(usize, Option<Vec<u8>>)> = connection
        .query_row(query, params![key, MAX_SAVED_BYTES], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    let Some((length, bytes)) = value else {
        return Ok(None);
    };
    if length > MAX_SAVED_BYTES {
        return Err(StorageError::SegmentResourceCapacity { limit: MAX_SAVED_BYTES });
    }
    Ok(Some(bytes.ok_or_else(invalid)?))
}

/// Same encrypted-generation transaction as the proof union and generic data merge.
pub(super) fn merge(connection: &Connection) -> Result<(), StorageError> {
    let mut root = None;
    let mut records = BTreeMap::new();
    let mut bytes = 128_usize;
    for database in ["main", "incoming"] {
        if database == "incoming" && !connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE name='runtime_actor_state')", [], |row| row.get::<_, bool>(0),
        )? { continue; }
        if let Some(raw) = read(connection, database, KEY)? {
            let staged: Restrictions =
                ramflux_protocol::contact_reach::decode(&raw, MAX_STATE_BYTES)?;
            bind_root(&mut root, staged.root)?;
            append(&mut records, staged.records, &mut bytes)?;
        }
        if let Some(raw) = read(connection, database, STATE_KEY)? {
            let saved: Saved = ramflux_protocol::parse_i_json(&raw)?;
            bind_root(&mut root, saved.root)?;
            append(
                &mut records,
                saved.records.into_iter().chain(saved.restrictions.into_values()),
                &mut bytes,
            )?;
        }
    }
    let Some(root) = root else {
        return Ok(());
    };
    let staged = Restrictions { root, records: records.into_values().collect() };
    let bytes = ramflux_protocol::canonical_json_bytes(&staged)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(StorageError::SegmentResourceCapacity { limit: MAX_STATE_BYTES });
    }
    connection.execute("INSERT INTO main.runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json", params![KEY, bytes])?;
    Ok(())
}
fn bind_root(root: &mut Option<String>, incoming: String) -> Result<(), StorageError> {
    let decoded = ramflux_protocol::decode_base64url(&incoming).map_err(|_| invalid())?;
    if decoded.len() != 32
        || ramflux_protocol::encode_base64url(decoded) != incoming
        || root.as_ref().is_some_and(|root| root != &incoming)
    {
        return Err(invalid());
    }
    *root = Some(incoming);
    Ok(())
}
fn append(
    records: &mut BTreeMap<Vec<u8>, StateRecord>,
    incoming: impl IntoIterator<Item = StateRecord>,
    bytes: &mut usize,
) -> Result<(), StorageError> {
    for record in incoming {
        if !matches!(
            record,
            StateRecord::Block { .. }
                | StateRecord::Decline { .. }
                | StateRecord::Floor { .. }
                | StateRecord::Conflict { .. }
                | StateRecord::Retirement { .. }
        ) {
            continue;
        }
        let key = ramflux_protocol::canonical_json_bytes(&record)?;
        if records.contains_key(&key) {
            continue;
        }
        *bytes = bytes
            .checked_add(key.len() + 1)
            .filter(|size| *size <= MAX_STATE_BYTES)
            .ok_or(StorageError::SegmentResourceCapacity { limit: MAX_STATE_BYTES })?;
        if records.len() >= 8192 {
            return Err(StorageError::SegmentResourceCapacity { limit: MAX_STATE_BYTES });
        }
        records.insert(key, record);
    }
    Ok(())
}

mod bounded;
#[cfg(test)]
mod tests;
