// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded foreign authority and marker associations in the enclosing merge transaction.
use super::*;
use std::collections::BTreeMap;

const LIMIT: usize = 16;
// Derived metadata, created only by merge; single-authority schema14 needs no association table.
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS account_mac_marker_bundle(
    state_kind TEXT PRIMARY KEY, bundle_id TEXT NOT NULL REFERENCES account_mac_bundle(bundle_id))";
const PREFIXES: [&str; 3] = ["message/deleted/", "message/deleted-envelope/", "routed/seen/"];
type Associations = BTreeMap<String, String>;

pub(super) fn load_set(db: &Connection, schema: &str) -> Result<Vec<Bundle>, StorageError> {
    if !matches!(schema, "main" | "incoming") {
        return Err(StorageError::AuthorizationRejected);
    }
    let valid: bool = db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.schema_migration WHERE schema_version=14 AND checksum=?1)"), [CHECKSUM], |r| r.get(0))?;
    if !valid {
        return Err(StorageError::AuthorizationRejected);
    }
    let mut statement = db.prepare(&format!("SELECT bundle_id,subkeys,is_current FROM {schema}.account_mac_bundle ORDER BY is_current DESC,bundle_id LIMIT 17"))?;
    let mut rows = statement.query([])?;
    let mut bundles = Vec::new();
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let bytes = row.get_ref(1)?.as_blob().map_err(|_| StorageError::AuthorizationRejected)?;
        let current: i64 = row.get(2)?;
        if bytes.len() != BUNDLE_BYTES || bundle_id(bytes) != id || !matches!(current, 0 | 1) {
            return Err(StorageError::AuthorizationRejected);
        }
        let mut keys = Zeroizing::new([0; BUNDLE_BYTES]);
        keys.copy_from_slice(bytes);
        bundles.push(Bundle { id, keys, current: current == 1 });
    }
    if bundles.is_empty()
        || bundles.len() > LIMIT
        || bundles.iter().filter(|b| b.current).count() != 1
    {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(bundles)
}

fn associations(
    db: &Connection,
    schema: &str,
    bundles: &[Bundle],
) -> Result<Associations, StorageError> {
    let exists: bool = db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.sqlite_master WHERE name='account_mac_marker_bundle')"), [], |r|r.get(0))?;
    let mut ids = Associations::new();
    if exists {
        let mut query = db.prepare(&format!(
            "SELECT state_kind,bundle_id FROM {schema}.account_mac_marker_bundle"
        ))?;
        for row in query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (marker, id) = row?;
            let valid = PREFIXES.iter().any(|prefix| {
                marker.strip_prefix(prefix).is_some_and(|suffix| {
                    ramflux_protocol::decode_base64url(suffix).is_ok_and(|b| b.len() == 32)
                })
            });
            if !valid || !bundles.iter().any(|b| b.id == id) {
                return Err(StorageError::AuthorizationRejected);
            }
            if ids.insert(marker, id).is_some() {
                return Err(StorageError::AuthorizationRejected);
            }
        }
    } else if bundles.len() > 1 {
        return Err(StorageError::AuthorizationRejected);
    }
    let current = bundles.iter().find(|b| b.current).ok_or(StorageError::AuthorizationRejected)?;
    let mut query = db.prepare(&format!("SELECT state_kind FROM {schema}.runtime_actor_state WHERE (state_kind GLOB 'message/deleted/*' AND json_valid(state_json) AND json_extract(state_json,'$.version')=2) OR state_kind GLOB 'message/deleted-envelope/*' OR state_kind GLOB 'routed/seen/*'"))?;
    for row in query.query_map([], |r| r.get::<_, String>(0))? {
        ids.entry(row?).or_insert_with(|| current.id.clone());
    }
    Ok(ids)
}

/// Validate both sets and all associations before modifying any authority.
pub(crate) fn prepare(db: &Connection) -> Result<Associations, StorageError> {
    let local = load_set(db, "main")?;
    let version: i64 = db.query_row(
        "SELECT COALESCE(MAX(schema_version),0) FROM incoming.schema_migration",
        [],
        |row| row.get(0),
    )?;
    let incoming = if version < VERSION {
        // A raw pre-bundle archive has no recoverable MAC authority. Import its
        // data without minting authority from the enclosing archive key; legacy
        // keyed markers remain unmatched, as for a fresh pre-bundle restore.
        let partial: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE name='account_mac_bundle' OR name='account_mac_marker_bundle')", [], |row| row.get(0),
        )?;
        if partial {
            return Err(StorageError::AuthorizationRejected);
        }
        Vec::new()
    } else {
        load_set(db, "incoming")?
    };
    if local.len() + incoming.iter().filter(|b| !local.iter().any(|l| l.id == b.id)).count() > LIMIT
    {
        return Err(StorageError::AuthorizationRejected);
    }
    let mut ids = associations(db, "main", &local)?;
    let incoming_ids = if incoming.is_empty() {
        Associations::new()
    } else {
        associations(db, "incoming", &incoming)?
    };
    for (marker, id) in incoming_ids {
        if ids.get(&marker).is_some_and(|old| *old != id) {
            return Err(StorageError::AuthorizationRejected);
        }
        ids.insert(marker, id);
    }
    db.execute_batch(SCHEMA)?;
    for bundle in incoming {
        db.execute(
            "INSERT OR IGNORE INTO account_mac_bundle VALUES(?1,?2,0)",
            params![bundle.id, bundle.keys.as_slice()],
        )?;
    }
    Ok(ids)
}

/// Retain ids only for admitted rows, after generic arbitration and native exclusions.
pub(crate) fn finish(db: &Connection, ids: Associations) -> Result<(), StorageError> {
    db.execute("DELETE FROM account_mac_marker_bundle", [])?;
    for (marker, id) in ids {
        db.execute("INSERT INTO account_mac_marker_bundle SELECT ?1,?2 WHERE EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=?1)",params![marker,id])?;
    }
    Ok(())
}

pub(super) fn validate(db: &Connection) -> Result<(), StorageError> {
    let bundles = load_set(db, "main")?;
    associations(db, "main", &bundles)?;
    Ok(())
}
