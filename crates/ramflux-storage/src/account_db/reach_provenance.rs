// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Backup union streams immutable encrypted proof/reference rows; never current authority.
use super::reach_proof_records::{
    END, MAX_KEY_BYTES, MAX_PROOF_BYTES, PREFIX, REFERENCES, canonical_record, validate,
};
use crate::StorageError;
use ramflux_protocol::contact_reach as wire;
use rusqlite::{Connection, OptionalExtension, params};
fn invalid() -> StorageError {
    StorageError::Integrity("conflicting or incomplete retained reach provenance")
}
fn capacity() -> StorageError {
    StorageError::SegmentResourceCapacity { limit: wire::MAX_PROVENANCE_BYTES }
}

/// Called inside the existing encrypted generation transaction; each body is bounded separately.
pub(super) fn merge(connection: &Connection) -> Result<(), StorageError> {
    let incoming_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE name='runtime_actor_state')",
        [],
        |row| row.get(0),
    )?;
    if !incoming_exists {
        return Ok(());
    }
    validate(connection, None)?;
    let legacy: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM incoming.runtime_actor_state WHERE state_kind='reach/provenance')", [], |row| row.get(0))?;
    if legacy {
        return Err(invalid());
    }
    let mut total: usize = connection.query_row("SELECT coalesce(sum(length(CAST(state_kind AS BLOB))+length(CAST(state_json AS BLOB))),0) FROM main.runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2", params![PREFIX, END], |row| row.get(0))?;
    let mut statement = connection.prepare("SELECT length(CAST(state_kind AS BLOB)),CASE WHEN length(CAST(state_kind AS BLOB))<=?3 THEN state_kind ELSE NULL END,length(CAST(state_json AS BLOB)),CASE WHEN length(CAST(state_json AS BLOB))<=CASE WHEN substr(state_kind,1,length(?5))=?5 THEN 2048 ELSE ?4 END THEN state_json ELSE NULL END FROM incoming.runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2 ORDER BY state_kind")?;
    let rows = statement.query_map(
        params![PREFIX, END, MAX_KEY_BYTES, MAX_PROOF_BYTES, REFERENCES],
        |row| {
            Ok((
                row.get::<_, usize>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, usize>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        },
    )?;
    let mut count = 0_usize;
    for row in rows {
        let (key_bytes, key, length, bytes) = row?;
        count += 1;
        if key_bytes > MAX_KEY_BYTES
            || length > MAX_PROOF_BYTES
            || count > wire::MAX_PROVENANCE_OBJECTS + wire::MAX_SIGNER_REFERENCES
        {
            return Err(capacity());
        }
        let key = key.ok_or_else(invalid)?;
        if key.starts_with(REFERENCES) && length > 2048 {
            return Err(capacity());
        }
        let canonical = canonical_record(&key, &bytes.ok_or_else(invalid)?)?;
        if let Some(old) = read_one(connection, &key)? {
            if canonical_record(&key, &old)? != canonical {
                return Err(invalid());
            }
            continue;
        }
        total = total
            .checked_add(key.len())
            .and_then(|size| size.checked_add(canonical.len()))
            .filter(|size| *size <= wire::MAX_PROVENANCE_BYTES)
            .ok_or_else(capacity)?;
        connection.execute(
            "INSERT INTO main.runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            params![key, canonical],
        )?;
    }
    drop(statement);
    validate(connection, None)
}
fn read_one(connection: &Connection, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
    let limit = if key.starts_with(REFERENCES) { 2048 } else { MAX_PROOF_BYTES };
    let value: Option<(usize, Option<Vec<u8>>)> = connection.query_row("SELECT length(CAST(state_json AS BLOB)),CASE WHEN length(CAST(state_json AS BLOB))<=?2 THEN state_json ELSE NULL END FROM main.runtime_actor_state WHERE state_kind=?1", params![key, limit], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
    let Some((length, bytes)) = value else {
        return Ok(None);
    };
    if length > limit {
        return Err(capacity());
    }
    Ok(Some(bytes.ok_or_else(invalid)?))
}

#[cfg(test)]
use ramflux_protocol::contact_reach::{ProvenanceAuthority, SignerReference};
#[cfg(test)]
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Pool {
    signers: Vec<SignerReference>,
    authorities: Vec<ProvenanceAuthority>,
}
#[cfg(test)]
fn persist(db: &super::AccountDb, pool: &Pool) -> Result<(), StorageError> {
    let root = &pool
        .authorities
        .first()
        .ok_or_else(invalid)?
        .authority
        .publication
        .record
        .body
        .account_anchor;
    db.retain_reach_provenance(root, &pool.signers, pool.authorities.iter().cloned().map(Ok))
}
#[cfg(test)]
fn read(connection: &Connection, database: &str) -> Result<Option<Pool>, StorageError> {
    if database != "main" {
        return Err(invalid());
    }
    validate(connection, None)?;
    let mut pool = Pool::default();
    let mut statement = connection.prepare("SELECT state_kind,state_json FROM main.runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2 ORDER BY state_kind")?;
    for row in statement.query_map(params![PREFIX, END], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })? {
        let (key, bytes) = row?;
        if key.starts_with(REFERENCES) {
            pool.signers.push(wire::decode(&bytes, 2048)?);
        } else {
            pool.authorities.push(wire::decode(&bytes, MAX_PROOF_BYTES)?);
        }
    }
    Ok((!pool.signers.is_empty() || !pool.authorities.is_empty()).then_some(pool))
}
#[cfg(test)]
mod tests;
