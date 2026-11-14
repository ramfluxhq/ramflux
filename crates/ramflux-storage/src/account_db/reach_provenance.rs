// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Backup union of original historical signer evidence; never authority or permissions.
use crate::StorageError;
use ramflux_protocol::contact_reach::{self as wire, ProvenanceAuthority, SignerReference};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
const KEY: &str = "reach/provenance";
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pool {
    signers: Vec<SignerReference>,
    authorities: Vec<ProvenanceAuthority>,
}
fn invalid() -> StorageError {
    StorageError::Integrity("conflicting or incomplete retained reach provenance")
}
fn read(connection: &Connection, database: &str) -> Result<Option<Pool>, StorageError> {
    let query = match database {
        "main" => {
            "SELECT length(state_json),CASE WHEN length(state_json)<=?2 THEN state_json ELSE NULL END FROM main.runtime_actor_state WHERE state_kind=?1"
        }
        "incoming" => {
            "SELECT length(state_json),CASE WHEN length(state_json)<=?2 THEN state_json ELSE NULL END FROM incoming.runtime_actor_state WHERE state_kind=?1"
        }
        _ => return Err(invalid()),
    };
    let value: Option<(u64, Option<Vec<u8>>)> = connection
        .query_row(query, params![KEY, wire::MAX_PROVENANCE_BYTES], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()?;
    let Some((length, bytes)) = value else {
        return Ok(None);
    };
    if length > wire::MAX_PROVENANCE_BYTES as u64 {
        return Err(StorageError::SegmentResourceCapacity { limit: wire::MAX_PROVENANCE_BYTES });
    }
    Ok(Some(wire::decode(&bytes.ok_or_else(invalid)?, wire::MAX_PROVENANCE_BYTES)?))
}
/// Called inside the encrypted generation's existing merge transaction.
pub(super) fn merge(connection: &Connection) -> Result<(), StorageError> {
    let incoming_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE name='runtime_actor_state')",
        [],
        |row| row.get(0),
    )?;
    if !incoming_exists {
        return Ok(());
    }
    let Some(incoming) = read(connection, "incoming")? else {
        return Ok(());
    };
    let local = read(connection, "main")?.unwrap_or_default();
    let pool = union(local, incoming)?;
    let bytes = ramflux_protocol::canonical_json_bytes(&pool)?;
    if bytes.len() > wire::MAX_PROVENANCE_BYTES {
        return Err(StorageError::SegmentResourceCapacity { limit: wire::MAX_PROVENANCE_BYTES });
    }
    connection.execute("INSERT INTO main.runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json", params![KEY, bytes])?;
    Ok(())
}
fn union(local: Pool, incoming: Pool) -> Result<Pool, StorageError> {
    let mut references = BTreeMap::new();
    let mut proofs = BTreeMap::new();
    for pool in [local, incoming] {
        for reference in pool.signers {
            reference.validate()?;
            let key = (reference.object_kind, reference.object_hash.clone());
            if let Some(old) = references.insert(key, reference.clone())
                && old != reference
            {
                return Err(invalid());
            }
        }
        for proof in pool.authorities {
            proof.validate()?;
            if let Some(old) = proofs.insert(proof.proof_hash.clone(), proof.clone())
                && old != proof
            {
                return Err(invalid());
            }
        }
    }
    if references.len() > wire::MAX_SIGNER_REFERENCES || proofs.len() > wire::MAX_PROVENANCE_OBJECTS
    {
        return Err(StorageError::SegmentResourceCapacity { limit: wire::MAX_PROVENANCE_BYTES });
    }
    let mut native = BTreeSet::new();
    let mut root = None;
    for proof in proofs.values() {
        let anchor = &proof.authority.publication.record.body.account_anchor;
        if root.is_some_and(|old| old != anchor) {
            return Err(invalid());
        }
        root = Some(anchor);
        native.extend(proof.native_hashes()?);
    }
    if native.len() > wire::MAX_PROVENANCE_OBJECTS {
        return Err(StorageError::SegmentResourceCapacity { limit: wire::MAX_PROVENANCE_BYTES });
    }
    for reference in references.values() {
        let proof = proofs.get(&reference.proof_hash).ok_or_else(invalid)?;
        if reference.authority_head_hash
            != ramflux_protocol::custody::object_hash(&proof.authority.publication.record)?
            || reference.master_certificate_hash
                != ramflux_protocol::custody::object_hash(
                    &proof.authority.publication.record.body.master_certificate,
                )?
        {
            return Err(invalid());
        }
    }
    Ok(Pool {
        signers: references.into_values().collect(),
        authorities: proofs.into_values().collect(),
    })
}

#[cfg(test)]
mod tests;
