// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete closure and quota checks stream one original proof row at a time on the DB worker.
use super::{
    END, MAX_KEY_BYTES, MAX_PROOF_BYTES, PREFIX, PROOFS, REFERENCES, StorageError, digest, invalid,
    proof_key, reference_key, wire,
};
use std::collections::{BTreeMap, BTreeSet};
type ProofSelectors = BTreeMap<String, (String, String)>;
pub(in crate::account_db) fn validate(
    connection: &rusqlite::Connection,
    expected_root: Option<&str>,
) -> Result<(), StorageError> {
    let legacy: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind='reach/provenance')",
        [],
        |row| row.get(0),
    )?;
    if legacy {
        return Err(invalid());
    }
    let (count, bytes): (usize, usize) = connection.query_row("SELECT count(*),coalesce(sum(length(CAST(state_kind AS BLOB))+length(CAST(state_json AS BLOB))),0) FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2", rusqlite::params![PREFIX, END], |row| Ok((row.get(0)?, row.get(1)?)))?;
    if count > wire::MAX_PROVENANCE_OBJECTS + wire::MAX_SIGNER_REFERENCES
        || bytes > wire::MAX_PROVENANCE_BYTES
    {
        return Err(capacity());
    }
    let mut root = expected_root.map(str::to_owned);
    let mut selectors = ProofSelectors::new();
    let mut native = BTreeSet::new();
    let mut seen = 0_usize;
    let mut statement = connection.prepare("SELECT length(CAST(state_kind AS BLOB)),CASE WHEN length(CAST(state_kind AS BLOB))<=?3 THEN state_kind ELSE NULL END,length(CAST(state_json AS BLOB)),CASE WHEN length(CAST(state_json AS BLOB))<=CASE WHEN substr(state_kind,1,length(?5))=?5 THEN 2048 ELSE ?4 END THEN state_json ELSE NULL END FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2 ORDER BY state_kind")?;
    let rows = statement.query_map(
        rusqlite::params![PREFIX, END, MAX_KEY_BYTES, MAX_PROOF_BYTES, REFERENCES],
        |row| {
            Ok((
                row.get::<_, usize>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, usize>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        },
    )?;
    let mut references = 0_usize;
    for row in rows {
        let (key_bytes, key, length, bytes) = row?;
        if key_bytes > MAX_KEY_BYTES || length > MAX_PROOF_BYTES {
            return Err(capacity());
        }
        let key = key.ok_or_else(invalid)?;
        if key.starts_with(REFERENCES) && length > 2048 {
            return Err(capacity());
        }
        let bytes = bytes.ok_or_else(invalid)?;
        if key.starts_with(PROOFS) {
            let proof: wire::ProvenanceAuthority = wire::decode(&bytes, MAX_PROOF_BYTES)?;
            proof.validate()?;
            if proof_key(&proof.proof_hash)? != key {
                return Err(invalid());
            }
            let anchor = &proof.authority.publication.record.body.account_anchor;
            digest(anchor)?;
            if root.as_ref().is_some_and(|root| root != anchor) {
                return Err(invalid());
            }
            root = Some(anchor.clone());
            native.extend(proof.native_hashes()?);
            let record = &proof.authority.publication.record;
            selectors.insert(
                proof.proof_hash,
                (
                    ramflux_protocol::custody::object_hash(record)?,
                    ramflux_protocol::custody::object_hash(&record.body.master_certificate)?,
                ),
            );
            if selectors.len() > wire::MAX_PROVENANCE_OBJECTS
                || native.len() > wire::MAX_PROVENANCE_OBJECTS
            {
                return Err(capacity());
            }
        } else if key.starts_with(REFERENCES) {
            if length > 2048 {
                return Err(capacity());
            }
            let reference: wire::SignerReference = wire::decode(&bytes, 2048)?;
            reference.validate()?;
            if reference_key(reference.object_kind, &reference.object_hash)? != key
                || selectors.get(&reference.proof_hash)
                    != Some(&(reference.authority_head_hash, reference.master_certificate_hash))
            {
                return Err(invalid());
            }
            references += 1;
            if references > wire::MAX_SIGNER_REFERENCES {
                return Err(capacity());
            }
        } else {
            return Err(invalid());
        }
        seen += 1;
    }
    if seen != count {
        return Err(invalid());
    }
    Ok(())
}
fn capacity() -> StorageError {
    StorageError::SegmentResourceCapacity { limit: wire::MAX_PROVENANCE_BYTES }
}
