// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Individually bounded encrypted historical proofs and immutable original-object selectors.
use super::AccountDb;
use crate::StorageError;
use ramflux_protocol::contact_reach::{
    self as wire, ObjectKind, ProvenanceAuthority, SignerReference,
};
use rusqlite::{OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};

pub(super) const PREFIX: &str = "reach/provenance/";
pub(super) const END: &str = "reach/provenance0";
pub(super) const MAX_KEY_BYTES: usize = REFERENCES.len() + "group_roster/".len() + 43;
pub(super) const PROOFS: &str = "reach/provenance/proof/";
pub(super) const REFERENCES: &str = "reach/provenance/reference/";
pub(super) const MAX_PROOF_BYTES: usize = 1024 * 1024 + 1024;
fn invalid() -> StorageError {
    StorageError::Integrity("invalid retained reach proof record")
}
fn digest(value: &str) -> Result<(), StorageError> {
    let bytes = ramflux_protocol::decode_base64url(value).map_err(|_| invalid())?;
    if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != value {
        return Err(invalid());
    }
    Ok(())
}
fn proof_key(hash: &str) -> Result<String, StorageError> {
    digest(hash)?;
    Ok(format!("{PROOFS}{hash}"))
}
fn reference_key(kind: ObjectKind, hash: &str) -> Result<String, StorageError> {
    digest(hash)?;
    let kind = match kind {
        ObjectKind::Admission => "admission",
        ObjectKind::GroupRoster => "group_roster",
        ObjectKind::Policy => "policy",
    };
    Ok(format!("{REFERENCES}{kind}/{hash}"))
}

pub(super) fn canonical_record(key: &str, bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    if key.starts_with(PROOFS) {
        let proof: ProvenanceAuthority = wire::decode(bytes, MAX_PROOF_BYTES)?;
        proof.validate()?;
        if proof_key(&proof.proof_hash)? != key {
            return Err(invalid());
        }
        return Ok(ramflux_protocol::canonical_json_bytes(&proof)?);
    }
    if key.starts_with(REFERENCES) {
        let reference: SignerReference = wire::decode(bytes, 2048)?;
        reference.validate()?;
        if reference_key(reference.object_kind, &reference.object_hash)? != key {
            return Err(invalid());
        }
        return Ok(ramflux_protocol::canonical_json_bytes(&reference)?);
    }
    Err(invalid())
}

impl AccountDb {
    /// Retain exact originals atomically with the caller's signed intent or adopted mirror.
    /// Each proof is decoded/encoded separately; no all-proof catalogue is allocated.
    /// # Errors
    /// Refuses changed selectors, mixed recipients, missing closure, resource caps and storage errors.
    pub fn retain_reach_provenance(
        &self,
        root: &str,
        references: &[SignerReference],
        proofs: impl IntoIterator<Item = Result<ProvenanceAuthority, StorageError>>,
    ) -> Result<(), StorageError> {
        digest(root)?;
        self.write_transaction(|| {
            for proof in proofs {
                let proof = proof?;
                proof.validate()?;
                if proof.authority.publication.record.body.account_anchor != root {
                    return Err(invalid());
                }
                self.put_reach_original(&proof_key(&proof.proof_hash)?, &proof, MAX_PROOF_BYTES)?;
            }
            for reference in references {
                reference.validate()?;
                self.put_reach_original(
                    &reference_key(reference.object_kind, &reference.object_hash)?,
                    reference,
                    2048,
                )?;
            }
            let root = root.to_owned();
            self.connection.call(move |connection| Ok(validate(connection, Some(&root))))??;
            Ok(())
        })
    }
    /// Read only the original proof selected by a retained object reference.
    /// # Errors
    /// Refuses over-limit, substituted or malformed encrypted records and database errors.
    pub fn reach_provenance_proof(
        &self,
        root: &str,
        hash: &str,
    ) -> Result<Option<ProvenanceAuthority>, StorageError> {
        let proof: Option<ProvenanceAuthority> =
            self.read_reach_original(&proof_key(hash)?, MAX_PROOF_BYTES)?;
        if let Some(proof) = &proof {
            proof.validate()?;
            if proof.proof_hash != hash
                || proof.authority.publication.record.body.account_anchor != root
            {
                return Err(invalid());
            }
        }
        Ok(proof)
    }
    /// Read immutable original signer metadata without fetching another proof.
    /// # Errors
    /// Refuses invalid selectors, over-limit metadata and storage errors.
    pub fn reach_provenance_reference(
        &self,
        kind: ObjectKind,
        hash: &str,
    ) -> Result<Option<SignerReference>, StorageError> {
        let reference: Option<SignerReference> =
            self.read_reach_original(&reference_key(kind, hash)?, 2048)?;
        if let Some(reference) = &reference {
            reference.validate()?;
            if reference.object_kind != kind || reference.object_hash != hash {
                return Err(invalid());
            }
        }
        Ok(reference)
    }
    /// Bounded selector metadata for local proof retention/collection; never current authority.
    /// # Errors
    /// Refuses excess references, malformed metadata and storage errors.
    pub fn reach_provenance_references(&self) -> Result<Vec<SignerReference>, StorageError> {
        let mut references = Vec::new();
        self.visit_reach_keys(REFERENCES, wire::MAX_SIGNER_REFERENCES, |key| {
            let reference: SignerReference =
                self.read_reach_original(key, 2048)?.ok_or_else(invalid)?;
            reference.validate()?;
            if reference_key(reference.object_kind, &reference.object_hash)? != key {
                return Err(invalid());
            }
            references.push(reference);
            Ok(())
        })?;
        references.sort_by(|left, right| left.order_key().cmp(&right.order_key()));
        Ok(references)
    }
    /// Bounded proof identifiers; proof bodies remain in their separately encrypted records.
    /// # Errors
    /// Refuses excess objects, invalid identifiers and storage errors.
    pub fn reach_provenance_proof_hashes(&self) -> Result<Vec<String>, StorageError> {
        let mut hashes = Vec::new();
        self.visit_reach_keys(PROOFS, wire::MAX_PROVENANCE_OBJECTS, |key| {
            let hash = key.strip_prefix(PROOFS).ok_or_else(invalid)?;
            digest(hash)?;
            hashes.push(hash.to_owned());
            Ok(())
        })?;
        Ok(hashes)
    }
    fn visit_reach_keys(
        &self,
        prefix: &str,
        limit: usize,
        mut visit: impl FnMut(&str) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let mut after = String::new();
        let mut count = 0_usize;
        loop {
            let keys = self.actor_state_key_page_after(prefix, &after, 128)?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                count += 1;
                if count > limit {
                    return Err(StorageError::SegmentResourceCapacity {
                        limit: wire::MAX_PROVENANCE_BYTES,
                    });
                }
                visit(&key)?;
                after = key;
            }
        }
        Ok(())
    }
    fn read_reach_original<T: DeserializeOwned + Serialize>(
        &self,
        key: &str,
        limit: usize,
    ) -> Result<Option<T>, StorageError> {
        let value: Option<(usize, Option<Vec<u8>>)> = self.connection.query_row(
            "SELECT length(CAST(state_json AS BLOB)),CASE WHEN length(CAST(state_json AS BLOB))<=?2 THEN state_json ELSE NULL END FROM runtime_actor_state WHERE state_kind=?1", params![key, limit], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let Some((length, bytes)) = value else {
            return Ok(None);
        };
        if length > limit {
            return Err(StorageError::SegmentResourceCapacity { limit });
        }
        Ok(Some(wire::decode(&bytes.ok_or_else(invalid)?, limit)?))
    }
    fn put_reach_original<T: Serialize + DeserializeOwned + PartialEq>(
        &self,
        key: &str,
        object: &T,
        limit: usize,
    ) -> Result<(), StorageError> {
        let bytes = ramflux_protocol::canonical_json_bytes(object)?;
        if bytes.len() > limit {
            return Err(StorageError::SegmentResourceCapacity { limit });
        }
        if let Some(old) = self.read_reach_original::<T>(key, limit)? {
            if old != *object {
                return Err(invalid());
            }
            return Ok(());
        }
        self.connection.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            params![key, bytes],
        )?;
        Ok(())
    }
}

mod validation;
pub(super) use validation::validate;

#[cfg(test)]
mod tests;
