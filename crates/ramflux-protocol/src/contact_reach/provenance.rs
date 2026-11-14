// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Content-addressed historical signer evidence, never current permission authority.
use super::{
    HistoricalCustodian, OPERATION_HASH_DOMAIN, STATE_CONTENT_DOMAIN, StateManifest, StatePage,
    StateRecord, digest, invalid, safe,
};
use crate::{
    ProtocolError,
    custody::{self, CustodyAuthority},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_PROVENANCE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PROVENANCE_OBJECTS: usize = 4096;
pub const MAX_SIGNER_REFERENCES: usize = 4 * 8192;
pub const MAX_REACH_STAGING_BYTES: usize = 160 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Admission,
    GroupRoster,
    Policy,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerReference {
    pub object_hash: String,
    pub object_kind: ObjectKind,
    pub authority_head_hash: String,
    pub master_certificate_hash: String,
    pub proof_hash: String,
}
impl SignerReference {
    #[must_use]
    pub fn order_key(&self) -> (ObjectKind, &str) {
        (self.object_kind, &self.object_hash)
    }
    /// # Errors
    /// Refuses invalid selectors and oversized metadata.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for value in [
            &self.object_hash,
            &self.authority_head_hash,
            &self.master_certificate_hash,
            &self.proof_hash,
        ] {
            digest(value)?;
        }
        if crate::canonical_json_bytes(self)?.len() > 2048 {
            return Err(invalid("signer reference capacity"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceAuthority {
    pub proof_hash: String,
    pub authority: CustodyAuthority,
    pub custodian_history: Vec<HistoricalCustodian>,
}
impl ProvenanceAuthority {
    /// Hash the full original native tuple and explicit historical closure.
    /// # Errors
    /// Refuses malformed, unordered, duplicate or over-limit native closure metadata.
    pub fn content_hash(&self) -> Result<String, ProtocolError> {
        #[derive(Serialize)]
        #[serde(rename_all = "snake_case")]
        enum Kind {
            CustodyAuthority,
        }
        #[derive(Serialize)]
        struct Input<'a> {
            kind: Kind,
            authority: &'a CustodyAuthority,
            custodian_history: &'a [HistoricalCustodian],
        }
        let mut previous: Option<&str> = None;
        if self.custodian_history.len() > 64 {
            return Err(invalid("historical custodian count"));
        }
        for entry in &self.custodian_history {
            digest(&entry.record_hash)?;
            if previous.is_some_and(|old| old >= entry.record_hash.as_str())
                || custody::object_hash(&entry.authority.publication.record)? != entry.record_hash
            {
                return Err(invalid("historical custodian order or selector"));
            }
            previous = Some(&entry.record_hash);
        }
        let input = Input {
            kind: Kind::CustodyAuthority,
            authority: &self.authority,
            custodian_history: &self.custodian_history,
        };
        if crate::canonical_json_bytes(&input)?.len() > 1024 * 1024 {
            return Err(invalid("historical native evidence capacity"));
        }
        custody::framed_hash(OPERATION_HASH_DOMAIN, &input)
    }
    /// Count distinct embedded native records separately from proof-bundle count.
    /// # Errors
    /// Propagates exact native whole-envelope hashing failures.
    pub fn native_hashes(&self) -> Result<BTreeSet<String>, ProtocolError> {
        let mut hashes = BTreeSet::new();
        for authority in std::iter::once(&self.authority)
            .chain(self.custodian_history.iter().map(|entry| &entry.authority))
        {
            hashes.insert(custody::object_hash(&authority.publication.record)?);
            if let Some(human) = &authority.custodian_publication {
                hashes.insert(custody::object_hash(&human.record)?);
            }
        }
        Ok(hashes)
    }
    /// # Errors
    /// Refuses a substituted proof or malformed exact native closure.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        digest(&self.proof_hash)?;
        if self.content_hash()? != self.proof_hash {
            return Err(invalid("historical proof hash mismatch"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    ReachProvenance,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub kind: ProvenanceKind,
    pub version: u32,
    pub account_anchor: String,
    pub revision: u64,
    pub state_hash: String,
    pub signers: Vec<SignerReference>,
    pub authorities: Vec<ProvenanceAuthority>,
}
impl Provenance {
    /// Verify exact catalogue closure and full manifest-bound content identity.
    /// This checks structural integrity, never native cryptographic authority.
    /// # Errors
    /// Refuses missing/extra/substituted proofs, counts, selectors and byte/hash mismatches.
    pub fn verify(
        &self,
        manifest: &StateManifest,
        pages: &[StatePage],
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        let signers = page_signers(pages)?;
        if self.account_anchor != manifest.account_anchor
            || self.revision != manifest.revision
            || self.state_hash != manifest.state_hash
            || self.signers != signers
            || u64::try_from(self.authorities.len()).ok() != Some(manifest.provenance_count)
            || u64::try_from(crate::canonical_json_bytes(self)?.len()).ok()
                != Some(manifest.provenance_bytes)
            || custody::framed_hash(STATE_CONTENT_DOMAIN, self)? != manifest.provenance_hash
        {
            return Err(invalid("historical catalogue manifest mismatch"));
        }
        Ok(())
    }
    /// # Errors
    /// Refuses noncanonical ordering, incomplete native selectors or unbounded storage.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        digest(&self.account_anchor)?;
        digest(&self.state_hash)?;
        safe(self.revision)?;
        if self.version != 1
            || self.signers.len() > MAX_SIGNER_REFERENCES
            || self.authorities.len() > MAX_PROVENANCE_OBJECTS
            || crate::canonical_json_bytes(self)?.len() > MAX_PROVENANCE_BYTES
        {
            return Err(invalid("historical catalogue capacity"));
        }
        let mut previous = None;
        let mut required = BTreeSet::new();
        for signer in &self.signers {
            signer.validate()?;
            if previous.is_some_and(|old| old >= signer.order_key()) {
                return Err(invalid("historical signer order"));
            }
            previous = Some(signer.order_key());
            required.insert(signer.proof_hash.as_str());
        }
        let mut previous: Option<&str> = None;
        let mut native_records = BTreeSet::new();
        for proof in &self.authorities {
            proof.validate()?;
            if previous.is_some_and(|old| old >= proof.proof_hash.as_str())
                || !required.remove(proof.proof_hash.as_str())
            {
                return Err(invalid("historical proof order or unsolicited proof"));
            }
            previous = Some(&proof.proof_hash);
            native_records.extend(proof.native_hashes()?);
            for signer in
                self.signers.iter().filter(|reference| reference.proof_hash == proof.proof_hash)
            {
                if proof.authority.publication.record.body.account_anchor != self.account_anchor
                    || signer.authority_head_hash
                        != custody::object_hash(&proof.authority.publication.record)?
                    || signer.master_certificate_hash
                        != custody::object_hash(
                            &proof.authority.publication.record.body.master_certificate,
                        )?
                {
                    return Err(invalid("historical native selector mismatch"));
                }
            }
        }
        if !required.is_empty() || native_records.len() > MAX_PROVENANCE_OBJECTS {
            return Err(invalid("historical catalogue incomplete or native capacity"));
        }
        Ok(())
    }
}

/// Original signed objects in canonical record/nested-field occurrence order.
/// # Errors
/// Propagates original signed-object hashing failures.
pub fn record_signers(record: &StateRecord) -> Result<Vec<SignerReference>, ProtocolError> {
    let mut out = Vec::new();
    let mut admission =
        |signed: &custody::Envelope<super::Admission>| -> Result<(), ProtocolError> {
            out.push(SignerReference {
                object_hash: custody::framed_hash(OPERATION_HASH_DOMAIN, signed)?,
                object_kind: ObjectKind::Admission,
                authority_head_hash: signed.body.authority_head_hash.clone(),
                master_certificate_hash: signed.body.master_certificate_hash.clone(),
                proof_hash: String::new(),
            });
            Ok(())
        };
    match record {
        StateRecord::Policy { update, .. } => out.push(SignerReference {
            object_hash: custody::framed_hash(OPERATION_HASH_DOMAIN, update)?,
            object_kind: ObjectKind::Policy,
            authority_head_hash: update.body.authority_head_hash.clone(),
            master_certificate_hash: update.body.master_certificate_hash.clone(),
            proof_hash: String::new(),
        }),
        StateRecord::AdmissionMeta { last_update: Some(update), .. }
        | StateRecord::Grant { update, .. }
        | StateRecord::Block { update, .. }
        | StateRecord::Decline { update, .. } => admission(update)?,
        StateRecord::Retirement { update, group_floor, .. } => {
            admission(update)?;
            if let Some(floor) = group_floor {
                if let Some(grant) = &floor.grant {
                    admission(grant)?;
                }
                if let Some(control) = &floor.block_control {
                    admission(control)?;
                }
                if let Some(header) = &floor.roster_header {
                    out.push(SignerReference {
                        object_hash: custody::framed_hash(OPERATION_HASH_DOMAIN, header.as_ref())?,
                        object_kind: ObjectKind::GroupRoster,
                        authority_head_hash: header.body.authority_head_hash.clone(),
                        master_certificate_hash: header.body.master_certificate_hash.clone(),
                        proof_hash: String::new(),
                    });
                }
            }
        }
        _ => {}
    }
    Ok(out)
}

/// Check each reference occurs on the first page containing its exact original signed object.
/// # Errors
/// Refuses missing, extra, conflicting or wrongly placed references.
pub fn page_signers(pages: &[StatePage]) -> Result<Vec<SignerReference>, ProtocolError> {
    let mut all = BTreeMap::new();
    for page in pages {
        if page.signers.len() > 4 * 32
            || !page.signers.windows(2).all(|pair| {
                pair.first().zip(pair.get(1)).is_some_and(|(a, b)| a.order_key() < b.order_key())
            })
        {
            return Err(invalid("page signer order or capacity"));
        }
        let mut expected = BTreeMap::new();
        for record in &page.records {
            for reference in record_signers(record)? {
                let key = (reference.object_kind, reference.object_hash.clone());
                if !all.contains_key(&key) {
                    expected.insert(key, reference);
                }
            }
        }
        if expected.len() != page.signers.len() {
            return Err(invalid("page signer closure"));
        }
        for signer in &page.signers {
            signer.validate()?;
            let key = (signer.object_kind, signer.object_hash.clone());
            let selected =
                expected.remove(&key).ok_or_else(|| invalid("unsolicited page signer"))?;
            if selected.authority_head_hash != signer.authority_head_hash
                || selected.master_certificate_hash != signer.master_certificate_hash
            {
                return Err(invalid("page signer selector mismatch"));
            }
            all.insert(key, signer.clone());
        }
    }
    Ok(all.into_values().collect())
}

#[cfg(test)]
mod tests;
