// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incremental canonical catalogue identity; only one bounded native proof is needed at a time.
use super::{
    MAX_PROVENANCE_BYTES, MAX_PROVENANCE_OBJECTS, MAX_SIGNER_REFERENCES, ProvenanceAuthority,
    STATE_CONTENT_DOMAIN, SignerReference, StateManifest, digest, invalid, safe,
};
use crate::ProtocolError;
use std::collections::{BTreeMap, BTreeSet};

/// Internal verification result, not an additional wire carrier.
pub struct ProvenanceIdentity {
    pub hash: String,
    pub count: u64,
    pub bytes: u64,
}
impl ProvenanceIdentity {
    /// # Errors
    /// Refuses substituted catalogue identity, transfer length or proof count.
    pub fn verify_manifest(&self, manifest: &StateManifest) -> Result<(), ProtocolError> {
        if self.hash != manifest.provenance_hash
            || self.count != manifest.provenance_count
            || self.bytes != manifest.provenance_bytes
        {
            return Err(invalid("streamed provenance identity mismatch"));
        }
        Ok(())
    }
}
/// Consumes authorities in exact proof-hash order while retaining bounded reference metadata only.
pub struct ProvenanceDigest {
    root: String,
    revision: u64,
    state_hash: String,
    signers: Vec<SignerReference>,
    required: BTreeMap<String, Vec<usize>>,
    previous: Option<String>,
    native: BTreeSet<String>,
    hasher: blake3::Hasher,
    bytes: usize,
    count: u64,
    poisoned: bool,
}
impl ProvenanceDigest {
    /// Begin the exact canonical Provenance preimage; no proof bytes are retained.
    /// # Errors
    /// Refuses malformed selectors, counters, ordering and reference capacity.
    pub fn new(
        root: &str,
        revision: u64,
        state_hash: &str,
        signers: Vec<SignerReference>,
    ) -> Result<Self, ProtocolError> {
        digest(root)?;
        digest(state_hash)?;
        safe(revision)?;
        if signers.len() > MAX_SIGNER_REFERENCES {
            return Err(invalid("streamed signer count"));
        }
        let mut required: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut previous = None;
        for (index, signer) in signers.iter().enumerate() {
            signer.validate()?;
            if previous.is_some_and(|old| old >= signer.order_key()) {
                return Err(invalid("streamed signer order"));
            }
            previous = Some(signer.order_key());
            required.entry(signer.proof_hash.clone()).or_default().push(index);
        }
        let mut value = Self {
            root: root.into(),
            revision,
            state_hash: state_hash.into(),
            signers,
            required,
            previous: None,
            native: BTreeSet::new(),
            hasher: blake3::Hasher::new(),
            bytes: 0,
            count: 0,
            poisoned: false,
        };
        value.hasher.update(STATE_CONTENT_DOMAIN.as_bytes());
        value.hasher.update(&[0]);
        value.append(b"{\"account_anchor\":")?;
        value.append(&crate::canonical_json_bytes(&root)?)?;
        value.append(b",\"authorities\":[")?;
        Ok(value)
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_PROVENANCE_BYTES)
            .ok_or_else(|| invalid("streamed provenance byte capacity"))?;
        self.hasher.update(bytes);
        Ok(())
    }
    /// Authenticate structural closure and hash one original proof, then release its bytes.
    /// Native signature verification remains the historical verifier's separate responsibility.
    /// # Errors
    /// Any failed push poisons this stage; no partial catalogue may finish successfully.
    pub fn push(&mut self, proof: &ProvenanceAuthority) -> Result<(), ProtocolError> {
        if self.poisoned {
            return Err(invalid("streamed provenance stage invalid"));
        }
        self.poisoned = true;
        proof.validate()?;
        if self.previous.as_ref().is_some_and(|previous| previous >= &proof.proof_hash)
            || self.count >= MAX_PROVENANCE_OBJECTS as u64
        {
            return Err(invalid("streamed proof order or capacity"));
        }
        let selected = self
            .required
            .remove(&proof.proof_hash)
            .ok_or_else(|| invalid("unsolicited streamed proof"))?;
        let head = crate::custody::object_hash(&proof.authority.publication.record)?;
        let certificate = crate::custody::object_hash(
            &proof.authority.publication.record.body.master_certificate,
        )?;
        if proof.authority.publication.record.body.account_anchor != self.root {
            return Err(invalid("streamed proof account mismatch"));
        }
        for index in selected {
            let signer = self.signers.get(index).ok_or_else(|| invalid("streamed signer index"))?;
            if signer.authority_head_hash != head || signer.master_certificate_hash != certificate {
                return Err(invalid("streamed native signer mismatch"));
            }
        }
        self.native.extend(proof.native_hashes()?);
        if self.native.len() > MAX_PROVENANCE_OBJECTS {
            return Err(invalid("streamed native capacity"));
        }
        if self.count != 0 {
            self.append(b",")?;
        }
        self.append(&crate::canonical_json_bytes(proof)?)?;
        self.count += 1;
        self.previous = Some(proof.proof_hash.clone());
        self.poisoned = false;
        Ok(())
    }
    /// Finish the identical canonical closed object used by the in-memory reference codec.
    /// # Errors
    /// Refuses a failed stage, missing proofs, serialization failure and total byte overflow.
    pub fn finish(mut self) -> Result<ProvenanceIdentity, ProtocolError> {
        if self.poisoned || !self.required.is_empty() {
            return Err(invalid("streamed provenance incomplete"));
        }
        self.append(b"],\"kind\":\"reach_provenance\",\"revision\":")?;
        self.append(&crate::canonical_json_bytes(&self.revision)?)?;
        self.append(b",\"signers\":")?;
        self.append(&crate::canonical_json_bytes(&self.signers)?)?;
        self.append(b",\"state_hash\":")?;
        self.append(&crate::canonical_json_bytes(&self.state_hash)?)?;
        self.append(b",\"version\":1}")?;
        Ok(ProvenanceIdentity {
            hash: crate::encode_base64url(self.hasher.finalize().as_bytes()),
            count: self.count,
            bytes: u64::try_from(self.bytes).map_err(|_| invalid("streamed provenance bytes"))?,
        })
    }
}
