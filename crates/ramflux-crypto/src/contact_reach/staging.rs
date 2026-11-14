// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-owned encrypted proof staging; original native tuples are decrypted one at a time.
use super::{CryptoError, reject, wire};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use std::collections::BTreeMap;
use wire::{
    ProvenanceAuthority, ProvenanceDigest, ProvenanceIdentity, SignerReference, StateManifest,
};
struct SealedProof {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}
struct Scope {
    root: String,
    revision: u64,
    state_hash: String,
}
impl Scope {
    fn aad(&self, hash: &str) -> Result<Vec<u8>, CryptoError> {
        Ok(ramflux_protocol::canonical_json_bytes(&(
            &self.root,
            self.revision,
            &self.state_hash,
            hash,
        ))?)
    }
}
pub struct ProvenanceStageBuilder {
    scope: Scope,
    signers: Vec<SignerReference>,
    key: zeroize::Zeroizing<[u8; 32]>,
    proofs: BTreeMap<String, SealedProof>,
    digest: Option<ProvenanceDigest>,
    bytes: usize,
    valid: bool,
}
/// Complete catalogue with ephemeral encryption keys; never serialized into backups or authority.
pub struct EncryptedProvenanceStage {
    scope: Scope,
    signers: Vec<SignerReference>,
    key: zeroize::Zeroizing<[u8; 32]>,
    proofs: BTreeMap<String, SealedProof>,
    identity: ProvenanceIdentity,
    bytes: usize,
}
impl ProvenanceStageBuilder {
    /// Start a private stage using the complete canonical page references.
    /// # Errors
    /// Refuses malformed metadata, reference limits, RNG and canonical serialization errors.
    pub fn new(
        root: &str,
        revision: u64,
        state_hash: &str,
        signers: Vec<SignerReference>,
    ) -> Result<Self, CryptoError> {
        let digest = ProvenanceDigest::new(root, revision, state_hash, signers.clone())?;
        let bytes = ramflux_protocol::canonical_json_bytes(&signers)?
            .len()
            .checked_add(root.len() + state_hash.len() + 40)
            .ok_or_else(|| reject("provenance staging capacity"))?;
        Ok(Self {
            scope: Scope { root: root.into(), revision, state_hash: state_hash.into() },
            signers,
            key: zeroize::Zeroizing::new(crate::random_32()?),
            proofs: BTreeMap::new(),
            digest: Some(digest),
            bytes,
            valid: true,
        })
    }
    /// Validate/hash and encrypt one bounded proof, releasing its plaintext before the next fetch.
    /// # Errors
    /// A failed push invalidates the stage; no partial transfer can finish.
    pub fn push(&mut self, proof: &ProvenanceAuthority) -> Result<(), CryptoError> {
        if !self.valid {
            return Err(reject("provenance staging invalid"));
        }
        self.valid = false;
        self.digest.as_mut().ok_or_else(|| reject("provenance digest absent"))?.push(proof)?;
        let plaintext = zeroize::Zeroizing::new(ramflux_protocol::canonical_json_bytes(proof)?);
        let bytes = self
            .bytes
            .checked_add(plaintext.len() + proof.proof_hash.len() + 28)
            .filter(|bytes| *bytes <= wire::MAX_REACH_STAGING_BYTES)
            .ok_or_else(|| reject("provenance staging capacity"))?;
        let mut nonce = [0_u8; 12];
        for (out, input) in nonce.iter_mut().zip(crate::random_32()?.iter()) {
            *out = *input;
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| reject("provenance staging key"))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: &plaintext, aad: &self.scope.aad(&proof.proof_hash)? },
            )
            .map_err(|_| reject("provenance staging encryption"))?;
        if self.proofs.insert(proof.proof_hash.clone(), SealedProof { nonce, ciphertext }).is_some()
        {
            return Err(reject("duplicate staged provenance"));
        }
        self.bytes = bytes;
        self.valid = true;
        Ok(())
    }
    /// Close the exact complete identity before any staged proof is exposed to a consumer.
    /// # Errors
    /// Refuses incomplete, failed or oversized stages.
    pub fn finish(mut self) -> Result<EncryptedProvenanceStage, CryptoError> {
        if !self.valid {
            return Err(reject("provenance staging invalid"));
        }
        let identity =
            self.digest.take().ok_or_else(|| reject("provenance digest absent"))?.finish()?;
        self.bytes = self
            .bytes
            .checked_add(identity.hash.len() + 16)
            .filter(|bytes| *bytes <= wire::MAX_REACH_STAGING_BYTES)
            .ok_or_else(|| reject("provenance staging capacity"))?;
        Ok(EncryptedProvenanceStage {
            scope: self.scope,
            signers: self.signers,
            key: self.key,
            proofs: self.proofs,
            identity,
            bytes: self.bytes,
        })
    }
}
impl EncryptedProvenanceStage {
    #[must_use]
    pub fn staged_bytes(&self) -> usize {
        self.bytes
    }
    #[must_use]
    pub fn identity(&self) -> &ProvenanceIdentity {
        &self.identity
    }
    #[must_use]
    pub fn signers(&self) -> &[SignerReference] {
        &self.signers
    }
    pub fn proof_hashes(&self) -> impl Iterator<Item = &str> {
        self.proofs.keys().map(String::as_str)
    }
    /// # Errors
    /// Refuses another account/revision/state or a different full catalogue identity.
    pub fn verify_manifest(&self, manifest: &StateManifest) -> Result<(), CryptoError> {
        if self.scope.root != manifest.account_anchor
            || self.scope.revision != manifest.revision
            || self.scope.state_hash != manifest.state_hash
        {
            return Err(reject("staged provenance scope mismatch"));
        }
        self.identity.verify_manifest(manifest)?;
        Ok(())
    }
    /// Read only a catalogue member, decrypting at most one bounded native proof.
    /// # Errors
    /// Refuses missing/swapped/corrupt ciphertext, malformed tuples or altered content hashes.
    pub fn read_proof(&self, hash: &str) -> Result<ProvenanceAuthority, CryptoError> {
        let proof =
            self.proofs.get(hash).ok_or_else(|| reject("staged provenance member absent"))?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| reject("provenance staging key"))?;
        let bytes = zeroize::Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&proof.nonce),
                    Payload { msg: &proof.ciphertext, aad: &self.scope.aad(hash)? },
                )
                .map_err(|_| reject("provenance staging authentication"))?,
        );
        let proof: ProvenanceAuthority = wire::decode(&bytes, 1024 * 1024 + 1024)?;
        proof.validate()?;
        if proof.proof_hash != hash {
            return Err(reject("staged provenance content mismatch"));
        }
        Ok(proof)
    }
    /// Authenticate each original object without materializing an all-proof plaintext catalogue.
    /// # Errors
    /// Refuses missing references, invalid historical tuples, roles or original signatures.
    pub fn verify_originals(&self, records: &[wire::StateRecord]) -> Result<(), CryptoError> {
        super::provenance::verify_records_with_reader(records, self)
    }
}
impl super::provenance::HistoricalProofReader for EncryptedProvenanceStage {
    fn signers(&self) -> &[SignerReference] {
        &self.signers
    }
    fn read(&self, hash: &str) -> Result<ProvenanceAuthority, CryptoError> {
        self.read_proof(hash)
    }
}

#[cfg(test)]
mod tests;
