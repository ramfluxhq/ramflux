// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact retained own-copy proof, separate from the preferred native body version.
use super::FullDirectHistory;
use crate::StorageError;
use prost::Message as _;
use ramflux_crypto::native_origin::OwnSentAttestation;
use sha2::{Digest as _, Sha256};
use std::io::{Read as _, Write};
use zeroize::{Zeroize as _, Zeroizing};

const MAGIC: &[u8; 4] = b"ROP1";
const COPY_LIMIT: usize = 256;
const MAX_OWNERS: usize = 8;
const OWNER_LIMIT: usize = 64;
const JSON_LIMIT: usize = super::super::raw_inner::MAX_HISTORY_CONTAINER_BYTES;
pub const FULL_RAW_OWN_PROOF_LIMIT: usize = 20
    + COPY_LIMIT
    + JSON_LIMIT
    + super::FULL_DIRECT_HISTORY_LIMIT
    + MAX_OWNERS * (4 + OWNER_LIMIT);

/// Original raw proof data. Its validity grants no replay, callback or fresh author authority.
pub struct FullRawOwnProof {
    source_copy: Zeroizing<String>,
    history: FullDirectHistory,
    exact_json: Zeroizing<Vec<u8>>,
    source_owners: Vec<Zeroizing<String>>,
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
impl FullRawOwnProof {
    /// Retain the original raw JSON and a verified own-copy history, without using the
    /// preferred body projection as a substitute for an independent contributor's proof.
    /// # Errors
    /// Refuses another proof class, changed original copy locator, missing evidence or bounds.
    pub fn from_parts(
        own: &str,
        source_copy: String,
        history: FullDirectHistory,
        exact_json: Vec<u8>,
        source_owners: Vec<String>,
    ) -> Result<Self, StorageError> {
        let value = Self {
            source_copy: Zeroizing::new(source_copy),
            history,
            exact_json: Zeroizing::new(exact_json),
            source_owners: source_owners.into_iter().map(Zeroizing::new).collect(),
        };
        value.validate(own)?;
        Ok(value)
    }
    fn validate(&self, own: &str) -> Result<(), StorageError> {
        if self.source_copy.len() > COPY_LIMIT
            || self.exact_json.is_empty()
            || self.exact_json.len() > JSON_LIMIT
        {
            return Err(invalid());
        }
        let version = self.history.verify(own)?;
        let original = ramflux_protocol::encode_base64url(&version.original().id);
        let current = ramflux_protocol::encode_base64url(&version.current().id);
        if self.source_copy.as_str() != format!("routed/own-sent-attestation/{original}/{current}")
        {
            return Err(invalid());
        }
        let raw: OwnSentAttestation =
            ramflux_protocol::parse_i_json_secret(&self.exact_json).map_err(|_| invalid())?;
        let expected = self.history.own_attestation().ok_or_else(invalid)?;
        let mut outer =
            ramflux_protocol::message::Inner::decode(expected.exact_outer_inner.as_slice())
                .map_err(|_| invalid())?;
        outer.body.zeroize();
        let enclosing =
            ramflux_protocol::encode_base64url(&outer.identity.as_ref().ok_or_else(invalid)?.id);
        let carrier = format!("copy:event:{enclosing}");
        let allowed = [original.as_str(), current.as_str(), enclosing.as_str(), carrier.as_str()];
        if self.source_owners.is_empty()
            || self.source_owners.len() > MAX_OWNERS
            || !self.source_owners.iter().any(|owner| owner.as_str() == original)
            || self
                .source_owners
                .iter()
                .any(|owner| owner.len() > OWNER_LIMIT || !allowed.contains(&owner.as_str()))
            || self
                .source_owners
                .iter()
                .zip(self.source_owners.iter().skip(1))
                .any(|(left, right)| left.as_str() >= right.as_str())
        {
            return Err(invalid());
        }

        // The closed typed comparison checks every unsigned historical field too.
        // Exact enclosing signed/native bytes and original JSON are retained unchanged.
        if super::direct_history::encode_state(&raw)?.as_slice()
            != super::direct_history::encode_state(expected)?.as_slice()
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Original source locator, never the destination's opaque local storage locator.
    #[must_use]
    pub fn source_copy_id(&self) -> &str {
        &self.source_copy
    }
    /// The exact original JSON digest remains independent of its typed transfer framing.
    #[must_use]
    pub fn raw_digest(&self) -> [u8; 32] {
        Sha256::digest(self.exact_json.as_slice()).into()
    }
    /// Original bytes stay inert and must retain every erasure owner on installation.
    #[must_use]
    pub fn exact_json(&self) -> &[u8] {
        &self.exact_json
    }
    /// A distinct exact enclosing proof gets a distinct variant, even at one source locator.
    /// # Errors
    /// Refuses invalid evidence or framing writes.
    pub fn variant_id(&self, own: &str) -> Result<String, StorageError> {
        let mut output = ProofHash(blake3::Hasher::new());
        output.0.update(b"ramflux.pairing.full.raw-own-proof.v1\0");
        self.write(own, &mut output)?;
        Ok(ramflux_protocol::encode_base64url(output.0.finalize().as_bytes()))
    }
    /// The verified original/current pair is data ownership, never mutation permission.
    /// # Errors
    /// Refuses another account or invalid native proof.
    pub fn native_identities(
        &self,
        own: &str,
    ) -> Result<
        (ramflux_protocol::message::EventIdentity, ramflux_protocol::message::EventIdentity),
        StorageError,
    > {
        self.validate(own)?;
        let version = self.history.verify(own)?;
        Ok((version.original().clone(), version.current().clone()))
    }
    /// Every verified native/enclosing owner participates in erasure, including the
    /// original source bindings. The enclosing carrier is not the native author.
    /// # Errors
    /// Refuses malformed proof or another account.
    pub fn erasure_owners(&self, own: &str) -> Result<Vec<String>, StorageError> {
        self.validate(own)?;
        let version = self.history.verify(own)?;
        let proof = self.history.own_attestation().ok_or_else(invalid)?;
        let mut outer =
            ramflux_protocol::message::Inner::decode(proof.exact_outer_inner.as_slice())
                .map_err(|_| invalid())?;
        outer.body.zeroize();
        let enclosing =
            ramflux_protocol::encode_base64url(&outer.identity.as_ref().ok_or_else(invalid)?.id);
        let mut owners = vec![
            ramflux_protocol::encode_base64url(&version.original().id),
            ramflux_protocol::encode_base64url(&version.current().id),
            format!("copy:event:{enclosing}"),
            enclosing,
        ];
        owners.extend(self.source_owners.iter().map(|owner| owner.to_string()));
        owners.sort_unstable();
        owners.dedup();
        Ok(owners)
    }

    /// Write one fixed-bounded frame; metadata and native part caps remain separate.
    /// # Errors
    /// Refuses invalid evidence, an oversized part or output failure.
    pub fn write(&self, own: &str, output: &mut impl Write) -> Result<(), StorageError> {
        self.validate(own)?;
        let mut native = Zeroizing::new(Vec::new());
        self.history.write(&mut *native)?;
        output.write_all(MAGIC)?;
        write_part(output, self.source_copy.as_bytes())?;
        write_part(output, &native)?;
        write_part(output, &self.exact_json)?;
        output.write_all(
            &u32::try_from(self.source_owners.len()).map_err(|_| invalid())?.to_be_bytes(),
        )?;
        for owner in &self.source_owners {
            write_part(output, owner.as_bytes())?;
        }
        Ok(())
    }
    /// Read under an independently authenticated account, never an embedded account claim.
    /// # Errors
    /// Refuses malformed lengths, trailing bytes, wrong proof/context or altered source JSON.
    pub fn read(mut bytes: &[u8], own: &str) -> Result<Self, StorageError> {
        if bytes.len() > FULL_RAW_OWN_PROOF_LIMIT || take(&mut bytes, MAGIC.len())? != MAGIC {
            return Err(invalid());
        }
        let source_copy =
            std::str::from_utf8(read_part(&mut bytes, COPY_LIMIT)?).map_err(|_| invalid())?;
        let history =
            FullDirectHistory::read(read_part(&mut bytes, super::FULL_DIRECT_HISTORY_LIMIT)?, own)?;
        let exact_json = read_part(&mut bytes, JSON_LIMIT)?;
        let count =
            u32::from_be_bytes(take(&mut bytes, 4)?.try_into().map_err(|_| invalid())?) as usize;
        if count == 0 || count > MAX_OWNERS {
            return Err(invalid());
        }
        let mut owners = Vec::new();
        for _ in 0..count {
            owners.push(
                std::str::from_utf8(read_part(&mut bytes, OWNER_LIMIT)?)
                    .map_err(|_| invalid())?
                    .to_owned(),
            );
        }
        if !bytes.is_empty() {
            return Err(invalid());
        }
        Self::from_parts(own, source_copy.to_owned(), history, exact_json.to_vec(), owners)
    }
}
struct ProofHash(blake3::Hasher);
impl Write for ProofHash {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn write_part(output: &mut impl Write, bytes: &[u8]) -> Result<(), StorageError> {
    output.write_all(&u32::try_from(bytes.len()).map_err(|_| invalid())?.to_be_bytes())?;
    output.write_all(bytes)?;
    Ok(())
}
fn take<'a>(bytes: &mut &'a [u8], size: usize) -> Result<&'a [u8], StorageError> {
    let value = bytes.get(..size).ok_or_else(invalid)?;
    *bytes = bytes.get(size..).ok_or_else(invalid)?;
    Ok(value)
}
fn read_part<'a>(bytes: &mut &'a [u8], limit: usize) -> Result<&'a [u8], StorageError> {
    let mut length = [0_u8; 4];
    take(bytes, 4)?.read_exact(&mut length)?;
    let size = u32::from_be_bytes(length) as usize;
    if size == 0 || size > limit {
        return Err(invalid());
    }
    take(bytes, size)
}
