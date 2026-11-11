// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Data-only grants and reconnect proof bodies. Neither carries a manifest hash or signing grant.
use super::{
    DataBinding, DeviceRef, PairingWire, Result, WireError, b32, budget, reference, require,
};
use crate::custody::pairing::context_v3::{DataSelectionV3, TranscriptV3};
use serde::{Deserialize, Serialize};

fn header(schema: &str, version: u32, name: &str) -> Result<()> {
    require(schema == format!("ramflux.pairing.full_transfer.{name}.v1") && version == 1, "schema")
}
fn signature(value: &str) -> Result<()> {
    require(value.len() == 86, "signature")?;
    let bytes = crate::decode_base64url(value).map_err(|_| WireError::Field("signature"))?;
    require(bytes.len() == 64 && crate::encode_base64url(bytes) == value, "signature")
}
fn role(value: &str) -> Result<()> {
    require(matches!(value, "initiator" | "responder"), "role")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchKeys {
    pub source: String,
    pub destination: String,
}
impl BranchKeys {
    /// Validate two distinct canonical public keys without granting possession or authority.
    /// # Errors
    /// Refuses malformed or reflected source/destination keys.
    pub fn validate(&self) -> Result<()> {
        b32(&self.source, "branch_key")?;
        b32(&self.destination, "branch_key")?;
        require(self.source != self.destination, "distinct_branch_keys")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataGrant {
    pub schema: String,
    pub version: u32,
    pub transfer_id: String,
    pub node_id: String,
    pub source_ref: DeviceRef,
    pub destination_ref: DeviceRef,
    pub branch_keys: BranchKeys,
    pub opaque_commitment: String,
    pub expires_at: u64,
}
impl PairingWire for DataGrant {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "data_grant")?;
        b32(&self.transfer_id, "transfer_id")?;
        b32(&self.opaque_commitment, "opaque_commitment")?;
        super::super::text(&self.node_id, true, "node_id")?;
        super::super::integer(self.expires_at, "expires_at")?;
        reference(&self.source_ref)?;
        reference(&self.destination_ref)?;
        self.branch_keys.validate()?;
        require(
            self.source_ref != self.destination_ref
                && self.source_ref.account_anchor == self.destination_ref.account_anchor,
            "grant_context",
        )?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub transcript_hash: String,
    pub grant: DataGrant,
    pub source_signature: String,
    pub destination_signature: String,
}
impl PairingWire for LeaseRequest {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "lease_request")?;
        b32(&self.invitation_id, "invitation_id")?;
        b32(&self.transcript_hash, "transcript_hash")?;
        super::super::integer(self.issuer_seq, "issuer_seq")?;
        require(self.issuer_seq > 0, "issuer_seq")?;
        self.grant.validate()?;
        signature(&self.source_signature)?;
        signature(&self.destination_signature)?;
        budget(self, Self::LIMIT)
    }
}
impl LeaseRequest {
    /// Both original branches sign the same grant, role label and frozen invitation/TH scope.
    /// # Errors
    /// Refuses malformed fields or a role outside the two original endpoints.
    pub fn signing_bytes(&self, signer_role: &str) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Body<'a> {
            role: &'a str,
            invitation_id: &'a str,
            issuer_seq: u64,
            transcript_hash: &'a str,
            grant: &'a DataGrant,
        }
        self.validate()?;
        role(signer_role)?;
        crate::custody::signing_bytes(
            "ramflux.identity.transfer.data_grant.full.v1",
            &Body {
                role: signer_role,
                invitation_id: &self.invitation_id,
                issuer_seq: self.issuer_seq,
                transcript_hash: &self.transcript_hash,
                grant: &self.grant,
            },
        )
        .map_err(|_| WireError::Json)
    }
    /// Check local SAS bindings before any branch signs or a node-issued lease is accepted.
    /// This does not substitute for actual local confirmation and peer confirmation MACs.
    /// # Errors
    /// Refuses changed identities, branch keys, invitation, TH or a partial transfer selection.
    pub fn bind_transcript(&self, transcript: &TranscriptV3, expected_th: &str) -> Result<()> {
        self.validate()?;
        transcript.validate()?;
        b32(expected_th, "transcript_hash")?;
        let a = &transcript.initiator;
        let b = &transcript.responder;
        let common = &a.common;
        require(
            common.purpose == "primary_transfer"
                && matches!(&common.data_selection, DataSelectionV3::FullAccountDataV1(_))
                && common.invitation_id == self.invitation_id
                && common.issuer_seq == self.issuer_seq
                && common.transfer_id.as_deref() == Some(self.grant.transfer_id.as_str())
                && expected_th == self.transcript_hash
                && a.device_ref == self.grant.source_ref
                && b.device_ref == self.grant.destination_ref
                && a.branch_key == self.grant.branch_keys.source
                && b.branch_key == self.grant.branch_keys.destination,
            "lease_context",
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataLease {
    pub schema: String,
    pub version: u32,
    pub lease_id: String,
    pub grant: DataGrant,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl PairingWire for DataLease {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "data_lease")?;
        b32(&self.lease_id, "lease_id")?;
        self.grant.validate()?;
        for value in [self.issued_at, self.expires_at] {
            super::super::integer(value, "lease_time")?;
        }
        require(
            self.expires_at > self.issued_at
                && self.expires_at <= self.grant.expires_at
                && self.expires_at - self.issued_at <= super::LEASE_SECONDS,
            "lease_time",
        )?;
        budget(self, Self::LIMIT)
    }
}
impl DataLease {
    /// # Errors
    /// Refuses malformed lease fields before a trusted node signs them.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        crate::custody::signing_bytes("ramflux.identity.transfer.data_lease.full.v1", self)
            .map_err(|_| WireError::Json)
    }
    /// # Errors
    /// Expired data leases cannot restore confirmations, sessions or relay tokens.
    pub fn require_live(&self, now: u64) -> Result<()> {
        self.validate()?;
        require(now >= self.issued_at && now < self.expires_at, "LeaseExpired")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeProof {
    pub schema: String,
    pub version: u32,
    pub lease_id: String,
    pub boot_id: String,
    pub nonce: String,
    pub role: String,
    pub hpke_keys: BranchKeys,
    pub epoch: String,
}
impl PairingWire for ResumeProof {
    const LIMIT: usize = 4096;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "resume_proof")?;
        for value in [&self.lease_id, &self.boot_id, &self.nonce, &self.epoch] {
            b32(value, "resume_context")?;
        }
        role(&self.role)?;
        self.hpke_keys.validate()?;
        budget(self, Self::LIMIT)
    }
}
impl ResumeProof {
    /// # Errors
    /// Refuses malformed proof scope before signing with the original branch key.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        crate::custody::signing_bytes("ramflux.identity.transfer.resume.full.v1", self)
            .map_err(|_| WireError::Json)
    }
    /// Compare all fresh operands; a role-reflected proof cannot complete the pair.
    /// # Errors
    /// Refuses a changed lease, nonce, boot, epoch or either fresh HPKE key.
    pub fn require_peer(&self, peer: &Self) -> Result<()> {
        self.validate()?;
        peer.validate()?;
        require(
            self.role != peer.role
                && self.lease_id == peer.lease_id
                && self.boot_id == peer.boot_id
                && self.nonce == peer.nonce
                && self.epoch == peer.epoch
                && self.hpke_keys == peer.hpke_keys,
            "resume_context",
        )
    }
}

/// Private opening goes only inside the confirmed SAS control; the serving node sees this hash.
#[must_use]
pub fn opaque_commitment(manifest_hash: &[u8; 32], opening: &[u8; 32]) -> [u8; 32] {
    let mut hash = super::integrity::framed("ramflux.pairing.full.lease.v1");
    hash.update(manifest_hash);
    hash.update(opening);
    *hash.finalize().as_bytes()
}

/// HPKE binding must use the same original branches as the signed grant.
/// # Errors
/// Refuses swapped contexts and requires the original base manifest hash to remain pinned.
pub fn bind_channel(grant: &DataGrant, binding: &DataBinding, opening: &[u8; 32]) -> Result<()> {
    grant.validate()?;
    binding.validate()?;
    let manifest: [u8; 32] = crate::decode_base64url(&binding.manifest_hash)
        .map_err(|_| WireError::Field("manifest_hash"))?
        .try_into()
        .map_err(|_| WireError::Field("manifest_hash"))?;
    require(
        crate::encode_base64url(opaque_commitment(&manifest, opening)) == grant.opaque_commitment
            && grant.transfer_id == binding.transfer_id
            && grant.source_ref == binding.source_ref
            && grant.destination_ref == binding.destination_ref,
        "data_binding",
    )
}

#[cfg(test)]
mod tests;
