// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A3.L5 local encrypted-stage columns. This record conveys data-resume trust only.
//! Its caller must first match the encrypted stage to the account's durable stage reference.
use super::{FullResumeTrust, PairingRole, Result};
use crate::{CryptoError, custody::VerifiedNodeRecord};
use ramflux_protocol::custody::{
    DeviceRef, Envelope,
    pairing::{
        PairingWire,
        context_v3::TranscriptV3,
        full_transfer::lease::{DataGrant, DataLease},
    },
};
use zeroize::Zeroizing;

/// Exactly the eight saved operands adopted in A3.L5. No Debug, serde, key or approval flag.
/// Byte columns are bound to a local encrypted stage; never construct this from relay replies.
pub struct FullResumeRecord {
    pub role: PairingRole,
    pub transcript: Zeroizing<Vec<u8>>,
    pub th: [u8; 32],
    pub grant: DataGrant,
    pub lease: Zeroizing<Vec<u8>>,
    pub transfer_id: String,
    pub base_manifest_hash: String,
    pub base_record_hash: String,
}
impl FullResumeTrust {
    /// Prepare the exact local stage columns after both confirmations and native lease checks.
    /// The stage owner commits these before the matching account live-row reference.
    /// # Errors
    /// Refuses a malformed or over-size frozen transcript.
    pub fn local_stage_record(&self) -> Result<FullResumeRecord> {
        Ok(FullResumeRecord {
            role: self.role,
            transcript: Zeroizing::new(self.context.to_wire_bytes()?),
            th: self.th,
            grant: self.grant.clone(),
            lease: self.lease.clone(),
            transfer_id: self.grant.transfer_id.clone(),
            base_manifest_hash: self.base_manifest_hash.clone(),
            base_record_hash: self.context.initiator.common.record_hash.clone(),
        })
    }
    /// Restore DATA-ONLY trust from the authenticated local encrypted stage after ordinary unlock.
    /// `local` and `own_branch_key` come from this device's actual unlocked branch owner.
    /// This restores no SAS confirmation, publication approval or HPKE private key. A tail owner
    /// must separately enforce persisted J6/current authority/terminal state before any hello.
    /// # Errors
    /// Refuses foreign local scope, mismatched context/TH/grant/lease, bad node signature or expiry.
    pub fn restore_local_stage(
        record: FullResumeRecord,
        node: &VerifiedNodeRecord,
        local: &DeviceRef,
        own_branch_key: &str,
        now: u64,
    ) -> Result<Self> {
        let context = TranscriptV3::from_wire_bytes(&record.transcript)?;
        let preimage = Zeroizing::new(
            ramflux_protocol::custody::pairing::context_v3::transcript_preimage(&context)?,
        );
        if super::super::sas::sha256(&preimage) != record.th {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        let own = match record.role {
            PairingRole::Initiator => &context.initiator,
            PairingRole::Responder => &context.responder,
        };
        if &own.device_ref != local || own.branch_key != own_branch_key {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        let a = &context.initiator;
        let b = &context.responder;
        record.grant.validate()?;
        if a.device_ref != record.grant.source_ref
            || b.device_ref != record.grant.destination_ref
            || a.branch_key != record.grant.branch_keys.source
            || b.branch_key != record.grant.branch_keys.destination
            || a.common.transfer_id.as_deref() != Some(record.transfer_id.as_str())
            || record.grant.transfer_id != record.transfer_id
            || a.common.record_hash != record.base_record_hash
        {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        let manifest = ramflux_protocol::decode_base64url(&record.base_manifest_hash)
            .map_err(|_| CryptoError::Pairing("WrongContext"))?;
        if manifest.len() != 32
            || ramflux_protocol::encode_base64url(manifest) != record.base_manifest_hash
        {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        // Bounded original bytes: signature and exact canonical local envelope are checked
        // before rebuilding trust. No node response may supply a replacement grant or context.
        if record.lease.len() > 8192 {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        let lease: Envelope<DataLease> = ramflux_protocol::parse_i_json_secret(&record.lease)
            .map_err(|_| CryptoError::Pairing("WrongContext"))?;
        super::super::verify_full_data_lease(&lease, &record.grant, node, now)?;
        let canonical = Zeroizing::new(ramflux_protocol::canonical_json_bytes(&lease)?);
        if canonical.as_slice() != record.lease.as_slice() {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        Ok(Self {
            role: record.role,
            context,
            grant: record.grant,
            lease: record.lease,
            base_manifest_hash: record.base_manifest_hash,
            th: record.th,
            allow_sas_key: false,
            lease_expires_at: lease.body.expires_at,
        })
    }
}

impl FullResumeRecord {
    /// Exact immutable record identity for the account-to-stage link (local A7 layout).
    /// This is a checksum of authenticated local operands, never a signature or approval.
    /// # Errors
    /// Refuses over-size columns, malformed grants and noncanonical 32-byte scope hashes.
    pub fn stage_digest(&self) -> Result<[u8; 32]> {
        if self.transcript.len() > TranscriptV3::LIMIT || self.lease.len() > 8192 {
            return Err(CryptoError::Pairing("WrongContext"));
        }
        self.grant.validate()?;
        let mut hasher = Zeroizing::new(blake3::Hasher::new());
        stage_field(&mut hasher, b"ramflux.full_transfer.resume_record.v1")?;
        hasher.update(&[self.role.byte()]);
        stage_field(&mut hasher, &self.transcript)?;
        hasher.update(&self.th);
        let grant = Zeroizing::new(ramflux_protocol::canonical_json_bytes(&self.grant)?);
        stage_field(&mut hasher, &grant)?;
        stage_field(&mut hasher, &self.lease)?;
        for hash in [&self.transfer_id, &self.base_manifest_hash, &self.base_record_hash] {
            let raw = Zeroizing::new(
                ramflux_protocol::decode_base64url(hash)
                    .map_err(|_| CryptoError::Pairing("WrongContext"))?,
            );
            if raw.len() != 32 || ramflux_protocol::encode_base64url(raw.as_slice()) != *hash {
                return Err(CryptoError::Pairing("WrongContext"));
            }
            hasher.update(&raw);
        }
        Ok(*hasher.finalize().as_bytes())
    }
}
fn stage_field(hasher: &mut blake3::Hasher, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| CryptoError::Pairing("WrongContext"))?;
    hasher.update(&length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}
