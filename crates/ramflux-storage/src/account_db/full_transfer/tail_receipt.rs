// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Tail semantic receipts require both actual B application passes and durable local progress.
use super::{FullTailEndpoint, FullTransferStage};
use crate::{FullLocalUnlockGuard, StorageError};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::{
    custody::pairing::{
        PairingWire,
        full_transfer::{ChainHasher, DataPacket, SourceManifest, manifest_hash},
    },
    encode_base64url,
};
use rusqlite::{OptionalExtension as _, params};
use zeroize::Zeroizing;
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}

/// Exact already-applied tail operands. No native/session/management signing permission.
/// The packet has a placeholder signature until `signed_packet` verifies original B's signature.
pub struct FullTailAppliedReceipt {
    packet: DataPacket,
    operation: String,
    hash: String,
    nonce: String,
    digest: [u8; 32],
    branch: String,
    expires: u64,
    guard: FullLocalUnlockGuard,
}
impl FullTailAppliedReceipt {
    #[must_use]
    pub const fn packet(&self) -> &DataPacket {
        &self.packet
    }
    #[must_use]
    pub fn expected_branch_key(&self) -> &str {
        &self.branch
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires
    }
    /// Attach only original B's signature over this exact committed tail application.
    /// # Errors
    /// Refuses original unlock loss, malformed receipt or a foreign signature.
    pub fn signed_packet(&self, signature: String) -> Result<DataPacket, StorageError> {
        self.guard.require_unlocked()?;
        let mut packet = self.packet.clone();
        let DataPacket::DataVerified { signature: field, .. } = &mut packet else {
            return Err(wrong());
        };
        *field = signature;
        packet.validate().map_err(|_| wrong())?;
        verify_signature(&packet, &self.branch)?;
        self.guard.require_unlocked()?;
        Ok(packet)
    }
}
impl FullTailEndpoint<'_> {
    /// Obtain a narrow signing request only after both actual selected-B passes committed.
    /// # Errors
    /// Refuses partial application, wrong generation/hash/digest, missing native/G3 or expiry.
    pub fn applied_receipt(
        &self,
        hash: &str,
        now: u64,
    ) -> Result<FullTailAppliedReceipt, StorageError> {
        self.require_tail(hash, now)?;
        self.stage.require_validated_tail_input(hash)?;
        let nonce = self.require_applied_tail(hash)?;
        let record = self.stage.resume_record()?;
        let manifest = self.stage.forward_manifest(hash)?;
        let digest = record.stage_digest()?;
        let chain = tail_chain(&self.stage, &manifest)?;
        Ok(FullTailAppliedReceipt {
            packet: DataPacket::DataVerified {
                manifest_hash: hash.into(),
                chunks_root: manifest.manifest.chunks_root,
                total_bytes: manifest.manifest.total_bytes,
                census_hash: manifest.manifest.census_hash,
                destination_ref: record.grant.destination_ref,
                manifest_chain_hash: encode_base64url(chain),
                signature: encode_base64url([0; 64]),
            },
            operation: self.operation.clone(),
            hash: hash.into(),
            nonce,
            digest,
            branch: record.grant.branch_keys.destination,
            expires: record.grant.expires_at.min(self.stage.reference().lease_expires_at.0),
            guard: self.stage.db.full_local_unlock_guard()?,
        })
    }
    fn require_applied_tail(&self, hash: &str) -> Result<String, StorageError> {
        let record = self.stage.resume_record()?;
        if record.role != PairingRole::Responder {
            return Err(wrong());
        }
        let adoption = self.stage.db.pairing_adoption()?.ok_or_else(wrong)?;
        let nonce = adoption.full_generation_nonce.ok_or_else(wrong)?;
        let digest = record.stage_digest()?;
        let total = self.stage.forward_manifest(hash)?.manifest.total_bytes.0;
        let valid: bool = self.stage.db.connection.query_row("SELECT EXISTS(SELECT 1 FROM pairing_full_tail_apply WHERE operation_id=?1 AND generation_nonce=?2 AND stage_digest=?3 AND tail_hash=?4 AND phase=2 AND next_record=?5 AND tail_status IN('pending','merged'))",
            params![self.operation,nonce,digest.as_slice(),hash,total], |row| row.get(0))?;
        if !valid {
            return Err(wrong());
        }
        Ok(nonce)
    }
    /// Persist original B's exact receipt, then report the locally merged tail.
    /// No packet may be sent or stage reclaimed before this returns successfully.
    /// # Errors
    /// Refuses another receipt/generation, partial application, bad signature or stale authority.
    pub fn record_applied_receipt(
        &self,
        application: &FullTailAppliedReceipt,
        packet: &DataPacket,
        now: u64,
    ) -> Result<(), StorageError> {
        self.require_tail(&application.hash, now)?;
        application.guard.require_unlocked()?;
        if application.operation != self.operation
            || application.nonce != self.require_applied_tail(&application.hash)?
            || application.digest != self.stage.resume_record()?.stage_digest()?
            || application.packet.data_verified_signing_bytes().map_err(|_| wrong())?
                != packet.data_verified_signing_bytes().map_err(|_| wrong())?
        {
            return Err(wrong());
        }
        verify_signature(packet, &application.branch)?;
        let bytes = packet.encode_secret().map_err(|_| wrong())?;
        retain_receipt(&self.stage, application, &bytes)?;
        if self.stage.db.connection.execute("UPDATE pairing_full_tail_apply SET tail_status='merged' WHERE operation_id=?1 AND generation_nonce=?2 AND stage_digest=?3 AND tail_hash=?4 AND phase=2 AND tail_status IN('pending','merged')",
            params![self.operation,application.nonce,application.digest.as_slice(),application.hash])? != 1 { return Err(wrong()); }
        self.require_live(now)
    }
}
fn verify_signature(packet: &DataPacket, branch: &str) -> Result<(), StorageError> {
    let DataPacket::DataVerified { signature, .. } = packet else {
        return Err(wrong());
    };
    packet.validate().map_err(|_| wrong())?;
    ramflux_crypto::verify_canonical_signature(
        &packet.data_verified_signing_bytes().map_err(|_| wrong())?,
        signature,
        branch,
    )
    .map_err(|_| wrong())
}
fn retain_receipt(
    stage: &FullTransferStage<'_>,
    application: &FullTailAppliedReceipt,
    bytes: &[u8],
) -> Result<(), StorageError> {
    let previous: Option<Option<Vec<u8>>> = stage.connection.query_row(
        "SELECT CASE WHEN length(bytes)<=16384 THEN bytes END FROM receiver_receipt WHERE manifest_hash=?1",
        params![application.hash], |row| row.get(0),
    ).optional()?;
    match previous {
        Some(Some(old)) if old.as_slice() == bytes => {}
        Some(_) => return Err(wrong()),
        None => {}
    }
    let hash = application.hash.clone();
    let nonce = super::stage::raw32(&application.nonce)?;
    let bytes = Zeroizing::new(bytes.to_vec());
    stage.connection.call(move |raw| {
        let tx = raw.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO receiver_receipt(manifest_hash,generation_nonce,bytes) VALUES(?1,?2,?3) ON CONFLICT(manifest_hash) DO NOTHING", params![hash,nonce.as_slice(),bytes.as_slice()])?;
        if tx.execute("UPDATE manifest SET verified=1 WHERE direction=0 AND manifest_hash=?1 AND kind='tail' AND root_verified=1", params![hash])?!=1 { return Err(rusqlite::Error::InvalidQuery); }
        tx.commit()
    })?;
    super::stage::sync_stage(&stage.directory)
}
fn tail_chain(
    stage: &FullTransferStage<'_>,
    manifest: &SourceManifest,
) -> Result<[u8; 32], StorageError> {
    let last = manifest.manifest.snapshot_cut.0;
    let mut chain = ChainHasher::new(last + 1).map_err(|_| wrong())?;
    for cut in 0..=last {
        let (bytes, verified): (Vec<u8>,bool) = stage.connection.query_row("SELECT bytes,verified FROM manifest WHERE direction=0 AND cut=?1 AND length(bytes)<=1048576", params![cut], |row| Ok((row.get(0)?,row.get(1)?)))?;
        if cut < last && !verified {
            return Err(wrong());
        }
        let member = SourceManifest::from_wire_bytes(&bytes).map_err(|_| wrong())?;
        chain
            .push(
                cut,
                &manifest_hash(&member).map_err(|_| wrong())?,
                &super::stage::raw32(&member.manifest.chunks_root)?,
            )
            .map_err(|_| wrong())?;
    }
    chain.finish().map_err(|_| wrong())
}
