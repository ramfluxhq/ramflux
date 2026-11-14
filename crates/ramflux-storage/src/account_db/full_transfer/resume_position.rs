// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First position derives only from this endpoint's retained manifest and signed-DV ledger.
use super::FullTransferStage;
use crate::StorageError;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::{
    custody::pairing::{
        PairingWire,
        full_transfer::{ChainHasher, DataPacket, SourceManifest, manifest_hash},
    },
    encode_base64url,
};
use rusqlite::{OptionalExtension as _, params};
/// DATA-only reconnect position; no human approval, epoch token or installation permission.
pub enum FullForwardResumePosition {
    Streaming { manifest: Box<SourceManifest>, last_verified: Option<Box<SourceManifest>> },
    Idle { manifest: Box<SourceManifest> },
    AwaitingSource,
}
fn wrong() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
impl FullTransferStage<'_> {
    /// Select the first cut without this endpoint's signed `DataVerified`, otherwise Idle.
    /// Every advertised Idle hash is backed by the original B signature over its full chain.
    /// # Errors
    /// Refuses corrupt/forked metadata, a missing receipt, a tail or a stale local unlock.
    pub fn forward_resume_position(&self) -> Result<FullForwardResumePosition, StorageError> {
        self.require_io()?;
        let unverified: Option<String> = self.connection.query_row(
            "SELECT manifest_hash FROM manifest WHERE direction=0 AND verified=0 ORDER BY cut LIMIT 1",
            [], |row| row.get(0),
        ).optional()?;
        let last: Option<String> = self.connection.query_row(
            "SELECT manifest_hash FROM manifest WHERE direction=0 AND verified=1 ORDER BY cut DESC LIMIT 1",
            [], |row| row.get(0),
        ).optional()?;
        let verified = last.map(|hash| self.resume_verified_manifest(&hash)).transpose()?;
        if let Some(hash) = unverified {
            let manifest = self.forward_manifest(&hash)?;
            if manifest.manifest.snapshot_cut.0 > 8 {
                return Err(wrong());
            }
            return Ok(FullForwardResumePosition::Streaming {
                manifest: Box::new(manifest),
                last_verified: verified.map(Box::new),
            });
        }
        if let Some(manifest) = verified {
            return Ok(FullForwardResumePosition::Idle { manifest: Box::new(manifest) });
        }
        Ok(FullForwardResumePosition::AwaitingSource)
    }
    fn resume_verified_manifest(&self, hash: &str) -> Result<SourceManifest, StorageError> {
        let record = self.resume_record()?;
        let manifest = self.forward_manifest(hash)?;
        if manifest.manifest.snapshot_cut.0 > 8 {
            return Err(wrong());
        }
        let table = if record.role == PairingRole::Initiator {
            "source_receipt"
        } else {
            "receiver_receipt"
        };
        let bytes = self.connection.query_row(
            &format!("SELECT bytes FROM {table} WHERE manifest_hash=?1"),
            params![hash],
            |row| Ok(zeroize::Zeroizing::new(row.get::<_, Vec<u8>>(0)?)),
        )?;
        let packet = DataPacket::from_wire_bytes(&bytes).map_err(|_| wrong())?;
        let DataPacket::DataVerified {
            manifest_hash: actual,
            chunks_root,
            total_bytes,
            census_hash,
            destination_ref,
            manifest_chain_hash,
            signature,
        } = &packet
        else {
            return Err(wrong());
        };
        if actual != hash
            || chunks_root != &manifest.manifest.chunks_root
            || total_bytes != &manifest.manifest.total_bytes
            || census_hash != &manifest.manifest.census_hash
            || destination_ref != &record.grant.destination_ref
        {
            return Err(wrong());
        }
        let mut chain =
            ChainHasher::new(manifest.manifest.snapshot_cut.0 + 1).map_err(|_| wrong())?;
        for cut in 0..=manifest.manifest.snapshot_cut.0 {
            let hash: String = self.connection.query_row(
                "SELECT manifest_hash FROM manifest WHERE direction=0 AND cut=?1 AND verified=1",
                params![cut],
                |row| row.get(0),
            )?;
            let member = self.forward_manifest(&hash)?;
            chain
                .push(
                    cut,
                    &manifest_hash_bytes(&member)?,
                    &super::stage::raw32(&member.manifest.chunks_root)?,
                )
                .map_err(|_| wrong())?;
        }
        if encode_base64url(chain.finish().map_err(|_| wrong())?) != *manifest_chain_hash {
            return Err(wrong());
        }
        ramflux_crypto::verify_canonical_signature(
            &packet.data_verified_signing_bytes().map_err(|_| wrong())?,
            signature,
            &record.grant.branch_keys.destination,
        )
        .map_err(|_| wrong())?;
        Ok(manifest)
    }
}
fn manifest_hash_bytes(manifest: &SourceManifest) -> Result<[u8; 32], StorageError> {
    manifest_hash(manifest).map_err(|_| wrong())
}
