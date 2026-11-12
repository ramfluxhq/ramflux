// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local durable duplex operands. No peer flag, candidate or publication permission.
use super::{FullTransferStage, stage::raw32};
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
use zeroize::Zeroizing;

/// Nonserializable evidence read from this endpoint's own signed application ledgers.
/// Reopen must reconstruct it; it confers only the prepublication control position.
pub struct FullDuplexReceipt {
    role: PairingRole,
    lease: String,
    expires_at: u64,
    chain: String,
    verified: String,
    restrictions: String,
}
impl FullDuplexReceipt {
    #[must_use]
    pub const fn role(&self) -> PairingRole {
        self.role
    }
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub fn manifest_chain_hash(&self) -> &str {
        &self.chain
    }
    #[must_use]
    pub fn data_verified_hash(&self) -> &str {
        &self.verified
    }
    #[must_use]
    pub fn target_restrictions_root(&self) -> &str {
        &self.restrictions
    }
}
fn wrong() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
impl FullTransferStage<'_> {
    /// Reconstruct the original endpoints' exact signed forward/reverse application.
    /// Requires the last signed prepublication delta, the complete verified chain,
    /// and this endpoint's actual durable application ledger. This grants no approval.
    /// # Errors
    /// Refuses missing/corrupt/stale receipts, changed original paths, expiry or lock.
    pub fn verified_duplex(&self, now: u64) -> Result<FullDuplexReceipt, StorageError> {
        self.require_io()?;
        let record = self.resume_record()?;
        let expiry = record.grant.expires_at.min(self.reference().lease_expires_at.0);
        if now >= expiry {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        let lease: ramflux_protocol::custody::Envelope<
            ramflux_protocol::custody::pairing::full_transfer::lease::DataLease,
        > = ramflux_protocol::parse_i_json(&record.lease)?;
        lease.body.validate().map_err(|_| wrong())?;
        if lease.body.grant != record.grant
            || lease.body.expires_at != self.reference().lease_expires_at.0
        {
            return Err(wrong());
        }
        let (forward, chain) = self.verified_forward_receipt()?;
        self.verify_reverse_application_receipt(now)?;
        // Only the current new-target neutral reverse is supported by reverse_receipt.
        let tag = b"ramflux.pairing.full.target_restrictions.v1";
        let mut restrictions = blake3::Hasher::new();
        restrictions.update(&u32::try_from(tag.len()).map_err(|_| wrong())?.to_be_bytes());
        restrictions.update(tag);
        self.require_io()?;
        Ok(FullDuplexReceipt {
            role: record.role,
            lease: lease.body.lease_id,
            expires_at: expiry,
            chain: encode_base64url(chain),
            verified: encode_base64url(forward.data_verified_hash().map_err(|_| wrong())?),
            restrictions: encode_base64url(restrictions.finalize().as_bytes()),
        })
    }
    fn verified_forward_receipt(&self) -> Result<(DataPacket, [u8; 32]), StorageError> {
        let record = self.resume_record()?;
        let (hash, bytes): (String, Vec<u8>) = self.connection.query_row(
            "SELECT manifest_hash,bytes FROM manifest WHERE direction=0 ORDER BY cut DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let manifest = SourceManifest::from_wire_bytes(&bytes).map_err(|_| wrong())?;
        if encode_base64url(manifest_hash(&manifest).map_err(|_| wrong())?) != hash
            || !manifest.manifest.is_last_prepublication_delta()
        {
            return Err(wrong());
        }
        let table = match record.role {
            PairingRole::Initiator => "source_receipt",
            PairingRole::Responder => "receiver_receipt",
        };
        let bytes = self
            .connection
            .query_row(
                &format!("SELECT bytes FROM {table} WHERE manifest_hash=?1"),
                params![hash],
                |row| Ok(Zeroizing::new(row.get::<_, Vec<u8>>(0)?)),
            )
            .optional()?
            .ok_or_else(wrong)?;
        let forward = DataPacket::from_wire_bytes(&bytes).map_err(|_| wrong())?;
        let DataPacket::DataVerified {
            manifest_hash: receipt_hash,
            chunks_root,
            total_bytes,
            census_hash,
            destination_ref,
            manifest_chain_hash,
            signature,
        } = &forward
        else {
            return Err(wrong());
        };
        if receipt_hash != &hash
            || chunks_root != &manifest.manifest.chunks_root
            || total_bytes != &manifest.manifest.total_bytes
            || census_hash != &manifest.manifest.census_hash
            || destination_ref != &record.grant.destination_ref
        {
            return Err(wrong());
        }
        let chain = self.verified_chain(manifest.manifest.snapshot_cut.0)?;
        if raw32(manifest_chain_hash)? != chain {
            return Err(wrong());
        }
        ramflux_crypto::verify_canonical_signature(
            &forward.data_verified_signing_bytes().map_err(|_| wrong())?,
            signature,
            &record.grant.branch_keys.destination,
        )
        .map_err(|_| wrong())?;
        if record.role == PairingRole::Responder {
            let valid: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM receiver_generation g JOIN receiver_receipt r ON r.manifest_hash=g.manifest_hash AND r.generation_nonce=g.generation_nonce WHERE g.singleton=1 AND g.manifest_hash=?1 AND g.stage_digest=?2)",params![hash,record.stage_digest()?.as_slice()],|row|row.get(0))?;
            if !valid {
                return Err(wrong());
            }
        }
        Ok((forward, chain))
    }
    fn verify_reverse_application_receipt(&self, now: u64) -> Result<(), StorageError> {
        let record = self.resume_record()?;
        let reverse = self.reverse_receipt(now)?;
        let DataPacket::DataVerified { manifest_hash: reverse_hash, .. } = reverse.packet() else {
            return Err(wrong());
        };
        let bytes = match record.role {
            PairingRole::Initiator => {
                let selected = self.db.account_index.account(&self.db.local_account_id)?;
                self.connection.query_row("SELECT receipt FROM reverse_application WHERE manifest_hash=?1 AND stage_digest=?2 AND db_path=?3 AND object_path=?4",params![reverse_hash,record.stage_digest()?.as_slice(),selected.db_relative_path,selected.object_dir_relative_path],|row|row.get::<_,Vec<u8>>(0))?
            }
            PairingRole::Responder => self.connection.query_row(
                "SELECT bytes FROM reverse_source_receipt WHERE manifest_hash=?1",
                params![reverse_hash],
                |row| row.get::<_, Vec<u8>>(0),
            )?,
        };
        let bytes = Zeroizing::new(bytes);
        let packet = DataPacket::from_wire_bytes(&bytes).map_err(|_| wrong())?;
        let DataPacket::DataVerified { signature, .. } = &packet else {
            return Err(wrong());
        };
        if reverse
            .signed_packet(signature.clone())?
            .encode_secret()
            .map_err(|_| wrong())?
            .as_slice()
            != bytes.as_slice()
        {
            return Err(wrong());
        }
        Ok(())
    }
    fn verified_chain(&self, last: u64) -> Result<[u8; 32], StorageError> {
        let record = self.resume_record()?;
        let mut chain = ChainHasher::new(last + 1).map_err(|_| wrong())?;
        let mut previous: Option<SourceManifest> = None;
        for cut in 0..=last {
            let (bytes, verified): (Vec<u8>, bool) = self.connection.query_row(
                "SELECT bytes,verified FROM manifest WHERE direction=0 AND cut=?1",
                params![cut],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if !verified {
                return Err(wrong());
            }
            let member = SourceManifest::from_wire_bytes(&bytes).map_err(|_| wrong())?;
            if member.manifest.snapshot_cut.0 != cut
                || member.manifest.transfer_id != record.transfer_id
                || member.manifest.base_record_hash != record.base_record_hash
                || member.manifest.source_ref != record.grant.source_ref
                || member.manifest.destination_ref != record.grant.destination_ref
                || (cut == 0
                    && encode_base64url(manifest_hash(&member).map_err(|_| wrong())?)
                        != record.base_manifest_hash)
            {
                return Err(wrong());
            }
            if let Some(prior) = &previous {
                member.verify_predecessor(prior).map_err(|_| wrong())?;
            }
            ramflux_crypto::verify_canonical_signature(
                &member.manifest.signing_bytes().map_err(|_| wrong())?,
                &member.source_signature,
                &record.grant.branch_keys.source,
            )
            .map_err(|_| wrong())?;
            chain
                .push(
                    cut,
                    &manifest_hash(&member).map_err(|_| wrong())?,
                    &raw32(&member.manifest.chunks_root)?,
                )
                .map_err(|_| wrong())?;
            previous = Some(member);
        }
        chain.finish().map_err(|_| wrong())
    }
}
