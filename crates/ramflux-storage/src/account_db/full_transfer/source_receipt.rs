// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A's signed-receipt ledger. Peer receipts never authorize publication or cut deletion.
use super::{FamilyRule, FullTransferStage, stage::raw32};
use crate::StorageError;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{ChainHasher, DataPacket, ManifestKind, SourceManifest, manifest_hash},
};
use rusqlite::{OptionalExtension as _, params};
use zeroize::Zeroizing;

pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS source_receipt(direction INTEGER NOT NULL DEFAULT 0 CHECK(direction=0),manifest_hash TEXT PRIMARY KEY,bytes BLOB NOT NULL,FOREIGN KEY(direction,manifest_hash) REFERENCES manifest(direction,manifest_hash));";
fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
impl FullTransferStage<'_> {
    /// Retain A's exact signed pre-publication manifest against its saved immutable cut.
    /// The source encoder must already have validated/encoded that cut before Issue;
    /// metadata retention alone never certifies its contents or authorizes source signing.
    /// # Errors
    /// Refuses wrong local role, missing/changed snapshot, scope/signature/catalog mismatch,
    /// unverified predecessor or a tail lacking the separate persisted J6 owner.
    pub fn retain_source_manifest(
        &mut self,
        manifest: &SourceManifest,
        rules: &'static [FamilyRule],
    ) -> Result<(), StorageError> {
        if manifest.manifest.kind == ManifestKind::Tail {
            return Err(mismatch());
        }
        self.retain_own_manifest(manifest, rules, false)
    }
    pub(super) fn retain_own_manifest(
        &mut self,
        manifest: &SourceManifest,
        rules: &'static [FamilyRule],
        tail: bool,
    ) -> Result<(), StorageError> {
        manifest.validate().map_err(|_| mismatch())?;
        let body = &manifest.manifest;
        let own = self.source_cut_schema(body.snapshot_cut.0, &body.snapshot_id, rules)?;
        own.require_typed_owners(rules)?;
        body.validate_catalog(&own.families, false)
            .map_err(|_| StorageError::PairingField("SchemaMismatch"))?;
        if body.census_hash != ramflux_protocol::encode_base64url(own.census_hash) {
            return Err(StorageError::PairingField("SchemaMismatch"));
        }
        if body.kind == ManifestKind::Base
            && body
                .families
                .iter()
                .zip(&own.families)
                .any(|(actual, expected)| actual.source_rows != expected.source_rows)
        {
            return Err(mismatch());
        }
        let (schema, erasure): (u64, u64) =
            self.with_source_cut(body.snapshot_cut.0, &body.snapshot_id, |input| {
                Ok((
                    input.query_row(
                        "SELECT max(schema_version) FROM schema_migration",
                        [],
                        |row| row.get(0),
                    )?,
                    input.query_row(
                        "SELECT generation FROM account_erasure_generation WHERE singleton=1",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })?;
        if schema != body.storage_generation.0 || erasure != body.source_erasure_generation.0 {
            return Err(StorageError::PairingField("SnapshotInvalidated"));
        }
        if tail {
            self.retain_tail_manifest_for_role(manifest, &own.families, PairingRole::Initiator)
        } else {
            self.retain_manifest_for_role(manifest, &own.families, PairingRole::Initiator)
        }
    }

    /// Verify B's receipt against A's OWN retained chain and original SAS branch key,
    /// then durably retain the exact signed bytes before allowing a successor manifest.
    /// This does not retire a cut: the completed successor diff is separately required.
    /// # Errors
    /// Refuses wrong role/lease, foreign or incomplete chain, wrong B signature or a
    /// conflicting receipt. No receipt here grants publication/activation authority.
    pub fn record_source_data_verified(
        &mut self,
        packet: &DataPacket,
        now: u64,
    ) -> Result<(), StorageError> {
        self.db.require_full_stage_unlock()?;
        let record = self.resume_record()?;
        if record.role != PairingRole::Initiator {
            return Err(StorageError::PairingField("WrongRole"));
        }
        if self.reference().lease_expires_at.0 <= now || record.grant.expires_at <= now {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        packet.validate().map_err(|_| mismatch())?;
        let DataPacket::DataVerified {
            manifest_hash: hash,
            chunks_root,
            total_bytes,
            census_hash,
            destination_ref,
            manifest_chain_hash,
            signature,
        } = packet
        else {
            return Err(mismatch());
        };
        let manifest = self.forward_manifest(hash)?;
        let body = &manifest.manifest;
        if body.chunks_root != *chunks_root
            || body.total_bytes != *total_bytes
            || body.census_hash != *census_hash
            || body.destination_ref != *destination_ref
            || record.grant.destination_ref != *destination_ref
        {
            return Err(mismatch());
        }
        let mut chain = ChainHasher::new(body.snapshot_cut.0 + 1).map_err(|_| mismatch())?;
        for cut in 0..=body.snapshot_cut.0 {
            let (bytes, verified) = self
                .connection
                .query_row(
                    "SELECT bytes,verified FROM manifest WHERE direction=0 AND cut=?1",
                    params![cut],
                    |row| Ok((Zeroizing::new(row.get::<_, Vec<u8>>(0)?), row.get::<_, bool>(1)?)),
                )
                .optional()?
                .ok_or_else(mismatch)?;
            if cut < body.snapshot_cut.0 && !verified {
                return Err(mismatch());
            }
            let member = SourceManifest::from_wire_bytes(&bytes).map_err(|_| mismatch())?;
            chain
                .push(
                    cut,
                    &manifest_hash(&member).map_err(|_| mismatch())?,
                    &raw32(&member.manifest.chunks_root)?,
                )
                .map_err(|_| mismatch())?;
        }
        if chain.finish().map_err(|_| mismatch())? != raw32(manifest_chain_hash)? {
            return Err(mismatch());
        }
        ramflux_crypto::verify_canonical_signature(
            &packet.data_verified_signing_bytes().map_err(|_| mismatch())?,
            signature,
            &record.grant.branch_keys.destination,
        )
        .map_err(|_| mismatch())?;
        let bytes = packet.encode_secret().map_err(|_| mismatch())?;
        let previous = self
            .connection
            .query_row(
                "SELECT bytes FROM source_receipt WHERE manifest_hash=?1",
                params![hash],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if previous.is_some_and(|old| old.as_slice() != bytes.as_slice()) {
            return Err(mismatch());
        }
        let hash = hash.clone();
        self.db.require_full_stage_unlock()?;
        self.connection.call(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT OR IGNORE INTO source_receipt(manifest_hash,bytes) VALUES(?1,?2)",
                params![hash, bytes.as_slice()],
            )?;
            tx.execute(
                "UPDATE manifest SET verified=1 WHERE direction=0 AND manifest_hash=?1",
                params![hash],
            )?;
            tx.commit()
        })?;
        Ok(())
    }

    pub(super) fn source_last_prepublication_data_verified(
        &self,
    ) -> Result<Option<DataPacket>, StorageError> {
        self.require_io()?;
        if self.resume_record()?.role != PairingRole::Initiator {
            return Err(StorageError::PairingField("WrongRole"));
        }
        let bytes = self.connection.query_row(
            "SELECT r.bytes FROM source_receipt r JOIN manifest m ON m.manifest_hash=r.manifest_hash AND m.direction=r.direction WHERE m.direction=0 AND m.kind!='tail' AND m.verified=1 AND length(r.bytes)<=16384 ORDER BY m.cut DESC LIMIT 1",
            [], |row| Ok(Zeroizing::new(row.get::<_,Vec<u8>>(0)?)),
        ).optional()?;
        bytes.map(|bytes| DataPacket::from_wire_bytes(&bytes).map_err(|_| mismatch())).transpose()
    }

    /// Read the exact original-A signed manifest named by the last durable B receipt.
    /// This is data-only local metadata, not a new consent, epoch, signing or tail grant.
    /// # Errors
    /// Refuses a locked/wrong-role owner or corrupt/inconsistent retained metadata.
    pub fn source_last_verified_manifest(&self) -> Result<Option<SourceManifest>, StorageError> {
        let Some(DataPacket::DataVerified { manifest_hash: hash, .. }) =
            self.source_last_data_verified()?
        else {
            return Ok(None);
        };
        let manifest = self.forward_manifest(&hash)?;
        let record = self.resume_record()?;
        ramflux_crypto::verify_canonical_signature(
            &manifest.manifest.signing_bytes().map_err(|_| mismatch())?,
            &manifest.source_signature,
            &record.grant.branch_keys.source,
        )
        .map_err(|_| mismatch())?;
        Ok(Some(manifest))
    }

    /// Read A's exact last durable B-signed receipt, for Idle/retry reconciliation.
    /// This restores no epoch keys, local approval, native authority or cut-retirement grant.
    /// # Errors
    /// Refuses a locked/wrong-role owner or corrupt local receipt encoding.
    pub fn source_last_data_verified(&self) -> Result<Option<DataPacket>, StorageError> {
        self.db.require_full_stage_unlock()?;
        if self.resume_record()?.role != PairingRole::Initiator {
            return Err(StorageError::PairingField("WrongRole"));
        }
        let bytes = self.connection.query_row("SELECT source_receipt.bytes FROM source_receipt JOIN manifest ON manifest.manifest_hash=source_receipt.manifest_hash AND manifest.direction=source_receipt.direction WHERE manifest.direction=0 AND verified=1 ORDER BY cut DESC LIMIT 1", [],
            |row| Ok(Zeroizing::new(row.get::<_,Vec<u8>>(0)?))).optional()?;
        bytes.map(|value| DataPacket::from_wire_bytes(&value).map_err(|_| mismatch())).transpose()
    }
}
