// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted durable private-generation application before any receiver DV signature.
use super::{FullReceiverBaseCopy, FullTransferStage, wrong};
use crate::StorageError;
use ramflux_protocol::{
    custody::pairing::{
        PairingWire,
        full_transfer::{ChainHasher, DataPacket, ManifestKind},
    },
    encode_base64url,
};
use rusqlite::{OptionalExtension as _, params};
use zeroize::Zeroizing;

pub(in crate::account_db::full_transfer) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS receiver_generation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation_nonce BLOB NOT NULL CHECK(length(generation_nonce)=32),stage_digest BLOB NOT NULL CHECK(length(stage_digest)=32),manifest_hash TEXT NOT NULL,workspace TEXT NOT NULL,private_key BLOB NOT NULL CHECK(length(private_key)=32),union_root BLOB NOT NULL CHECK(length(union_root)=32),records INTEGER NOT NULL,encoded_bytes INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS receiver_receipt(manifest_hash TEXT PRIMARY KEY,generation_nonce BLOB NOT NULL CHECK(length(generation_nonce)=32),bytes BLOB NOT NULL);";

/// A validated, durably committed endpoint data application; no native or primary signing right.
/// Not serializable/cloneable: restart must rebase B and revalidate actual prepared bytes.
pub struct FullAppliedDataReceipt {
    pub(in crate::account_db::full_transfer) role: ramflux_crypto::custody::pairing::PairingRole,
    pub(in crate::account_db::full_transfer) packet: DataPacket,
    pub(in crate::account_db::full_transfer) nonce: [u8; 32],
    pub(in crate::account_db::full_transfer) applied_root: [u8; 32],
    pub(in crate::account_db::full_transfer) digest: [u8; 32],
    pub(in crate::account_db::full_transfer) branch_key: String,
    pub(in crate::account_db::full_transfer) expires_at: u64,
}
impl FullAppliedDataReceipt {
    /// Original endpoint whose current generation committed this exact application.
    #[must_use]
    pub const fn expected_role(&self) -> ramflux_crypto::custody::pairing::PairingRole {
        self.role
    }

    /// Exact closed input receipt operands; its placeholder signature is not a signed DV.
    #[must_use]
    pub const fn packet(&self) -> &DataPacket {
        &self.packet
    }
    #[must_use]
    pub fn expected_branch_key(&self) -> &str {
        &self.branch_key
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    /// Attach only a valid signature by the original grant's destination branch.
    /// This does not persist or transmit the receipt; the original copy owner must do so.
    /// # Errors
    /// Refuses a malformed or foreign signature over these exact immutable operands.
    pub fn signed_packet(&self, signature: String) -> Result<DataPacket, StorageError> {
        let mut packet = self.packet.clone();
        let DataPacket::DataVerified { signature: slot, .. } = &mut packet else {
            return Err(wrong());
        };
        *slot = signature;
        packet.validate().map_err(|_| wrong())?;
        let DataPacket::DataVerified { signature, .. } = &packet else {
            return Err(wrong());
        };
        ramflux_crypto::verify_canonical_signature(
            &packet.data_verified_signing_bytes().map_err(|_| wrong())?,
            signature,
            &self.branch_key,
        )
        .map_err(|_| wrong())?;
        Ok(packet)
    }
}
impl FullReceiverBaseCopy {
    /// Verify/fsync the exact private generation, then commit its key/root in encrypted
    /// stage SQL before exposing the narrow receipt-signing request. This restores no
    /// approval after lock/restart and selects neither paths nor native authority.
    /// # Errors
    /// Refuses changed B/scope/bytes, unsupported successor input, expiry or durability errors.
    fn application_proof(
        &self,
        stage: &FullTransferStage<'_>,
        now: u64,
    ) -> Result<FullAppliedDataReceipt, StorageError> {
        self.verify_materialization(stage)?;
        let record = stage.resume_record()?;
        if now >= record.grant.expires_at || now >= stage.reference().lease_expires_at.0 {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        let manifest = stage.forward_manifest(&self.hash)?;
        if !matches!(manifest.manifest.kind, ManifestKind::Base | ManifestKind::Delta)
            || manifest.manifest.snapshot_cut.0 > 8
        {
            return Err(wrong());
        }
        let union = self.union.as_ref().ok_or_else(wrong)?;
        let mut chain =
            ChainHasher::new(manifest.manifest.snapshot_cut.0 + 1).map_err(|_| wrong())?;
        for cut in 0..=manifest.manifest.snapshot_cut.0 {
            let (bytes, verified): (Vec<u8>, bool) = stage.connection.query_row(
                "SELECT bytes,verified FROM manifest WHERE direction=0 AND cut=?1",
                params![cut],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if cut < manifest.manifest.snapshot_cut.0 && !verified {
                return Err(wrong());
            }
            let member =
                ramflux_protocol::custody::pairing::full_transfer::SourceManifest::from_wire_bytes(
                    &bytes,
                )
                .map_err(|_| wrong())?;
            chain
                .push(
                    cut,
                    &ramflux_protocol::custody::pairing::full_transfer::manifest_hash(&member)
                        .map_err(|_| wrong())?,
                    &super::super::stage::raw32(&member.manifest.chunks_root)?,
                )
                .map_err(|_| wrong())?;
        }
        Ok(FullAppliedDataReceipt {
            role: ramflux_crypto::custody::pairing::PairingRole::Responder,
            packet: DataPacket::DataVerified {
                manifest_hash: self.hash.clone(),
                chunks_root: manifest.manifest.chunks_root,
                total_bytes: manifest.manifest.total_bytes,
                census_hash: manifest.manifest.census_hash,
                destination_ref: record.grant.destination_ref,
                manifest_chain_hash: encode_base64url(chain.finish().map_err(|_| wrong())?),
                signature: encode_base64url([0; 64]),
            },
            nonce: union.generation_nonce,
            applied_root: union.chunks_root,
            digest: self.stage_digest,
            branch_key: record.grant.branch_keys.destination,
            expires_at: record.grant.expires_at.min(stage.reference().lease_expires_at.0),
        })
    }
    /// Durably retain a validated private generation before requesting its original DV.
    /// # Errors
    /// Refuses changed input, expiry, lost B ownership or encrypted stage I/O failure.
    pub fn commit_application(
        &mut self,
        stage: &mut FullTransferStage<'_>,
        now: u64,
    ) -> Result<FullAppliedDataReceipt, StorageError> {
        let proof = self.application_proof(stage, now)?;
        self.persist_application(stage, None)?;
        Ok(proof)
    }
    fn persist_application(
        &mut self,
        stage: &FullTransferStage<'_>,
        receipt: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<(), StorageError> {
        for name in ["private.db", "contributions.db"] {
            super::super::stage::open_regular(&self.scratch.path.join(name), false)?.sync_all()?;
        }
        std::fs::File::open(&self.scratch.path)?.sync_all()?;
        let workspace =
            self.scratch.path.file_name().and_then(|n| n.to_str()).ok_or_else(wrong)?.to_owned();
        let key = Zeroizing::new(*self.key.bytes());
        let union = self.union.as_ref().ok_or_else(wrong)?;
        let nonce = union.generation_nonce;
        let digest = self.stage_digest;
        let root = union.chunks_root;
        let records = union.records;
        let bytes = union.total_bytes;
        let hash = self.hash.clone();
        stage.connection.call(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute("INSERT INTO receiver_generation VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(singleton) DO UPDATE SET generation_nonce=excluded.generation_nonce,stage_digest=excluded.stage_digest,manifest_hash=excluded.manifest_hash,workspace=excluded.workspace,private_key=excluded.private_key,union_root=excluded.union_root,records=excluded.records,encoded_bytes=excluded.encoded_bytes",params![nonce.as_slice(),digest.as_slice(),hash,workspace,key.as_slice(),root.as_slice(),records,bytes])?;
            if let Some(receipt) = receipt
                && tx.execute("UPDATE receiver_receipt SET generation_nonce=?1 WHERE manifest_hash=?2 AND bytes=?3", params![nonce.as_slice(),hash,receipt.as_slice()])? != 1 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            tx.commit()
        })?;
        // A possible metadata commit must never leave its durable key pointing at deleted files.
        self.scratch.retain();
        super::super::stage::sync_stage(&stage.directory)?;
        self.observation.require_current(stage.db)
    }
    pub(super) fn retain_for_installation(
        &mut self,
        stage: &FullTransferStage<'_>,
        now: u64,
    ) -> Result<(), StorageError> {
        stage.verified_duplex(now)?;
        let proof = self.application_proof(stage, now)?;
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(stage.connection.query_row(
            "SELECT bytes FROM receiver_receipt WHERE manifest_hash=?1",
            params![self.hash],
            |row| row.get(0),
        )?);
        let packet = DataPacket::from_wire_bytes(bytes.as_slice()).map_err(|_| wrong())?;
        let DataPacket::DataVerified { signature, .. } = packet else {
            return Err(wrong());
        };
        let expected = proof.signed_packet(signature)?.encode_secret().map_err(|_| wrong())?;
        if expected.as_slice() != bytes.as_slice() {
            return Err(wrong());
        }
        // The source input/signature is unchanged; only the locally rebased B generation
        // and its qualified contribution ledger move together in this transaction.
        self.persist_application(stage, Some(bytes))
    }
    /// Persist exact signed DV and its input-verified flag in one stage transaction after
    /// rechecking this same B writer and actual generation. Only its returned bytes may send.
    /// # Errors
    /// Refuses expired/foreign requests, changed files/ledger/generation or signature mismatch.
    pub fn record_data_verified(
        &self,
        stage: &mut FullTransferStage<'_>,
        application: &FullAppliedDataReceipt,
        packet: &DataPacket,
        now: u64,
    ) -> Result<(), StorageError> {
        if application.role != ramflux_crypto::custody::pairing::PairingRole::Responder
            || now >= application.expires_at
            || application.digest != self.stage_digest
            || self.union.as_ref().map(|u| u.generation_nonce) != Some(application.nonce)
            || self.union.as_ref().map(|u| u.chunks_root) != Some(application.applied_root)
            || !matches!(application.packet(),DataPacket::DataVerified {manifest_hash,..} if manifest_hash == &self.hash)
        {
            return Err(wrong());
        }
        self.verify_materialization(stage)?;
        let DataPacket::DataVerified { signature, .. } = packet else {
            return Err(wrong());
        };
        let expected =
            application.signed_packet(signature.clone())?.encode_secret().map_err(|_| wrong())?;
        let bytes = packet.encode_secret().map_err(|_| wrong())?;
        if bytes.as_slice() != expected.as_slice() {
            return Err(wrong());
        }
        let key = Zeroizing::new(*self.key.bytes());
        let nonce = application.nonce;
        let digest = self.stage_digest;
        let hash = self.hash.clone();
        let root = self.union.as_ref().ok_or_else(wrong)?.chunks_root;
        let workspace = self
            .scratch
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(wrong)?
            .to_owned();
        let valid = stage.connection.call(move |db| {
            db.query_row("SELECT EXISTS(SELECT 1 FROM receiver_generation WHERE singleton=1 AND generation_nonce=?1 AND stage_digest=?2 AND manifest_hash=?3 AND union_root=?4 AND private_key=?5 AND workspace=?6)",params![nonce.as_slice(),digest.as_slice(),hash,root.as_slice(),key.as_slice(),workspace],|row|row.get::<_,bool>(0))
        })?;
        if !valid {
            return Err(wrong());
        }
        let hash = self.hash.clone();
        let nonce = application.nonce;
        stage.connection.call(move |db| {
            let tx=db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let old:Option<Vec<u8>>=tx.query_row("SELECT bytes FROM receiver_receipt WHERE manifest_hash=?1",params![hash],|r|r.get(0)).optional()?;
            if old.is_some_and(|old|old.as_slice()!=bytes.as_slice()) { return Err(rusqlite::Error::InvalidQuery); }
            tx.execute("INSERT INTO receiver_receipt(manifest_hash,generation_nonce,bytes) VALUES(?1,?2,?3) ON CONFLICT(manifest_hash) DO UPDATE SET generation_nonce=excluded.generation_nonce",params![hash,nonce.as_slice(),bytes.as_slice()])?;
            if tx.execute("UPDATE manifest SET verified=1 WHERE direction=0 AND manifest_hash=?1 AND root_verified=1",params![hash])? != 1 { return Err(rusqlite::Error::InvalidQuery); }
            tx.commit()
        })?;
        super::super::stage::sync_stage(&stage.directory)?;
        self.observation.require_current(stage.db)
    }
}
impl FullTransferStage<'_> {
    pub(in crate::account_db::full_transfer) fn retained_receiver_workspace(
        &self,
    ) -> Result<Option<String>, StorageError> {
        let name: Option<String> = self
            .connection
            .query_row("SELECT workspace FROM receiver_generation WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(name) = &name {
            super::super::stage::raw32(name.strip_prefix("receiver-").ok_or_else(wrong)?)?;
        }
        Ok(name)
    }
}

mod recovery;

#[cfg(test)]
mod tests;
