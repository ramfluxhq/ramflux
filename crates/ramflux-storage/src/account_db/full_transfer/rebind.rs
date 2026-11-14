// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated pre-J3 native-head bindings retain historical manifest provenance.
use super::FullTransferStage;
use crate::StorageError;
use ramflux_crypto::custody::{
    VerifiedRecord,
    pairing::{PairingRole, verify_full_prepublication_authority},
};
use ramflux_protocol::{
    custody::{
        object_hash,
        pairing::{PairingWire, full_transfer::DataPacket},
    },
    encode_base64url,
};
use rusqlite::{OptionalExtension as _, params};
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS rebound_head(hash TEXT PRIMARY KEY,packet BLOB NOT NULL); CREATE TABLE IF NOT EXISTS prepublication_binding(singleton INTEGER PRIMARY KEY CHECK(singleton=1),hash TEXT NOT NULL,epoch INTEGER NOT NULL);";
fn changed() -> StorageError {
    StorageError::PairingField("HeadChanged")
}
impl FullTransferStage<'_> {
    fn require_before_candidate(&self) -> Result<(), StorageError> {
        let Some(head) = self.db.pairing_head()? else {
            return Ok(());
        };
        if head.kind != "transfer" {
            return Ok(());
        }
        for row in self.db.pairing_live_rows()? {
            if row.operation_id == head.operation_id
                && row.full_stage_reference()?.as_ref() == Some(self.reference())
            {
                return Err(changed());
            }
        }
        Ok(())
    }
    /// Latest accepted source-signed head, or the original SAS base before any Rebind.
    /// Manifest and channel provenance always retain the original base hash.
    /// # Errors
    /// Refuses a stale unlock, corrupt local metadata or a malformed bound hash.
    pub fn full_prepublication_record_hash(&self) -> Result<String, StorageError> {
        self.require_io()?;
        self.connection.execute_batch(SCHEMA)?;
        let hash: Option<String> = self
            .connection
            .query_row("SELECT hash FROM prepublication_binding WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .optional()?;
        let hash = hash.unwrap_or(self.resume_record()?.base_record_hash);
        super::stage::raw32(&hash)?;
        Ok(hash)
    }
    /// Native epoch paired with the latest accepted source-signed hash.
    /// # Errors
    /// Refuses corrupt encrypted metadata, a locked stage or invalid original transcript.
    pub fn full_prepublication_record_epoch(&self) -> Result<u64, StorageError> {
        self.require_io()?;
        self.connection.execute_batch(SCHEMA)?;
        let epoch: Option<u64> = self
            .connection
            .query_row("SELECT epoch FROM prepublication_binding WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .optional()?;
        if let Some(epoch) = epoch {
            Ok(epoch)
        } else {
            let record = self.resume_record()?;
            let context =
                ramflux_protocol::custody::pairing::context_v3::TranscriptV3::from_wire_bytes(
                    &record.transcript,
                )
                .map_err(|_| changed())?;
            Ok(context.initiator.common.device_set_epoch)
        }
    }
    /// Prepare one data-only Rebind after this endpoint independently obtains native authority.
    /// Only original A may request a signature; publication and SAS consent are unchanged.
    /// # Errors
    /// Refuses J3, lost original roles/keys, native rollback/fork or more than 64 distinct heads.
    pub fn prepare_full_rebind(
        &mut self,
        current: &VerifiedRecord,
        now: u64,
    ) -> Result<DataPacket, StorageError> {
        self.require_io()?;
        self.observe_full_native_head(current)?;
        self.require_before_candidate()?;
        let record = self.resume_record()?;
        if record.role != PairingRole::Initiator {
            return Err(changed());
        }
        verify_full_prepublication_authority(&record.grant, current, now).map_err(|_| changed())?;
        let hash = object_hash(current.envelope())?;
        self.require_rebind_capacity(&hash)?;
        Ok(DataPacket::Rebind {
            manifest_hash: record.base_manifest_hash,
            new_base_record_hash: hash,
            source_signature: encode_base64url([0; 64]),
        })
    }
    fn require_rebind_capacity(&self, hash: &str) -> Result<(), StorageError> {
        self.connection.execute_batch(SCHEMA)?;
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM rebound_head WHERE hash=?1)",
            params![hash],
            |row| row.get(0),
        )?;
        let count: u64 =
            self.connection.query_row("SELECT count(*) FROM rebound_head", [], |row| row.get(0))?;
        if !exists && count >= 64 {
            return Err(StorageError::PairingField("TransferCapacity"));
        }
        Ok(())
    }
    /// Persist only an original-A signature over the exact independently fetched current head.
    /// A peer hint alone never advances the bound head; duplicate frames are idempotent.
    /// # Errors
    /// Refuses J3, wrong manifest/hash/signature, lost original authority, rollback or overflow.
    pub fn retain_full_rebind(
        &mut self,
        current: &VerifiedRecord,
        packet: &DataPacket,
        now: u64,
    ) -> Result<(), StorageError> {
        self.require_io()?;
        self.observe_full_native_head(current)?;
        self.require_before_candidate()?;
        let record = self.resume_record()?;
        verify_full_prepublication_authority(&record.grant, current, now).map_err(|_| changed())?;
        let DataPacket::Rebind { manifest_hash, new_base_record_hash, source_signature } = packet
        else {
            return Err(changed());
        };
        if manifest_hash != &record.base_manifest_hash
            || new_base_record_hash != &object_hash(current.envelope())?
        {
            return Err(changed());
        }
        ramflux_crypto::verify_canonical_signature(
            &packet.rebind_signing_bytes().map_err(|_| changed())?,
            source_signature,
            &record.grant.branch_keys.source,
        )
        .map_err(|_| changed())?;
        self.require_rebind_capacity(new_base_record_hash)?;
        let hash = new_base_record_hash.clone();
        let epoch = current.envelope().body.device_set_epoch;
        let bytes = zeroize::Zeroizing::new(packet.encode_secret().map_err(|_| changed())?);
        self.connection.call_immediate(move |tx| {
            tx.execute("INSERT INTO rebound_head VALUES(?1,?2) ON CONFLICT(hash) DO NOTHING",params![hash,bytes.as_slice()])?;
            tx.execute("INSERT INTO prepublication_binding VALUES(1,?1,?2) ON CONFLICT(singleton) DO UPDATE SET hash=excluded.hash,epoch=excluded.epoch",params![hash,epoch])?;
            Ok(())
        })?;
        super::stage::sync_stage(&self.directory)?;
        self.require_io()
    }
    /// J3/preservation uses this exact latest accepted native head, never a peer hint.
    /// # Errors
    /// Refuses a stale/fenced head, missing Rebind or another native publication.
    pub fn require_full_prepublication_record(
        &self,
        current: &VerifiedRecord,
    ) -> Result<(), StorageError> {
        self.require_io()?;
        self.require_full_native_floor(current)?;
        if self.full_prepublication_record_hash()? != object_hash(current.envelope())? {
            return Err(changed());
        }
        Ok(())
    }
}
