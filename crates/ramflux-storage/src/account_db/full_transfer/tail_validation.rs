// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete tail root/codec admission off-loan, before any selected-B mutation or receipt.
use super::receiver_read::{OwnedReceiverInput, ReceiverInput};
use super::{FullScalarInputCounts, FullTailEndpoint, full_transfer_catalog};
use crate::StorageError;
use ramflux_crypto::custody::pairing::PairingRole;
use rusqlite::params;

/// One decrypt-only local worker, counted/drained by the SDK's original root owner.
/// It retains no actual B connection/key, native authority, signer or publication permission.
pub struct FullTailValidationWork {
    input: OwnedReceiverInput,
    hash: String,
    digest: [u8; 32],
}
/// Non-forgeable complete input result. It is not a merge, semantic DV or admission lease.
pub struct FullValidatedTailInput {
    hash: String,
    digest: [u8; 32],
    counts: FullScalarInputCounts,
    guard: super::source_scalar::SourceGuard,
}
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl FullTailEndpoint<'_> {
    /// Move root/record validation away from B's ordinary writer loan.
    /// Drop the caller's account writer loan before running the returned local worker.
    /// # Errors
    /// Refuses wrong roles, incomplete input, foreign tail/hash or expired native admission.
    pub fn into_validation_work(
        self,
        hash: &str,
        now: u64,
    ) -> Result<FullTailValidationWork, StorageError> {
        self.require_tail(hash, now)?;
        let record = self.stage.resume_record()?;
        if record.role != PairingRole::Responder {
            return Err(wrong());
        }
        let input = self.stage.pin_tail_read_input(hash, now)?;
        Ok(FullTailValidationWork { input, hash: hash.into(), digest: record.stage_digest()? })
    }
    /// Bind a completed input check back to this fresh G3/native-admitted endpoint.
    /// This never writes portable data, a semantic receipt or a merged status.
    /// # Errors
    /// Refuses a foreign/replaced input, lost root unlock, changed digest or expired authority.
    pub fn accept_validated_input(
        &self,
        input: &FullValidatedTailInput,
        now: u64,
    ) -> Result<(), StorageError> {
        input.guard.require()?;
        self.require_tail(&input.hash, now)?;
        if self.stage.resume_record()?.role != PairingRole::Responder
            || self.stage.resume_record()?.stage_digest()? != input.digest
        {
            return Err(wrong());
        }
        self.stage.connection.execute_batch("CREATE TABLE IF NOT EXISTS tail_input_validated(manifest_hash TEXT PRIMARY KEY,stage_digest BLOB NOT NULL CHECK(length(stage_digest)=32),records INTEGER NOT NULL,encoded_bytes INTEGER NOT NULL)")?;
        self.stage.connection.execute("INSERT INTO tail_input_validated VALUES(?1,?2,?3,?4) ON CONFLICT(manifest_hash) DO NOTHING",
            params![input.hash,input.digest.as_slice(),input.counts.records,input.counts.encoded_bytes])?;
        if self.stage.connection.execute("UPDATE manifest SET root_verified=1 WHERE direction=0 AND manifest_hash=?1 AND kind='tail'", params![input.hash])? != 1 {
            return Err(wrong());
        }
        let adoption = self.stage.db.pairing_adoption()?.ok_or_else(wrong)?;
        let nonce = adoption.full_generation_nonce.ok_or_else(wrong)?;
        let source = super::super::mac_subkeys::full::source_key(
            &self.stage.resume_record()?.grant.source_ref,
        )?;
        if self.stage.db.connection.execute("UPDATE pairing_full_tail_apply SET tail_hash=?1 WHERE operation_id=?2 AND generation_nonce=?3 AND stage_digest=?4 AND source_owner=?5 AND tail_status IN('pending','merged') AND (tail_hash IS NULL OR tail_hash=?1)",
            params![input.hash,self.operation,nonce,input.digest.as_slice(),source])? != 1 {
            return Err(wrong());
        }
        super::stage::sync_stage(&self.stage.directory)?;
        self.require_live(now)
    }
}
impl FullTailValidationWork {
    /// Verify the complete signed root, unique ordered keys, closed codecs and exact totals.
    /// No selected B writes or semantic receipt can occur in this worker.
    /// # Errors
    /// Refuses corruption, unsupported owners, malformed input, lock/cancel or stale selection.
    pub fn validate(self) -> Result<FullValidatedTailInput, StorageError> {
        self.input.require_io()?;
        let counts =
            self.input.index_forward_scalar_records(&self.hash, full_transfer_catalog())?;
        self.input.require_io()?;
        Ok(FullValidatedTailInput {
            hash: self.hash,
            digest: self.digest,
            counts,
            guard: self.input.source_guard(),
        })
    }
}

impl super::FullTransferStage<'_> {
    pub(super) fn require_validated_tail_input(&self, hash: &str) -> Result<(), StorageError> {
        self.require_io()?;
        let manifest = self.forward_manifest(hash)?;
        let digest = self.resume_record()?.stage_digest()?;
        let valid: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM tail_input_validated WHERE manifest_hash=?1 AND stage_digest=?2 AND encoded_bytes=?3)",
            params![hash,digest.as_slice(),manifest.manifest.total_bytes.0], |row| row.get(0),
        )?;
        if !valid {
            return Err(wrong());
        }
        Ok(())
    }
}
