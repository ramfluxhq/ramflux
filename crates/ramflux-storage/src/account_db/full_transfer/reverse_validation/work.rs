// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original-A reverse validation with independent stage bytes/key and weak ordinary unlock.
use super::super::read_work::{self as reader, Reader};
use super::{StorageError, mismatch};
use crate::account_db::full_transfer::{
    FullTransferStage, StageDirection, source_scalar::SourceGuard,
};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::{SourceManifest, manifest_hash};
/// Root-drained local validation. Owns no ordinary database, data key or signing permission.
pub struct FullReverseValidationWork {
    reader: Reader,
    manifest: SourceManifest,
    hash: String,
    digest: [u8; 32],
    guard: SourceGuard,
}
/// Complete restrictive input proof only, bound to the original live stage and unlocked writer.
/// It cannot authorize semantic DV until actual A application has separately committed.
pub struct FullValidatedReverseInput {
    hash: String,
    digest: [u8; 32],
    guard: SourceGuard,
}
impl FullTransferStage<'_> {
    /// Release the ordinary writer borrow before scanning/decrypting a reverse stream.
    /// The independent stage lock remains owned for the bounded root-drained worker.
    /// # Errors
    /// Refuses another role, changed manifest, dead actual unlock or stage-key failure.
    pub fn into_reverse_validation_work(
        self,
        hash: &str,
    ) -> Result<FullReverseValidationWork, StorageError> {
        self.require_io()?;
        let record = self.resume_record()?;
        if record.role != PairingRole::Initiator {
            return Err(StorageError::PairingField("WrongContext"));
        }
        let manifest = self.reverse_manifest(hash)?;
        if ramflux_protocol::encode_base64url(manifest_hash(&manifest).map_err(|_| mismatch())?)
            != hash
        {
            return Err(mismatch());
        }
        let guard = SourceGuard::new(self.db, Some(self.source_cancelled.clone()));
        let key = self.key.chunk_read_key(
            super::super::stage::raw32(hash)?,
            StageDirection::Reverse,
            guard.clone(),
        )?;
        let reader = Reader::new(
            reader::Inputs {
                connection: self.connection,
                lock: std::sync::Arc::new(self.lock),
                directory: self.directory,
                key: std::sync::Arc::new(key),
                direction: 1,
            },
            manifest.clone(),
            hash.into(),
            guard.clone(),
        );
        Ok(FullReverseValidationWork {
            reader,
            manifest,
            hash: hash.into(),
            digest: record.stage_digest()?,
            guard,
        })
    }
    /// Retain only a complete input-validation proof through a new short original-A loan.
    /// This deliberately creates no reverse application receipt or verified/DV marker.
    /// # Errors
    /// Refuses changed stage/unlock/manifest or failure to durably retain the local proof.
    pub fn accept_validated_reverse_input(
        &self,
        input: &FullValidatedReverseInput,
    ) -> Result<(), StorageError> {
        self.require_io()?;
        input.guard.require()?;
        let record = self.resume_record()?;
        if record.role != PairingRole::Initiator || record.stage_digest()? != input.digest {
            return Err(mismatch());
        }
        self.reverse_manifest(&input.hash)?;
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS reverse_input_validated(manifest_hash TEXT PRIMARY KEY,stage_digest BLOB NOT NULL CHECK(length(stage_digest)=32));")?;
        self.connection.execute("INSERT INTO reverse_input_validated VALUES(?1,?2) ON CONFLICT(manifest_hash) DO UPDATE SET stage_digest=excluded.stage_digest", rusqlite::params![input.hash,input.digest.as_slice()])?;
        super::super::stage::sync_stage(&self.directory)?;
        self.require_io()
    }
}
impl FullReverseValidationWork {
    /// Verify exact disk root and every locally owned restrictive record off-loan.
    /// # Errors
    /// Refuses corrupt/incomplete data, false counts, unsupported owners, cancellation or lock.
    pub fn validate(mut self) -> Result<FullValidatedReverseInput, StorageError> {
        self.guard.require()?;
        self.reader.verify_root()?;
        super::validate_input(&mut self.reader, &self.manifest, &self.guard)?;
        self.guard.require()?;
        Ok(FullValidatedReverseInput { hash: self.hash, digest: self.digest, guard: self.guard })
    }
}
