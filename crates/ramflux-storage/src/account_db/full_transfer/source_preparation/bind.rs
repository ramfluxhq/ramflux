// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! No data stage exists until fresh trust and the exact prepared signed base agree.
use super::{FullBaseSourceEncoding, FullSourcePreparation};
use crate::account_db::full_transfer::{
    FullStageKey, FullTransferStage,
    stage::{context, raw32, stage_directory, sync_stage, write_new_atomic},
};
use crate::{AccountDb, StorageError, database::Connection};
use ramflux_crypto::custody::{
    VerifiedRecord,
    pairing::{FullResumeRecord, FullResumeTrust, PairingRole},
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{ManifestKind, SourceManifest, manifest_hash},
};
use std::path::PathBuf;

pub(in crate::account_db::full_transfer) struct SourceBindParts<'db> {
    pub(in crate::account_db::full_transfer) connection: Connection,
    pub(in crate::account_db::full_transfer) lock: std::fs::File,
    pub(in crate::account_db::full_transfer) key: FullStageKey<'db>,
    pub(in crate::account_db::full_transfer) db: &'db AccountDb,
    pub(in crate::account_db::full_transfer) directory: PathBuf,
    pub(in crate::account_db::full_transfer) cancelled:
        std::sync::Arc<std::sync::atomic::AtomicBool>,
}
fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
fn matches_encoding(
    manifest: &SourceManifest,
    snapshot_id: &str,
    encoded: &FullBaseSourceEncoding,
) -> Result<(), StorageError> {
    let body = &manifest.manifest;
    if body.kind != ManifestKind::Base
        || body.snapshot_cut.0 != 0
        || body.snapshot_id != snapshot_id
        || body.storage_generation.0 != encoded.storage_generation
        || body.source_erasure_generation.0 != encoded.source_erasure_generation
        || body.total_bytes.0 != encoded.total_bytes
        || body.chunk_count.0 != encoded.chunk_count
        || body.chunks_root != ramflux_protocol::encode_base64url(encoded.chunks_root)
        || body.census_hash != ramflux_protocol::encode_base64url(encoded.schema.census_hash)
        || body.families != encoded.schema.families
    {
        return Err(mismatch());
    }
    Ok(())
}
impl<'db> FullSourcePreparation<'db> {
    /// Bind only the exact prepared signed base to independently established full data trust.
    /// This consumes the private preparation, rewraps its independent key to the transfer ID,
    /// and persists the unchanged eight resume operands plus exact SAS-base floor BEFORE a
    /// linkable authenticated stage reference can be returned. It restores no approval.
    /// # Errors
    /// Refuses cancellation, expiry, wrong role/context/signature/root or unsafe I/O.
    pub fn bind_full_transfer(
        self,
        trust: &FullResumeTrust,
        sas_base: &VerifiedRecord,
        manifest: &SourceManifest,
        now: u64,
    ) -> Result<FullTransferStage<'db>, StorageError> {
        self.bind_record(
            trust.local_stage_record()?,
            trust.lease_expires_at(),
            sas_base,
            manifest,
            now,
        )
    }
    #[cfg(test)]
    pub(in crate::account_db::full_transfer) fn bind_record_for_test(
        self,
        record: FullResumeRecord,
        expires_at: u64,
        sas_base: &VerifiedRecord,
        manifest: &SourceManifest,
        now: u64,
    ) -> Result<FullTransferStage<'db>, StorageError> {
        self.bind_record(record, expires_at, sas_base, manifest, now)
    }
    fn bind_record(
        self,
        record: FullResumeRecord,
        expires_at: u64,
        sas_base: &VerifiedRecord,
        manifest: &SourceManifest,
        now: u64,
    ) -> Result<FullTransferStage<'db>, StorageError> {
        self.context()?.require_source_live()?;
        if record.role != PairingRole::Initiator {
            return Err(context());
        }
        if expires_at <= now || record.grant.expires_at <= now {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        super::super::native_floor::validate_sas_base(&record, sas_base)?;
        let (snapshot_id, encoded) = self.prepared.as_ref().ok_or_else(context)?;
        manifest.validate().map_err(|_| mismatch())?;
        matches_encoding(manifest, snapshot_id, encoded)?;
        let body = &manifest.manifest;
        if body.transfer_id != record.transfer_id
            || body.base_record_hash != record.base_record_hash
            || body.source_ref != record.grant.source_ref
            || body.destination_ref != record.grant.destination_ref
            || ramflux_protocol::encode_base64url(manifest_hash(manifest).map_err(|_| mismatch())?)
                != record.base_manifest_hash
        {
            return Err(mismatch());
        }
        ramflux_crypto::verify_canonical_signature(
            &body.signing_bytes().map_err(|_| mismatch())?,
            &manifest.source_signature,
            &record.grant.branch_keys.source,
        )?;
        let (schema, erasure): (u64, u64) =
            self.context()?.with_source_cut(0, snapshot_id, |input| {
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
        if body.storage_generation.0 != schema || body.source_erasure_generation.0 != erasure {
            return Err(StorageError::PairingField("SnapshotInvalidated"));
        }
        // Validate before changing a wrapper, directory or durable resume row.
        record.stage_digest()?;
        let transfer_id = record.transfer_id.clone();
        let directory = if transfer_id == self.preparation_id {
            self.directory.clone()
        } else {
            stage_directory(self.db, &transfer_id, true)?
        };
        let wrapped = self.key.wrap_for(&raw32(&transfer_id)?, PairingRole::Initiator)?;
        write_new_atomic(&self.directory, "stage.key", &wrapped.to_file_bytes()?)?;
        // Close SQLite before moving its directory: future journals must use the final path.
        drop(self.connection);
        if directory != self.directory {
            std::fs::rename(&self.directory, &directory)?;
            crate::sync_path::sync_path(directory.parent().ok_or_else(context)?)?;
        }
        let connection = self.key.open_metadata(&directory.join("stage.db"))?;
        connection.execute_batch("DROP TABLE IF EXISTS source_preparation_ready")?;
        sync_stage(&directory)?;
        if self.cancelled.load(super::Ordering::Acquire) {
            return Err(StorageError::PairingField("Cancelled"));
        }
        FullTransferStage::finish_prepared_source(
            SourceBindParts {
                connection,
                lock: self.lock,
                key: self.key,
                db: self.db,
                directory,
                cancelled: self.cancelled,
            },
            record,
            expires_at,
            sas_base,
            manifest,
        )
    }
}
