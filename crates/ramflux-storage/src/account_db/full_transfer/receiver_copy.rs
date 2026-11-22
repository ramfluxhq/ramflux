// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiver-owned qualified private generation; selection requires its separate owner.
use super::{
    FullScalarInputCounts, FullTargetObservation, FullTransferStage, receiver_scratch::Scratch,
};
use crate::{AccountDbKey, BackupDatabase, StorageError, account_db::backup::FullTransferCut};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::{ManifestKind, SourceManifest};
use std::io::{Read as _, Seek as _};
use std::sync::{Arc, atomic::AtomicBool};

pub(super) mod application;
mod delta;
mod generation;
pub(super) mod rebase;
pub use application::FullAppliedDataReceipt;
pub use generation::{
    FullGenerationRecoveryDraft, FullGenerationRecoveryWork, FullPreparedReceiverDatabase,
    FullReceiverDatabaseWork, FullSelectedReceiverGeneration,
};

mod incremental;
mod seal;
mod sql_delta;

fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}

/// Actual B read cut and optimistic writer observation, pinned in the same local loan.
/// Contains no approval or original writer ownership. Drop the stage/writer loan before
/// the bounded disk copy; root cancellation must drain the worker that owns this value.
pub struct FullPinnedReceiverBase {
    cut: FullTransferCut,
    observation: FullTargetObservation,
    stage_digest: [u8; 32],
    hash: String,
    scratch: Scratch,
    cancelled: Arc<AtomicBool>,
    owners: [ramflux_protocol::custody::DeviceRef; 2],
    schema: super::FullTransferSchema,
}

/// Device-local encrypted B copy with its non-forgeable original-cut provenance.
/// No Debug/serde/clone, no externally supplied database/key/path, and no wire export.
/// A copy or projection alone grants no `DataVerified`, installation or publication.
pub struct FullReceiverBaseCopy {
    projected: Option<FullScalarInputCounts>,
    contributions: super::receiver_contributions::Contributions,
    union: Option<super::FullUnionEncoding>,
    key: AccountDbKey,
    observation: FullTargetObservation,
    stage_digest: [u8; 32],
    hash: String,
    // Close the encrypted database and erase its key before removing its scratch directory.
    scratch: Scratch,
    attested: std::sync::Mutex<Option<seal::CopySeal>>,
    /// The private file is a clean export copy, not a record projection.
    export_installed: bool,
}

impl FullTransferStage<'_> {
    /// Pin the actual current B writer for this exact retained original-source base.
    /// Release the stage and writer owner before calling the returned owner's `copy`.
    /// # Errors
    /// Refuses source role, foreign account, non-base input, lost unlock or unsafe scratch.
    pub fn pin_receiver_base(&self, hash: &str) -> Result<FullPinnedReceiverBase, StorageError> {
        self.require_io()?;
        let record = self.resume_record()?;
        rebase::require_before_selection(self)?;
        let manifest = self.forward_manifest(hash)?;
        if record.role != ramflux_crypto::custody::pairing::PairingRole::Responder
            || record.grant.destination_ref.account_anchor != self.db.principal_commitment
            || manifest.manifest.kind
                != ramflux_protocol::custody::pairing::full_transfer::ManifestKind::Base
        {
            return Err(wrong());
        }
        let (cut, observation) = self.db.pin_full_transfer_target()?;
        let (schema, _, _) = cut.inspect_full_profile_cut()?;
        schema.require_typed_owners(super::full_transfer_catalog())?;
        let scratch =
            Scratch::create(&self.directory, self.retained_receiver_workspace()?.as_deref())?;
        self.require_io()?;
        observation.require_current(self.db)?;
        Ok(FullPinnedReceiverBase {
            cut,
            observation,
            stage_digest: record.stage_digest()?,
            hash: hash.into(),
            scratch,
            cancelled: self.source_cancelled.clone(),
            owners: [record.grant.source_ref, record.grant.destination_ref],
            schema,
        })
    }
}
impl FullPinnedReceiverBase {
    /// Copy B's pinned database in bounded encrypted page batches after releasing its loan.
    /// # Errors
    /// Refuses cancellation, lost actual writer, stale selection, low space or failed I/O.
    pub fn copy(self) -> Result<FullReceiverBaseCopy, StorageError> {
        let path = self.scratch.path.join("private.db");
        let snapshot = self.cut.write_private_snapshot(&path, self.cancelled.clone())?;
        let private = BackupDatabase::open_full_receiver_copy(&path, &snapshot.key)?;
        let contributions = super::receiver_contributions::Contributions::capture(
            &self.scratch.path.join("contributions.db"),
            &snapshot.key,
            &private,
            [&self.owners[0], &self.owners[1]],
            &self.cancelled,
            &self.schema,
        )?;
        drop(private);
        Ok(FullReceiverBaseCopy {
            projected: None,
            contributions,
            union: None,
            key: snapshot.key,
            observation: self.observation,
            stage_digest: self.stage_digest,
            hash: self.hash,
            scratch: self.scratch,
            attested: std::sync::Mutex::new(None),
            export_installed: false,
        })
    }
}
impl FullReceiverBaseCopy {
    /// Original B's pinned paths and privacy version; data-only, never a reservation.
    #[must_use]
    pub const fn target_observation(&self) -> &super::FullTargetObservation {
        &self.observation
    }

    /// Qualified normalized fixed-base stream, still requiring semantic/install validation.
    #[must_use]
    pub const fn union_encoding(&self) -> Option<&super::FullUnionEncoding> {
        self.union.as_ref()
    }
    /// Exact signed input counts after the typed private projection; never DV evidence.
    #[must_use]
    pub const fn projected_input(&self) -> Option<FullScalarInputCounts> {
        self.projected
    }
    /// Recompute the qualified root and compare every actual prepared portable row.
    /// This grants no semantic receipt, generation selection or publication permission.
    /// # Errors
    /// Refuses changed B, wrong stage, missing/extra/altered private rows or a changed ledger.
    pub fn verify_materialization(
        &self,
        stage: &FullTransferStage<'_>,
    ) -> Result<(), StorageError> {
        self.verify_input(stage)
    }
    pub(super) fn verify_input(
        &self,
        stage: &impl super::receiver_read::ReceiverInput,
    ) -> Result<(), StorageError> {
        stage.require_io()?;
        stage.require_target(&self.observation)?;
        if stage.resume_record()?.stage_digest()? != self.stage_digest {
            return Err(wrong());
        }
        if self.export_installed {
            self.attested
                .lock()
                .map_err(|_| wrong())?
                .as_ref()
                .ok_or_else(wrong)?
                .require(&self.scratch.path)?;
            stage.require_target(&self.observation)?;
            return Ok(());
        }
        self.attested.lock().map_err(|_| wrong())?.take();
        let encoding = self.union.as_ref().ok_or_else(wrong)?;
        let sealed = seal::CopySeal::capture(&self.scratch.path)?;
        let private = BackupDatabase::open_full_receiver_copy(
            &self.scratch.path.join("private.db"),
            &self.key,
        )?;
        super::receiver_materialization::Verification {
            directory: &self.scratch.path,
            key: &self.key,
            encoding,
            owners: &self.contributions.owners,
            private: &private,
            private_key: &self.key,
            stage,
        }
        .run()?;
        drop(private);
        sealed.require(&self.scratch.path)?;
        stage.require_target(&self.observation)?;
        *self.attested.lock().map_err(|_| wrong())? = Some(sealed);
        Ok(())
    }
    /// Require the same private files physically verified off-loan and unchanged B.
    /// This is only data-application evidence, never a signature or install authority.
    /// # Errors
    /// Refuses replaced/changed files, missing verification or another current B writer.
    pub fn require_materialized_generation(
        &self,
        stage: &FullTransferStage<'_>,
    ) -> Result<(), StorageError> {
        self.require_materialization_stamp(stage)
    }
    pub(super) fn require_materialization_stamp(
        &self,
        stage: &impl super::receiver_read::ReceiverInput,
    ) -> Result<(), StorageError> {
        stage.require_io()?;
        stage.require_target(&self.observation)?;
        if stage.resume_record()?.stage_digest()? != self.stage_digest || self.union.is_none() {
            return Err(wrong());
        }
        self.attested
            .lock()
            .map_err(|_| wrong())?
            .as_ref()
            .ok_or_else(wrong)?
            .require(&self.scratch.path)?;
        stage.require_target(&self.observation)
    }
    /// Recheck the original B writer and exact stage before applying retained signed bytes.
    /// The typed restrictive-first projection is atomic and keeps live B untouched. This
    /// establishes neither complete contribution provenance nor semantic/DV acceptance.
    /// # Errors
    /// Refuses a foreign/replaced stage, changed B, corrupt input or conflicting typed rows.
    pub fn project(
        &mut self,
        stage: &FullTransferStage<'_>,
    ) -> Result<FullScalarInputCounts, StorageError> {
        let manifest = stage.forward_manifest(&self.hash)?;
        let digest = crate::account_db::transfer_export::export_contract_digest()?;
        if manifest.manifest.census_hash == ramflux_protocol::encode_base64url(digest) {
            return self.project_export(stage, &manifest);
        }
        self.project_input(stage)
    }
    fn carry_installed_pairing(
        &self,
        stage: &FullTransferStage<'_>,
        private: &std::path::Path,
    ) -> Result<(), StorageError> {
        if let Err(error) =
            super::export_local::carry_local_pairing(&stage.db.connection, private, &self.key)
        {
            let _ = std::fs::remove_file(private);
            let _ = std::fs::remove_file(private.with_extension("db-journal"));
            let _ = std::fs::remove_file(private.with_extension("db-wal"));
            let _ = std::fs::remove_file(private.with_extension("db-shm"));
            stage.destroy_retained_digests()?;
            return Err(error);
        }
        Ok(())
    }
    /// Install a framed export: open the received file, keep only the clean copy, and do not
    /// parse family records. A non-fresh account refuses before the file is written.
    /// # Errors
    /// `RecipientNotFresh` before the file is written; `TransferExportRefused` at the open
    /// step that failed; `NoSpace`; `ManifestMismatch` when the stream length disagrees.
    fn project_export(
        &mut self,
        stage: &FullTransferStage<'_>,
        manifest: &SourceManifest,
    ) -> Result<FullScalarInputCounts, StorageError> {
        self.projected = None;
        self.union = None;
        self.export_installed = false;
        self.attested.lock().map_err(|_| wrong())?.take();
        stage.require_io()?;
        let record = stage.resume_record()?;
        if record.stage_digest()? != self.stage_digest
            || record.role != PairingRole::Responder
            || record.grant.destination_ref.account_anchor != stage.db.principal_commitment
            || record.grant.source_ref.account_anchor != stage.db.principal_commitment
            || manifest.manifest.kind != ManifestKind::Base
        {
            return Err(wrong());
        }
        stage.db.require_fresh_transfer_target()?;
        self.observation.require_current(stage.db)?;
        let clean = self.scratch.path.join("private-clean.db");
        let mut reader = stage.forward_reader(&self.hash)?;
        let built = super::export_cut::install_framed_export(
            &mut reader,
            &clean,
            &self.key,
            &manifest.manifest.account_anchor,
        )?;
        let mut extra = [0_u8; 1];
        let trailing = reader.read(&mut extra)?;
        if trailing != 0 || reader.stream_position()? != manifest.manifest.total_bytes.0 {
            drop(reader);
            let _ = std::fs::remove_file(&clean);
            return Err(StorageError::PairingField("ManifestMismatch"));
        }
        drop(reader);
        let private = self.scratch.path.join("private.db");
        if let Err(error) = std::fs::rename(&clean, &private) {
            let _ = std::fs::remove_file(&clean);
            return Err(error.into());
        }
        super::stage::sync_regular(&private)?;
        if let Err(error) =
            stage.retain_installed_export(&private, &self.key, &manifest.manifest.account_anchor)
        {
            let _ = std::fs::remove_file(&private);
            return Err(error);
        }
        self.carry_installed_pairing(stage, &private)?;
        let chunks_root = decode_root(&manifest.manifest.chunks_root)?;
        let counts = FullScalarInputCounts {
            records: built.rows,
            encoded_bytes: manifest.manifest.total_bytes.0,
        };
        let union = super::FullUnionEncoding {
            generation_nonce: self.contributions.nonce,
            records: built.rows,
            total_bytes: manifest.manifest.total_bytes.0,
            chunks_root,
        };
        let sealed = seal::CopySeal::capture(&self.scratch.path)?;
        sealed.require(&self.scratch.path)?;
        self.observation.require_current(stage.db)?;
        *self.attested.lock().map_err(|_| wrong())? = Some(sealed);
        self.union = Some(union);
        self.projected = Some(counts);
        self.export_installed = true;
        Ok(counts)
    }
    pub(super) fn project_input(
        &mut self,
        stage: &impl super::receiver_read::ReceiverInput,
    ) -> Result<FullScalarInputCounts, StorageError> {
        self.projected = None;
        self.union = None;
        self.export_installed = false;
        self.attested.lock().map_err(|_| wrong())?.take();
        stage.require_io()?;
        if stage.resume_record()?.stage_digest()? != self.stage_digest {
            return Err(wrong());
        }
        let mut private = BackupDatabase::open_full_receiver_copy(
            &self.scratch.path.join("private.db"),
            &self.key,
        )?;
        let counts = super::receiver_projection::project_fixed(
            stage,
            &self.hash,
            &mut private,
            &self.observation,
        )?;
        let union = self.contributions.finish(
            &self.scratch.path.join("contributions.db"),
            &self.key,
            &private,
            stage,
            &self.hash,
        )?;
        let sealed = seal::CopySeal::capture(&self.scratch.path)?;
        super::receiver_materialization::Verification {
            directory: &self.scratch.path,
            key: &self.key,
            encoding: &union,
            owners: &self.contributions.owners,
            private: &private,
            private_key: &self.key,
            stage,
        }
        .run()?;
        drop(private);
        sealed.require(&self.scratch.path)?;
        stage.require_target(&self.observation)?;
        *self.attested.lock().map_err(|_| wrong())? = Some(sealed);
        self.union = Some(union);
        self.projected = Some(counts);
        Ok(counts)
    }
}

fn decode_root(encoded: &str) -> Result<[u8; 32], StorageError> {
    let bytes = ramflux_protocol::decode_base64url(encoded)
        .map_err(|_| StorageError::PairingField("ManifestMismatch"))?;
    bytes.try_into().map_err(|_| StorageError::PairingField("ManifestMismatch"))
}

#[cfg(test)]
mod tests;
