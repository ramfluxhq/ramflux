// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiver-owned qualified private generation; selection requires its separate owner.
use super::{
    FullScalarInputCounts, FullTargetObservation, FullTransferStage, receiver_scratch::Scratch,
};
use crate::{AccountDbKey, BackupDatabase, StorageError, account_db::backup::FullTransferCut};
use std::sync::{Arc, atomic::AtomicBool};

pub(super) mod application;
mod delta;
mod generation;
pub(super) mod rebase;
pub use application::FullAppliedDataReceipt;
pub use generation::{
    FullPreparedReceiverDatabase, FullReceiverDatabaseWork, FullSelectedReceiverGeneration,
};

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
        let encoding = self.union.as_ref().ok_or_else(wrong)?;
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
        self.project_input(stage)
    }
    pub(super) fn project_input(
        &mut self,
        stage: &impl super::receiver_read::ReceiverInput,
    ) -> Result<FullScalarInputCounts, StorageError> {
        self.projected = None;
        self.union = None;
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
        stage.require_target(&self.observation)?;
        self.union = Some(union);
        self.projected = Some(counts);
        Ok(counts)
    }
}

#[cfg(test)]
mod tests;
