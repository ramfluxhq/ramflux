// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only receiver input shared by short loans and independently owned replay work.
use super::{
    FamilyRule, FullScalarInputCounts, FullTargetObservation, FullTransferStage,
    source_scalar::SourceGuard,
};
use crate::StorageError;
use ramflux_crypto::custody::pairing::FullResumeRecord;
use ramflux_protocol::custody::pairing::full_transfer::SourceManifest;

mod work;
pub use work::FullReceiverReplayWork;

pub(super) trait ReadSeek: std::io::Read + std::io::Seek {}
impl<T: std::io::Read + std::io::Seek> ReadSeek for T {}
pub(super) trait ReceiverInput {
    fn require_io(&self) -> Result<(), StorageError>;
    fn resume_record(&self) -> Result<FullResumeRecord, StorageError>;
    fn forward_manifest(&self, hash: &str) -> Result<SourceManifest, StorageError>;
    fn forward_reader(&self, hash: &str) -> Result<Box<dyn ReadSeek + '_>, StorageError>;
    fn require_target(&self, observation: &FullTargetObservation) -> Result<(), StorageError>;
    fn source_guard(&self) -> SourceGuard;
    fn principal(&self) -> &str;
    fn index_forward_scalar_records(
        &self,
        hash: &str,
        rules: &[FamilyRule],
    ) -> Result<FullScalarInputCounts, StorageError>;
}
impl ReceiverInput for FullTransferStage<'_> {
    fn require_io(&self) -> Result<(), StorageError> {
        self.require_io()
    }
    fn resume_record(&self) -> Result<FullResumeRecord, StorageError> {
        self.resume_record()
    }
    fn forward_manifest(&self, hash: &str) -> Result<SourceManifest, StorageError> {
        self.forward_manifest(hash)
    }
    fn forward_reader(&self, hash: &str) -> Result<Box<dyn ReadSeek + '_>, StorageError> {
        Ok(Box::new(self.forward_reader(hash)?))
    }
    fn require_target(&self, observation: &FullTargetObservation) -> Result<(), StorageError> {
        observation.require_current(self.db)
    }
    fn source_guard(&self) -> SourceGuard {
        SourceGuard::new(self.db, Some(self.source_cancelled.clone()))
    }
    fn principal(&self) -> &str {
        &self.db.principal_commitment
    }
    fn index_forward_scalar_records(
        &self,
        hash: &str,
        rules: &[FamilyRule],
    ) -> Result<FullScalarInputCounts, StorageError> {
        self.index_forward_scalar_records(hash, rules)
    }
}
