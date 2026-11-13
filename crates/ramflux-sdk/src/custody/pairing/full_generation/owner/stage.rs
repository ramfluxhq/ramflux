// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared data-install operations for live and terminal-reconciliation stage owners.
use crate::SdkError;
use ramflux_protocol::custody::DeviceRef;
use ramflux_storage::{
    AdoptionRow, BackupIndexInstall, FullDuplexReceipt, FullPreparedReceiverDatabase,
    FullReceiverBaseCopy, FullReceiverDatabaseWork, FullRecipientInstallStage,
    FullSelectedReceiverGeneration, FullStageReference, FullTransferStage,
};
use std::path::PathBuf;

pub(super) trait InstallStage {
    fn destination(&self) -> Result<DeviceRef, SdkError>;
    fn reference(&self) -> &FullStageReference;
    fn duplex(&self, now: u64) -> Result<FullDuplexReceipt, SdkError>;
    fn prepare(
        &self,
        copy: FullReceiverBaseCopy,
        path: PathBuf,
        adoption: AdoptionRow,
        now: u64,
    ) -> Result<FullReceiverDatabaseWork, SdkError>;
    fn select(
        &self,
        prepared: FullPreparedReceiverDatabase,
        write: &BackupIndexInstall<'_>,
        now: u64,
    ) -> Result<FullSelectedReceiverGeneration, SdkError>;
}
impl InstallStage for FullTransferStage<'_> {
    fn destination(&self) -> Result<DeviceRef, SdkError> {
        Ok(self.resume_record()?.grant.destination_ref)
    }
    fn reference(&self) -> &FullStageReference {
        self.reference()
    }
    fn duplex(&self, now: u64) -> Result<FullDuplexReceipt, SdkError> {
        Ok(self.verified_duplex(now)?)
    }
    fn prepare(
        &self,
        copy: FullReceiverBaseCopy,
        path: PathBuf,
        adoption: AdoptionRow,
        now: u64,
    ) -> Result<FullReceiverDatabaseWork, SdkError> {
        Ok(copy.into_generation_database_work(self, path, adoption, now)?)
    }
    fn select(
        &self,
        prepared: FullPreparedReceiverDatabase,
        write: &BackupIndexInstall<'_>,
        now: u64,
    ) -> Result<FullSelectedReceiverGeneration, SdkError> {
        Ok(prepared.select(self, write, now)?)
    }
}
impl InstallStage for FullRecipientInstallStage<'_> {
    fn destination(&self) -> Result<DeviceRef, SdkError> {
        Ok(self.destination_ref()?)
    }
    fn reference(&self) -> &FullStageReference {
        self.reference()
    }
    fn duplex(&self, _now: u64) -> Result<FullDuplexReceipt, SdkError> {
        Ok(self.verified_duplex()?)
    }
    fn prepare(
        &self,
        copy: FullReceiverBaseCopy,
        path: PathBuf,
        adoption: AdoptionRow,
        _now: u64,
    ) -> Result<FullReceiverDatabaseWork, SdkError> {
        Ok(self.prepare_generation(copy, path, adoption)?)
    }
    fn select(
        &self,
        prepared: FullPreparedReceiverDatabase,
        write: &BackupIndexInstall<'_>,
        _now: u64,
    ) -> Result<FullSelectedReceiverGeneration, SdkError> {
        Ok(self.select_generation(prepared, write)?)
    }
}
