// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic PRIVATE fixed-base projection. No semantic receipt or generation selection.
use super::{
    FullScalarInputCounts, FullTargetObservation, FullTransferStage, full_transfer_catalog,
};
use crate::{BackupDatabase, StorageError};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::{
    ManifestKind, RecordHeader, read_record_header,
};
use std::io::Seek as _;
use zeroize::Zeroize as _;

fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
struct Header(RecordHeader);
impl Drop for Header {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}
struct Projection<'a> {
    private: &'a mut BackupDatabase,
    committed: bool,
}
impl Drop for Projection<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.private.db.execute_batch("ROLLBACK");
        }
    }
}
impl FullTransferStage<'_> {
    /// Apply a complete original-source-signed base through the compiled fixed owners
    /// into an already created PRIVATE target copy. The caller supplies the optimistic
    /// observation from pinning that target, and still owns copy provenance, contribution
    /// tracking, normalized union construction and final generation fencing. This method
    /// revalidates the actual slots/counts, applies restrictive rows first and rolls back
    /// the entire private transaction on any failure. It sets no semantic/DV marker.
    /// # Errors
    /// Refuses wrong role/account, non-base input, unsupported nonempty owners, bad input,
    /// changed live target, active private transactions or conflicting projected values.
    pub fn project_forward_fixed_base(
        &self,
        hash: &str,
        private: &mut BackupDatabase,
        observation: &FullTargetObservation,
    ) -> Result<FullScalarInputCounts, StorageError> {
        project_fixed(self, hash, private, observation)
    }
}
pub(super) fn project_fixed(
    stage: &impl super::receiver_read::ReceiverInput,
    hash: &str,
    private: &mut BackupDatabase,
    observation: &FullTargetObservation,
) -> Result<FullScalarInputCounts, StorageError> {
    stage.require_io()?;
    let record = stage.resume_record()?;
    let manifest = stage.forward_manifest(hash)?;
    if record.role != PairingRole::Responder
        || record.grant.destination_ref.account_anchor != stage.principal()
        || record.grant.source_ref.account_anchor != stage.principal()
        || manifest.manifest.kind != ManifestKind::Base
        || !private.db.is_autocommit()
    {
        return Err(StorageError::PairingField("WrongContext"));
    }
    stage.require_target(observation)?;
    let counts = stage.index_forward_scalar_records(hash, full_transfer_catalog())?;
    private.db.execute_batch("BEGIN IMMEDIATE")?;
    let mut pending = Projection { private, committed: false };
    for restrictive in [true, false] {
        project_pass(stage, hash, &mut pending, restrictive)?;
    }
    stage.require_io()?;
    stage.require_target(observation)?;
    pending.private.db.execute_batch("COMMIT")?;
    pending.committed = true;
    Ok(counts)
}

fn project_pass(
    stage: &impl super::receiver_read::ReceiverInput,
    hash: &str,
    pending: &mut Projection<'_>,
    restrictive: bool,
) -> Result<(), StorageError> {
    let source = stage.forward_manifest(hash)?.manifest.source_ref;
    let mut reader = stage.forward_reader(hash)?;
    let rules = full_transfer_catalog();
    while let Some(header) = read_record_header(&mut reader).map_err(|_| mismatch())? {
        stage.require_io()?;
        let header = Header(header);
        let index = rules
            .binary_search_by_key(&header.0.family.as_str(), |rule| rule.id)
            .map_err(|_| mismatch())?;
        let rule = rules.get(index).ok_or_else(mismatch)?;
        if rule.restrictive == restrictive {
            pending.private.apply_full_fixed_base_record(&source, &header.0, &mut reader)?;
        } else {
            super::copy_full_scalar_record(rule, &header.0, &mut reader, &mut std::io::sink())?;
        }
    }
    if reader.stream_position()? != stage.forward_manifest(hash)?.manifest.total_bytes.0 {
        return Err(mismatch());
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests;
