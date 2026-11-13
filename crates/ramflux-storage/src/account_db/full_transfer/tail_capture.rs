// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! J6's one-shot read view becomes an encrypted retained cut without borrowing A's writer.
use super::{FullTransferStage, source_owner::SourceContext, source_scalar::SourceGuard};
use crate::{FullTransferCut, StorageError, database::Connection};
use ramflux_protocol::custody::pairing::full_transfer::{DataPacket, SourceManifest};
use rusqlite::OptionalExtension as _;
use std::{
    fs::File,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}

/// The exact read view reserved by this source's J6 transaction. No public constructor.
/// This is neither a raw key exporter nor permission to merge or publish a tail.
pub struct FullSourceTailCut {
    pub(super) cut: FullTransferCut,
    pub(super) operation: String,
    pub(super) stage: String,
    pub(super) snapshot: String,
    pub(super) hash: String,
}
/// Bulk source-only copying, holding encrypted stage metadata and weak original unlock.
/// The frontend must return its ordinary database loan before running this owner.
pub struct FullSourceTailWork {
    connection: Connection,
    _lock: File,
    key: super::keys::FullSourceMetadataKey,
    guard: SourceGuard,
    directory: PathBuf,
    cancelled: Arc<AtomicBool>,
    cut: FullTransferCut,
    snapshot: String,
    ordinal: u64,
}
impl FullSourceTailCut {
    /// Move only the matching retained source stage into off-loan bulk copying.
    /// # Errors
    /// Refuses another J6/stage/cut, missing final DV, lost unlock or a changed marker.
    pub fn into_private_work(
        self,
        stage: FullTransferStage<'_>,
    ) -> Result<FullSourceTailWork, StorageError> {
        stage.require_io()?;
        let (snapshot, ordinal) = stage.tail_capture_identity()?;
        let head = stage.db.pairing_head()?.ok_or_else(wrong)?;
        if self.operation != head.operation_id
            || self.stage != stage.reference().stage_id
            || self.snapshot != snapshot
            || self.hash != head.candidate_hash
        {
            return Err(wrong());
        }
        let guard = SourceGuard::new(stage.db, Some(stage.source_cancelled.clone()));
        let key = stage.key.source_job_key(guard.clone())?;
        Ok(FullSourceTailWork {
            connection: stage.connection,
            _lock: stage.lock,
            key,
            guard,
            directory: stage.directory,
            cancelled: stage.source_cancelled,
            cut: self.cut,
            snapshot,
            ordinal,
        })
    }
}
impl FullSourceTailWork {
    /// Copy and fsync the immutable J6 view and commit its independent key in encrypted stage SQL.
    /// A crash before key commit cannot be repaired by recutting a later source view.
    /// # Errors
    /// Refuses lost unlock, cancellation, unsafe scratch or copying/adoption failure.
    pub fn copy(self) -> Result<(), StorageError> {
        self.guard.require()?;
        let pending = self.directory.join(format!("pending-source-{}.db", self.snapshot));
        let snapshot = self.cut.write_private_snapshot(&pending, self.cancelled)?;
        let source = SourceContext {
            key: &self.key,
            connection: &self.connection,
            guard: self.guard,
            directory: &self.directory,
        };
        source.adopt_source_cut(self.ordinal, &self.snapshot, &pending, snapshot)?;
        super::stage::sync_stage(&self.directory)?;
        source.require_source_live()
    }
}
impl FullTransferStage<'_> {
    fn tail_capture_identity(&self) -> Result<(String, u64), StorageError> {
        self.require_io()?;
        let record = self.resume_record()?;
        if record.role != ramflux_crypto::custody::pairing::PairingRole::Initiator {
            return Err(wrong());
        }
        let head = self.db.pairing_head()?.ok_or_else(wrong)?;
        if head.state != "acknowledged" || head.kind != "transfer" {
            return Err(wrong());
        }
        let live = self
            .db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == head.operation_id)
            .ok_or_else(wrong)?;
        if live.full_stage_reference()?.as_ref() != Some(self.reference()) {
            return Err(wrong());
        }
        let snapshot: String = self.db.connection.query_row(
            "SELECT snapshot_id FROM pairing_full_tail WHERE account_id=?1 AND operation_id=?2 AND stage_id=?3 AND record_hash=?4 AND tail_status='pending'",
            rusqlite::params![self.db.local_account_id,head.operation_id,self.reference().stage_id,head.candidate_hash],|row|row.get(0))?;
        super::stage::raw32(&snapshot)?;
        let Some(DataPacket::DataVerified { manifest_hash: hash, .. }) =
            self.source_last_data_verified()?
        else {
            return Err(wrong());
        };
        let parent: SourceManifest = self.forward_manifest(&hash)?;
        if !parent.manifest.is_last_prepublication_delta() {
            return Err(wrong());
        }
        Ok((snapshot, parent.manifest.snapshot_cut.0 + 1))
    }
    /// Complete/reconcile only the exact already-keyed J6 cut after the off-loan copy.
    /// Missing bytes/key explicitly invalidate the opportunity; this never pins a new view.
    /// # Errors
    /// Refuses a missing/corrupt immutable cut, changed J6 or unavailable original unlock.
    pub fn finish_source_tail_capture(&self) -> Result<(), StorageError> {
        let (snapshot, ordinal) = self.tail_capture_identity()?;
        let saved: Option<String> = self
            .connection
            .query_row(
                "SELECT snapshot_id FROM source_cut WHERE cut=?1",
                rusqlite::params![ordinal],
                |row| row.get(0),
            )
            .optional()?;
        if saved.as_deref() != Some(snapshot.as_str()) {
            return Err(StorageError::PairingField("SnapshotInvalidated"));
        }
        self.source_cut_schema(ordinal, &snapshot, super::full_transfer_catalog())?;
        if self.db.connection.execute("UPDATE pairing_full_tail SET cut_state='durable' WHERE account_id=?1 AND operation_id=?2 AND stage_id=?3 AND snapshot_id=?4 AND tail_status='pending'",rusqlite::params![self.db.local_account_id,self.db.pairing_head()?.ok_or_else(wrong)?.operation_id,self.reference().stage_id,snapshot])? != 1 { return Err(wrong()); }
        Ok(())
    }
}
