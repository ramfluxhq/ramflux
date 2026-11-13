// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded actual-A restrictive commits. Stage progress follows each idempotent account commit.
use super::{
    FullTransferStage, fixed_union::apply_fixed_base_in_transaction, full_transfer_catalog,
};
use crate::StorageError;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::{
    RecordHeader, RecordOp, read_record_header,
};
use rusqlite::{OptionalExtension as _, params};
use std::io::{Read as _, Seek as _, SeekFrom};
use zeroize::{Zeroize as _, Zeroizing};
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS reverse_merge_progress(manifest_hash TEXT PRIMARY KEY,stage_digest BLOB NOT NULL CHECK(length(stage_digest)=32),db_path TEXT NOT NULL,object_path TEXT NOT NULL,offset INTEGER NOT NULL CHECK(offset>=0),complete INTEGER NOT NULL CHECK(complete IN(0,1)));";
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
struct Record {
    header: RecordHeader,
    bytes: Zeroizing<Vec<u8>>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.header.key.zeroize();
    }
}
struct Progress {
    offset: u64,
    complete: bool,
}
impl FullTransferStage<'_> {
    /// Apply at most 32 exact restrictive records through the actual original-A writer.
    /// The complete input must already have passed owned off-loan validation. Every
    /// account commit precedes its private cursor update; replay only adds/max-merges.
    /// Return true only when this actual generation has consumed the complete input.
    /// # Errors
    /// Refuses an unvalidated/foreign input, changed A, unsupported rows or persistence failure.
    pub fn apply_restrictive_reverse_batch(
        &self,
        hash: &str,
        limit: u8,
    ) -> Result<bool, StorageError> {
        if limit == 0 || limit > 32 || self.resume_record()?.role != PairingRole::Initiator {
            return Err(wrong());
        }
        self.require_validated_reverse_input(hash)?;
        self.db.require_selected_transfer_source()?;
        let manifest = self.reverse_manifest(hash)?;
        let mut progress = self.reverse_merge_progress(hash)?;
        if progress.offset > manifest.manifest.total_bytes.0
            || (progress.complete && progress.offset != manifest.manifest.total_bytes.0)
        {
            return Err(wrong());
        }
        if progress.complete {
            return Ok(true);
        }
        let mut reader = self.validated_reverse_reader(hash)?;
        reader.seek(SeekFrom::Start(progress.offset))?;
        for _ in 0..limit {
            if progress.offset == manifest.manifest.total_bytes.0 {
                break;
            }
            self.require_io()?;
            let header = read_record_header(&mut reader).map_err(|_| wrong())?.ok_or_else(wrong)?;
            let mut record = Record { header, bytes: Zeroizing::new(Vec::new()) };
            let rule = full_transfer_catalog()
                .iter()
                .find(|rule| rule.id == record.header.family)
                .ok_or_else(wrong)?;
            if !rule.restrictive || record.header.op != RecordOp::Put {
                return Err(wrong());
            }
            let size = record
                .header
                .cell_lengths
                .iter()
                .try_fold(0_u64, |sum, length| sum.checked_add(length.0).ok_or_else(wrong))?;
            if size > 1024 {
                return Err(StorageError::PairingField("UnsupportedRecord"));
            }
            record.bytes = Zeroizing::new(vec![0; usize::try_from(size).map_err(|_| wrong())?]);
            reader.read_exact(&mut record.bytes)?;
            let source = manifest.manifest.source_ref.clone();
            self.db.connection.call(move |raw| {
                Ok((|| -> Result<(), StorageError> {
                    let tx =
                        raw.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                    apply_fixed_base_in_transaction(
                        &tx,
                        &source,
                        &record.header,
                        &mut record.bytes.as_slice(),
                    )?;
                    tx.commit()?;
                    Ok(())
                })())
            })??;
            self.db.require_selected_transfer_source()?;
            let next = reader.stream_position()?;
            self.advance_reverse_merge(hash, progress.offset, next, false)?;
            progress.offset = next;
        }
        if progress.offset == manifest.manifest.total_bytes.0 {
            self.advance_reverse_merge(hash, progress.offset, progress.offset, true)?;
            return Ok(true);
        }
        Ok(false)
    }
    fn reverse_merge_progress(&self, hash: &str) -> Result<Progress, StorageError> {
        self.connection.execute_batch(SCHEMA)?;
        let record = self.resume_record()?;
        let digest = record.stage_digest()?;
        let selected = self.db.account_index.account(&self.db.local_account_id)?;
        self.connection.execute("INSERT INTO reverse_merge_progress VALUES(?1,?2,?3,?4,0,0) ON CONFLICT(manifest_hash) DO NOTHING",params![hash,digest.as_slice(),selected.db_relative_path,selected.object_dir_relative_path])?;
        self.connection.query_row("SELECT offset,complete FROM reverse_merge_progress WHERE manifest_hash=?1 AND stage_digest=?2 AND db_path=?3 AND object_path=?4",params![hash,digest.as_slice(),selected.db_relative_path,selected.object_dir_relative_path],|row|Ok(Progress { offset:row.get(0)?,complete:row.get(1)? })).map_err(StorageError::from)
    }
    fn advance_reverse_merge(
        &self,
        hash: &str,
        old: u64,
        next: u64,
        complete: bool,
    ) -> Result<(), StorageError> {
        let selected = self.db.account_index.account(&self.db.local_account_id)?;
        let digest = self.resume_record()?.stage_digest()?;
        self.require_io()?;
        if self.connection.execute("UPDATE reverse_merge_progress SET offset=?1,complete=?2 WHERE manifest_hash=?3 AND offset=?4 AND stage_digest=?5 AND db_path=?6 AND object_path=?7",params![next,complete,hash,old,digest.as_slice(),selected.db_relative_path,selected.object_dir_relative_path])? != 1 { return Err(wrong()); }
        super::stage::sync_stage(&self.directory)?;
        self.require_io()
    }
    pub(super) fn require_reverse_merge_complete(&self, hash: &str) -> Result<(), StorageError> {
        self.require_validated_reverse_input(hash)?;
        self.db.require_selected_transfer_source()?;
        let manifest = self.reverse_manifest(hash)?;
        let selected = self.db.account_index.account(&self.db.local_account_id)?;
        let digest = self.resume_record()?.stage_digest()?;
        let complete: Option<bool> = self.connection.query_row("SELECT complete FROM reverse_merge_progress WHERE manifest_hash=?1 AND offset=?2 AND stage_digest=?3 AND db_path=?4 AND object_path=?5",params![hash,manifest.manifest.total_bytes.0,digest.as_slice(),selected.db_relative_path,selected.object_dir_relative_path],|row|row.get(0)).optional()?;
        if complete != Some(true) {
            return Err(wrong());
        }
        self.require_io()
    }
}

#[cfg(test)]
mod tests;
