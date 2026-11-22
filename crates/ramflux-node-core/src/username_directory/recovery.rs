// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated recovery sources preserve whole delete units and exact witness head equality.
use super::{
    CheckpointError, CheckpointHead, DirectoryAuthority, ImagePage, Result, WriterIdentity,
    checkpoint_batch, transitions::ensure,
};
use ramflux_protocol::username_directory::{self as w, DirectoryCode as Code};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGroup {
    pub records: Vec<w::Checkpoint>,
    pub batch: Option<w::BatchRow>,
}

impl DirectoryAuthority {
    /// Recovery is private to the authenticated writer; the service must additionally require
    /// controller recovery authority for an image rebuild. No mutation is accepted during rebuild.
    /// # Errors
    /// Refuses expired incarnations, changed source heads and out-of-bound cursors/pages.
    pub fn recovery_image_page(
        &mut self,
        writer: &WriterIdentity,
        expected: &CheckpointHead,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<ImagePage> {
        self.fence.check_writer(writer, self.witness.sample_time()?)?;
        ensure(self.head() == *expected, Code::DirectoryUnavailable)?;
        self.witness.image_page(after, limit)
    }

    /// Returns one complete next replay unit. Missing results require a privileged image rebuild;
    /// a primary at a batch's intermediate LSN is never repaired by applying just its delete.
    /// # Errors
    /// Refuses ahead/foreign/conflicting primary heads and missing or partial replay evidence.
    pub fn recovery_group(
        &mut self,
        writer: &WriterIdentity,
        primary: &CheckpointHead,
    ) -> Result<Option<RecoveryGroup>> {
        let time = self.witness.sample_time()?;
        self.fence.check_writer(writer, time)?;
        let head = self.head();
        ensure(
            primary.center_id == head.center_id
                && primary.generation == head.generation
                && primary.lsn <= head.lsn
                && primary.codec_version == head.codec_version
                && primary.policy == head.policy,
            Code::DirectoryUnavailable,
        )?;
        if primary.lsn == head.lsn {
            ensure(primary == &head, Code::DirectoryUnavailable)?;
            return Ok(None);
        }
        self.witness.update_aux(time, |tx| {
            if primary.lsn > 0 {
                let previous = checkpoint_batch::record(tx, primary.lsn)?;
                ensure(
                    ramflux_crypto::username_directory::checkpoint_hash(&previous)?
                        == primary.digest,
                    Code::DirectoryUnavailable,
                )?;
                if let Some(batch) = checkpoint_batch::member_batch(tx, &previous.delta.tx_id)? {
                    ensure(primary.lsn != batch.lsn_n1, Code::DirectoryUnavailable)?;
                }
            }
            let next = primary
                .lsn
                .checked_add(1)
                .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
            let record = checkpoint_batch::record(tx, next)?;
            ensure(
                record.previous_digest == primary.digest
                    && record.center_id == head.center_id
                    && record.generation == head.generation,
                Code::DirectoryUnavailable,
            )?;
            if let Some(batch) = checkpoint_batch::member_batch(tx, &record.delta.tx_id)? {
                ensure(record.lsn == batch.lsn_n1, Code::DirectoryUnavailable)?;
                Ok(Some(RecoveryGroup {
                    records: checkpoint_batch::pair(tx, &batch)?.to_vec(),
                    batch: Some(batch),
                }))
            } else {
                Ok(Some(RecoveryGroup { records: vec![record], batch: None }))
            }
        })
    }

    /// Compact a bounded retained-redo page only after its primary head is durably applied.
    /// # Errors
    /// Refuses retired/unapplied writers, unsafe clocks and corrupt retained associations.
    pub fn compact_applied(&mut self, writer: &WriterIdentity) -> Result<usize> {
        self.fence.check_ready(writer, &self.head(), self.witness.sample_time()?)?;
        self.witness.compact(self.head().lsn)
    }
}
