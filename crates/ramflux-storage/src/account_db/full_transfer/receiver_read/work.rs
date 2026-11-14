// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent encrypted retained-chain replay; never retains the actual B database or key.
use super::{
    FamilyRule, FullResumeRecord, FullScalarInputCounts, FullTargetObservation, FullTransferStage,
    ReceiverInput, SourceGuard, SourceManifest, StorageError,
};
use crate::account_db::full_transfer::{
    FullReceiverBaseCopy, StageDirection,
    keys::FullChunkReadKey,
    read_work::{Inputs, Reader},
};
use ramflux_protocol::custody::pairing::full_transfer::ManifestKind;
use std::sync::Arc;
struct RetainedCut {
    hash: String,
    manifest: SourceManifest,
    key: Arc<FullChunkReadKey>,
}
pub(in crate::account_db::full_transfer) struct OwnedReceiverInput {
    connection: crate::database::Connection,
    lock: Arc<std::fs::File>,
    directory: std::path::PathBuf,
    record: FullResumeRecord,
    guard: SourceGuard,
    manifests: Vec<RetainedCut>,
}
/// Root-drained private projection with at most nine retained input manifests.
/// No original writer, database key, signer or publication permission is retained.
pub struct FullReceiverReplayWork {
    input: OwnedReceiverInput,
    copy: FullReceiverBaseCopy,
    through_hash: String,
}
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl FullTransferStage<'_> {
    /// Pin independently owned decrypt-only input before replaying the retained chain.
    /// Drop the ordinary writer loan before calling `replay`.
    /// # Errors
    /// Refuses incomplete duplex, changed B, selected/foreign stages or malformed chains.
    pub fn into_receiver_replay_work(
        self,
        copy: FullReceiverBaseCopy,
        now: u64,
    ) -> Result<FullReceiverReplayWork, StorageError> {
        self.verified_duplex(now)?;
        let hash: String = self.connection.query_row(
            "SELECT manifest_hash FROM manifest WHERE direction=0 ORDER BY cut DESC LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        if !self.forward_manifest(&hash)?.manifest.is_last_prepublication_delta() {
            return Err(wrong());
        }
        self.into_receiver_replay_through(copy, &hash, now)
    }
    /// Reconstruct private B through one completely received retained base/delta.
    /// Earlier cuts must already be verified; the current cut still requires actual DV.
    /// Release the ordinary writer loan before `replay`.
    /// # Errors
    /// Refuses a selected/foreign stage, changed B, incomplete chain, expiry or a tail.
    pub fn into_receiver_replay_through(
        self,
        copy: FullReceiverBaseCopy,
        hash: &str,
        now: u64,
    ) -> Result<FullReceiverReplayWork, StorageError> {
        self.require_io()?;
        super::super::receiver_copy::rebase::require_before_selection(&self)?;
        copy.target_observation().require_current(self.db)?;
        let input = self.pin_receiver_read_input(hash, now)?;
        Ok(FullReceiverReplayWork { input, copy, through_hash: hash.into() })
    }
    pub(in crate::account_db::full_transfer) fn pin_receiver_read_input(
        &self,
        hash: &str,
        now: u64,
    ) -> Result<OwnedReceiverInput, StorageError> {
        self.pin_receiver_input(hash, now, false)
    }
    pub(in crate::account_db::full_transfer) fn pin_tail_read_input(
        &self,
        hash: &str,
        now: u64,
    ) -> Result<OwnedReceiverInput, StorageError> {
        self.pin_receiver_input(hash, now, true)
    }
    fn pin_receiver_input(
        &self,
        hash: &str,
        now: u64,
        tail: bool,
    ) -> Result<OwnedReceiverInput, StorageError> {
        self.require_io()?;
        let record = self.resume_record()?;
        if record.role != ramflux_crypto::custody::pairing::PairingRole::Responder
            || now >= record.grant.expires_at
            || now >= self.reference().lease_expires_at.0
        {
            return Err(wrong());
        }
        let current = self.forward_manifest(hash)?;
        let last = current.manifest.snapshot_cut.0;
        if last > if tail { 9 } else { 8 }
            || if tail {
                current.manifest.kind != ManifestKind::Tail
            } else {
                !matches!(current.manifest.kind, ManifestKind::Base | ManifestKind::Delta)
            }
        {
            return Err(wrong());
        }
        let guard = SourceGuard::new(self.db, Some(self.source_cancelled.clone()));
        let mut manifests = Vec::new();
        // Tail validation needs only its one bounded authenticated stream; its
        // prepublication chain/G3 are checked by the separate endpoint constructor.
        let first = if tail { last } else { 0 };
        for cut in first..=last {
            let hash: String = self.connection.query_row(
                "SELECT manifest_hash FROM manifest WHERE direction=0 AND cut=?1 AND (verified=1 OR cut=?2)",
                rusqlite::params![cut,last],
                |row| row.get(0),
            )?;
            let manifest = self.forward_manifest(&hash)?;
            let key = self.key.chunk_read_key(
                super::super::stage::raw32(&hash)?,
                StageDirection::Forward,
                guard.clone(),
            )?;
            manifests.push(RetainedCut { hash, manifest, key: Arc::new(key) });
        }
        if manifests.last().is_none_or(|item| item.hash != hash) {
            return Err(wrong());
        }
        guard.require()?;
        Ok(OwnedReceiverInput {
            connection: self.connection.clone(),
            lock: self.lock.clone(),
            directory: self.directory.clone(),
            record,
            guard,
            manifests,
        })
    }
}
impl FullReceiverReplayWork {
    /// Verify roots/records and replay union/max semantics without borrowing B's frontend.
    /// # Errors
    /// Refuses corrupt input, changed actual B, lock/cancel or inconsistent private bytes.
    pub fn replay(mut self) -> Result<FullReceiverBaseCopy, StorageError> {
        self.input.require_io()?;
        let hashes = self.input.manifests.iter().map(|item| item.hash.clone()).collect::<Vec<_>>();
        if self.copy.projected_input().is_some() {
            self.copy.project_delta_input(&self.input, &self.through_hash)?;
        } else {
            self.copy.project_prefix_input(&self.input, &hashes)?;
        }
        self.input.require_io()?;
        Ok(self.copy)
    }
}
impl OwnedReceiverInput {
    pub(in crate::account_db::full_transfer) fn directory(&self) -> &std::path::Path {
        &self.directory
    }
}
impl ReceiverInput for OwnedReceiverInput {
    fn require_io(&self) -> Result<(), StorageError> {
        self.guard.require()
    }
    fn resume_record(&self) -> Result<FullResumeRecord, StorageError> {
        self.require_io()?;
        Ok(FullResumeRecord {
            role: self.record.role,
            transcript: self.record.transcript.clone(),
            th: self.record.th,
            grant: self.record.grant.clone(),
            lease: self.record.lease.clone(),
            transfer_id: self.record.transfer_id.clone(),
            base_manifest_hash: self.record.base_manifest_hash.clone(),
            base_record_hash: self.record.base_record_hash.clone(),
        })
    }
    fn forward_manifest(&self, hash: &str) -> Result<SourceManifest, StorageError> {
        self.require_io()?;
        self.manifests
            .iter()
            .find(|item| item.hash == hash)
            .map(|item| item.manifest.clone())
            .ok_or_else(wrong)
    }
    fn forward_reader(&self, hash: &str) -> Result<Box<dyn super::ReadSeek + '_>, StorageError> {
        let manifest = self.manifests.iter().find(|item| item.hash == hash).ok_or_else(wrong)?;
        let mut reader = Reader::new(
            Inputs {
                connection: self.connection.clone(),
                lock: self.lock.clone(),
                directory: self.directory.clone(),
                key: manifest.key.clone(),
                direction: 0,
            },
            manifest.manifest.clone(),
            hash.into(),
            self.guard.clone(),
        );
        reader.verify_root()?;
        Ok(Box::new(reader))
    }
    fn require_target(&self, observation: &FullTargetObservation) -> Result<(), StorageError> {
        self.require_io()?;
        observation.require_current_off_loan()
    }
    fn source_guard(&self) -> SourceGuard {
        self.guard.clone()
    }
    fn principal(&self) -> &str {
        &self.record.grant.destination_ref.account_anchor
    }
    fn index_forward_scalar_records(
        &self,
        hash: &str,
        rules: &[FamilyRule],
    ) -> Result<FullScalarInputCounts, StorageError> {
        let mut counts = FullScalarInputCounts { records: 0, encoded_bytes: 0 };
        super::super::stage_validation::visit_input(self, hash, rules, |_, _, bytes| {
            counts.records = counts.records.checked_add(1).ok_or_else(wrong)?;
            counts.encoded_bytes = counts.encoded_bytes.checked_add(bytes).ok_or_else(wrong)?;
            Ok(())
        })?;
        Ok(counts)
    }
}
