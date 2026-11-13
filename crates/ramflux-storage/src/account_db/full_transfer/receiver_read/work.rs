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
use std::sync::Arc;
struct Manifest {
    hash: String,
    manifest: SourceManifest,
    key: Arc<FullChunkReadKey>,
}
struct Input {
    connection: crate::database::Connection,
    lock: Arc<std::fs::File>,
    directory: std::path::PathBuf,
    record: FullResumeRecord,
    guard: SourceGuard,
    manifests: Vec<Manifest>,
}
/// Root-drained private projection with at most nine retained input manifests.
/// No original writer, database key, signer or publication permission is retained.
pub struct FullReceiverReplayWork {
    input: Input,
    copy: FullReceiverBaseCopy,
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
        self.require_io()?;
        super::super::receiver_copy::rebase::require_before_selection(&self)?;
        self.verified_duplex(now)?;
        copy.target_observation().require_current(self.db)?;
        let record = self.resume_record()?;
        if record.role != ramflux_crypto::custody::pairing::PairingRole::Responder {
            return Err(wrong());
        }
        let last: u64 = self.connection.query_row(
            "SELECT max(cut) FROM manifest WHERE direction=0",
            [],
            |row| row.get(0),
        )?;
        if last == 0 || last > 8 {
            return Err(wrong());
        }
        let guard = SourceGuard::new(self.db, Some(self.source_cancelled.clone()));
        let mut manifests = Vec::new();
        for cut in 0..=last {
            let hash: String = self.connection.query_row(
                "SELECT manifest_hash FROM manifest WHERE direction=0 AND cut=?1 AND verified=1",
                rusqlite::params![cut],
                |row| row.get(0),
            )?;
            let manifest = self.forward_manifest(&hash)?;
            let key = self.key.chunk_read_key(
                super::super::stage::raw32(&hash)?,
                StageDirection::Forward,
                guard.clone(),
            )?;
            manifests.push(Manifest { hash, manifest, key: Arc::new(key) });
        }
        guard.require()?;
        Ok(FullReceiverReplayWork {
            input: Input {
                connection: self.connection,
                lock: Arc::new(self.lock),
                directory: self.directory,
                record,
                guard,
                manifests,
            },
            copy,
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
        self.copy.project_chain_input(&self.input, &hashes)?;
        self.input.require_io()?;
        Ok(self.copy)
    }
}
impl ReceiverInput for Input {
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
