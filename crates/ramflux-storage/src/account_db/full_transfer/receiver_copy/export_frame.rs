// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Record a framed export during off-loan replay.
//! An existing device already holds rows. This path does not apply the fresh-target gate,
//! which belongs to the live-account install.
//! `private.db` stays the full receiver snapshot from `copy`. `prepare` opens that file
//! with the full-account checks (storage generation, migration rows, copy-key fingerprint).
//! The clean export is a generation-0 15-table file and cannot pass those checks. Its
//! keyed digests are retained, then the clean file is removed.

use super::FullReceiverBaseCopy;
use crate::StorageError;
use crate::account_db::full_transfer::receiver_read::ReceiverInput;
use crate::account_db::full_transfer::retained_digest::ExportRetain;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::{ManifestKind, SourceManifest};
use std::io::{Read as _, Seek as _};
use std::path::Path;

impl FullReceiverBaseCopy {
    /// Retain this framed export cut and keep the full snapshot as `private.db`.
    /// # Errors
    /// `WrongContext` for a non-export census, a tail, or a foreign stage.
    /// `ManifestMismatch` when the frame length disagrees. `RecipientNotFresh` is not used.
    pub(in crate::account_db::full_transfer) fn install_export_frame(
        &mut self,
        stage: &(impl ReceiverInput + ExportRetain),
        hash: &str,
    ) -> Result<super::super::FullScalarInputCounts, StorageError> {
        let manifest = stage.forward_manifest(hash)?;
        self.admit_export_frame(stage, hash, &manifest)?;
        let rows = self.write_export_frame(stage, hash, &manifest)?;
        self.finish_export_frame(stage, hash, &manifest, rows)
    }

    fn admit_export_frame(
        &mut self,
        stage: &impl ReceiverInput,
        hash: &str,
        manifest: &SourceManifest,
    ) -> Result<(), StorageError> {
        if !super::super::export_tail::is_export_census(&manifest.manifest.census_hash)? {
            return Err(super::wrong());
        }
        stage.require_io()?;
        let record = stage.resume_record()?;
        if record.stage_digest()? != self.stage_digest
            || record.role != PairingRole::Responder
            || record.grant.destination_ref.account_anchor != stage.principal()
            || record.grant.source_ref.account_anchor != stage.principal()
        {
            return Err(super::wrong());
        }
        match manifest.manifest.kind {
            ManifestKind::Base if self.hash == hash => Ok(()),
            ManifestKind::Delta => {
                let previous = stage.forward_manifest(&self.hash)?;
                manifest.verify_predecessor(&previous).map_err(|_| super::wrong())
            }
            ManifestKind::Base | ManifestKind::Tail => Err(super::wrong()),
        }?;
        self.projected = None;
        self.union = None;
        self.export_installed = false;
        self.attested.lock().map_err(|_| super::wrong())?.take();
        stage.require_target(&self.observation)
    }

    fn write_export_frame(
        &self,
        stage: &impl ReceiverInput,
        hash: &str,
        manifest: &SourceManifest,
    ) -> Result<u64, StorageError> {
        let clean = self.scratch.path.join("private-clean.db");
        let mut reader = stage.forward_reader(hash)?;
        let built = super::super::export_cut::install_framed_export(
            &mut reader,
            &clean,
            &self.key,
            &manifest.manifest.account_anchor,
        )?;
        let mut extra = [0_u8; 1];
        let trailing = reader.read(&mut extra)?;
        if trailing != 0 || reader.stream_position()? != manifest.manifest.total_bytes.0 {
            drop(reader);
            discard_database(&clean);
            return Err(StorageError::PairingField("ManifestMismatch"));
        }
        drop(reader);
        Ok(built.rows)
    }

    fn finish_export_frame(
        &mut self,
        stage: &(impl ReceiverInput + ExportRetain),
        hash: &str,
        manifest: &SourceManifest,
        rows: u64,
    ) -> Result<super::super::FullScalarInputCounts, StorageError> {
        let clean = self.scratch.path.join("private-clean.db");
        if let Err(error) = stage.retain_export_frame(
            &clean,
            &self.key,
            &manifest.manifest.account_anchor,
            self.erasure_generation,
        ) {
            discard_database(&clean);
            return Err(error);
        }
        discard_database(&clean);
        let chunks_root = super::decode_root(&manifest.manifest.chunks_root)?;
        let counts = super::super::FullScalarInputCounts {
            records: rows,
            encoded_bytes: manifest.manifest.total_bytes.0,
        };
        let sealed = super::seal::CopySeal::capture(&self.scratch.path)?;
        sealed.require(&self.scratch.path)?;
        stage.require_target(&self.observation)?;
        *self.attested.lock().map_err(|_| super::wrong())? = Some(sealed);
        self.union = Some(super::super::FullUnionEncoding {
            generation_nonce: self.contributions.nonce,
            records: rows,
            total_bytes: manifest.manifest.total_bytes.0,
            chunks_root,
        });
        self.projected = Some(counts);
        self.export_installed = true;
        if manifest.manifest.kind == ManifestKind::Delta {
            hash.clone_into(&mut self.hash);
        }
        Ok(counts)
    }
}

fn discard_database(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-journal"));
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}
