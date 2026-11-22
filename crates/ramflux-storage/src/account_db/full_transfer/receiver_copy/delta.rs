// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-G2 private successors retain independent B provenance and all union/max restrictions.
use super::*;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::ManifestKind;
impl FullReceiverBaseCopy {
    /// Apply one consecutive retained delta to the SAME private B generation.
    /// Every input is reindexed/root checked, restrictive puts run first, and an absence
    /// removes only the source's content contribution. B's rows and vetoes survive.
    /// This grants no DV/publication and selects no live paths. Changed live B needs rebase.
    /// # Errors
    /// Refuses a foreign stage/chain, changed B, malformed input or inconsistent actual rows.
    pub fn project_delta(
        &mut self,
        stage: &FullTransferStage<'_>,
        hash: &str,
    ) -> Result<FullScalarInputCounts, StorageError> {
        let next = stage.forward_manifest(hash)?;
        if super::super::export_tail::is_export_census(&next.manifest.census_hash)? {
            self.verify_input(stage)?;
            return self.install_export_delta(stage, hash);
        }
        self.project_delta_input(stage, hash)
    }
    pub(super) fn install_export_delta(
        &mut self,
        stage: &FullTransferStage<'_>,
        hash: &str,
    ) -> Result<FullScalarInputCounts, StorageError> {
        let previous = stage.forward_manifest(&self.hash)?;
        let next = stage.forward_manifest(hash)?;
        if next.manifest.kind != ManifestKind::Delta {
            return Err(wrong());
        }
        next.verify_predecessor(&previous).map_err(|_| wrong())?;
        self.replace_export_file(stage, hash, &next)
    }
    fn replace_export_file(
        &mut self,
        stage: &FullTransferStage<'_>,
        hash: &str,
        manifest: &ramflux_protocol::custody::pairing::full_transfer::SourceManifest,
    ) -> Result<FullScalarInputCounts, StorageError> {
        self.projected = None;
        self.union = None;
        self.export_installed = false;
        self.attested.lock().map_err(|_| wrong())?.take();
        stage.require_io()?;
        let record = stage.resume_record()?;
        if record.stage_digest()? != self.stage_digest
            || record.role != PairingRole::Responder
            || record.grant.destination_ref.account_anchor != stage.db.principal_commitment
            || record.grant.source_ref.account_anchor != stage.db.principal_commitment
        {
            return Err(wrong());
        }
        stage.db.require_fresh_transfer_target()?;
        self.observation.require_current(stage.db)?;
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
            let _ = std::fs::remove_file(&clean);
            return Err(StorageError::PairingField("ManifestMismatch"));
        }
        drop(reader);
        let private = self.scratch.path.join("private.db");
        if let Err(error) = std::fs::rename(&clean, &private) {
            let _ = std::fs::remove_file(&clean);
            return Err(error.into());
        }
        super::super::stage::sync_regular(&private)?;
        if let Err(error) =
            stage.retain_installed_export(&private, &self.key, &manifest.manifest.account_anchor)
        {
            let _ = std::fs::remove_file(&private);
            return Err(error);
        }
        let counts = FullScalarInputCounts {
            records: built.rows,
            encoded_bytes: manifest.manifest.total_bytes.0,
        };
        let sealed = super::seal::CopySeal::capture(&self.scratch.path)?;
        sealed.require(&self.scratch.path)?;
        self.observation.require_current(stage.db)?;
        *self.attested.lock().map_err(|_| wrong())? = Some(sealed);
        self.union = Some(super::super::FullUnionEncoding {
            generation_nonce: self.contributions.nonce,
            records: built.rows,
            total_bytes: manifest.manifest.total_bytes.0,
            chunks_root: super::decode_root(&manifest.manifest.chunks_root)?,
        });
        self.projected = Some(counts);
        self.export_installed = true;
        hash.clone_into(&mut self.hash);
        Ok(counts)
    }
    pub(in crate::account_db::full_transfer) fn project_delta_input(
        &mut self,
        stage: &impl super::super::receiver_read::ReceiverInput,
        hash: &str,
    ) -> Result<FullScalarInputCounts, StorageError> {
        self.verify_input(stage)?;
        let previous = stage.forward_manifest(&self.hash)?;
        let next = stage.forward_manifest(hash)?;
        if next.manifest.kind != ManifestKind::Delta {
            return Err(wrong());
        }
        next.verify_predecessor(&previous).map_err(|_| wrong())?;
        let counts =
            stage.index_forward_scalar_records(hash, super::super::full_transfer_catalog())?;
        self.projected = None;
        self.union = None;
        self.attested.lock().map_err(|_| wrong())?.take();
        let mut private = BackupDatabase::open_full_receiver_copy(
            &self.scratch.path.join("private.db"),
            &self.key,
        )?;
        let encoding = self.contributions.advance(
            &self.scratch.path.join("contributions.db"),
            &self.key,
            &mut private,
            stage,
            hash,
        )?;
        let sealed = super::seal::CopySeal::capture(&self.scratch.path)?;
        super::super::receiver_materialization::Verification {
            directory: &self.scratch.path,
            key: &self.key,
            encoding: &encoding,
            owners: &self.contributions.owners,
            private: &private,
            private_key: &self.key,
            stage,
        }
        .run()?;
        drop(private);
        sealed.require(&self.scratch.path)?;
        stage.require_target(&self.observation)?;
        *self.attested.lock().map_err(|_| wrong())? = Some(sealed);
        hash.clone_into(&mut self.hash);
        self.projected = Some(counts);
        self.union = Some(encoding);
        Ok(counts)
    }
}

#[cfg(test)]
mod tests;
