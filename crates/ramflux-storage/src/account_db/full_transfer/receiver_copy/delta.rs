// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-G2 private successors retain independent B provenance and all union/max restrictions.
use super::*;
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
        self.project_delta_input(stage, hash)
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
        let snapshot = super::super::snapshot_receive::active();
        let counts = if snapshot {
            None
        } else {
            Some(stage.index_forward_scalar_records(hash, super::super::full_transfer_catalog())?)
        };
        self.projected = None;
        self.union = None;
        self.attested.lock().map_err(|_| wrong())?.take();
        let (counts, encoding, private) = if let Some(counts) = counts {
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
            (counts, encoding, private)
        } else {
            // A later cut is a complete snapshot; the monotonic merge subsumes the earlier one.
            let counts = super::super::snapshot_receive::merge_cut(
                stage,
                hash,
                &self.scratch.path,
                &self.key,
            )?;
            let private = BackupDatabase::open_full_receiver_copy(
                &self.scratch.path.join("private.db"),
                &self.key,
            )?;
            let encoding = super::super::snapshot_receive::union(
                &self.scratch.path.join("contributions.db"),
                &self.key,
                self.contributions.nonce,
                &private,
            )?;
            (counts, encoding, private)
        };
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
