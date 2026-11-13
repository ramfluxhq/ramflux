// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reapply the frozen source chain onto a newly pinned original B before G2 only.
use super::{FullReceiverBaseCopy, FullTransferStage, wrong};
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::ManifestKind;
use rusqlite::params;
use serde::Deserialize;

#[derive(Deserialize)]
struct Origin {
    origin: Option<String>,
    #[serde(default, deserialize_with = "present")]
    full_transfer: Option<Stage>,
}
#[derive(Deserialize)]
struct Stage {
    stage_id: String,
}
fn present<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Option<Stage>, D::Error> {
    Stage::deserialize(decoder).map(Some)
}
// Only inspect the public discriminator/stage ID. Legacy recovery metadata may
// contain secrets; its raw bytes erase and unknown fields are never materialized.
pub(in crate::account_db::full_transfer) fn require_before_selection(
    stage: &FullTransferStage<'_>,
) -> Result<(), StorageError> {
    let selected =
        stage.db.account_index.account_generation_selection(&stage.db.local_account_id)?;
    let Some(bytes) = selected.manifest_json.map(zeroize::Zeroizing::new) else {
        return Ok(());
    };
    let origin: Origin = ramflux_protocol::parse_i_json(&bytes)?;
    match (origin.origin.as_deref(), origin.full_transfer) {
        (None, None) => Ok(()),
        (Some("full_transfer"), Some(reference)) => {
            super::super::stage::raw32(&reference.stage_id)?;
            if reference.stage_id == stage.reference().stage_id { Err(wrong()) } else { Ok(()) }
        }
        _ => Err(wrong()),
    }
}
impl FullReceiverBaseCopy {
    /// Rebase the frozen, fully verified source input on this fresh pinned B copy.
    /// Call only before G2. The same selected full generation can never be repinned
    /// and relabeled as a new independent B contribution. This grants no new approval.
    /// # Errors
    /// Refuses stale B, incomplete/nonfinal input, a selected stage or malformed chain.
    pub fn project_retained_chain(
        &mut self,
        stage: &FullTransferStage<'_>,
        now: u64,
    ) -> Result<(), StorageError> {
        require_before_selection(stage)?;
        stage.verified_duplex(now)?;
        let mut hashes = Vec::new();
        let (last, _): (u64, String) = stage.connection.query_row(
            "SELECT cut,manifest_hash FROM manifest WHERE direction=0 ORDER BY cut DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if last == 0 || last > 8 {
            return Err(wrong());
        }
        for cut in 0..=last {
            hashes.push(stage.connection.query_row(
                "SELECT manifest_hash FROM manifest WHERE direction=0 AND cut=?1 AND verified=1",
                params![cut],
                |row| row.get(0),
            )?);
        }
        self.project_chain_input(stage, &hashes)
    }
    pub(in crate::account_db::full_transfer) fn project_chain_input(
        &mut self,
        stage: &impl super::super::receiver_read::ReceiverInput,
        hashes: &[String],
    ) -> Result<(), StorageError> {
        let record = stage.resume_record()?;
        if self.hash != record.base_manifest_hash || self.projected.is_some() {
            return Err(wrong());
        }
        let last = hashes.last().ok_or_else(wrong)?;
        if hashes.len() < 2
            || hashes.len() > 9
            || hashes.first() != Some(&record.base_manifest_hash)
            || !stage.forward_manifest(last)?.manifest.is_last_prepublication_delta()
        {
            return Err(wrong());
        }
        self.project_input(stage)?;
        for hash in hashes.iter().skip(1) {
            if stage.forward_manifest(hash)?.manifest.kind != ManifestKind::Delta {
                return Err(wrong());
            }
            self.project_delta_input(stage, hash)?;
        }
        self.verify_input(stage)
    }
}
