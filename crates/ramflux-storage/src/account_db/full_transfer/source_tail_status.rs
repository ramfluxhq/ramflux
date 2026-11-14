// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cold original-A tail display and rollback pins use retained J6/cleanup evidence.
use super::{FullInstalledTailScope, FullTransferStage};
use crate::{AccountDb, StorageError};
use ramflux_crypto::custody::{VerifiedRecord, pairing::PairingRole};
use ramflux_protocol::custody::pairing::{PairingWire as _, full_transfer::SourceManifest};
use rusqlite::{OptionalExtension as _, params};
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl AccountDb {
    pub(super) fn source_tail_status_stage(
        &self,
        operation: &str,
        generation: u64,
        now: u64,
    ) -> Result<Option<(FullTransferStage<'_>, String)>, StorageError> {
        self.require_full_stage_unlock()?;
        let Some(live) =
            self.pairing_live_rows()?.into_iter().find(|row| row.operation_id == operation)
        else {
            return Ok(None);
        };
        if live.generation != generation {
            return Err(wrong());
        }
        if live.role != "initiator" || self.pairing_head()?.is_some() {
            return Ok(None);
        }
        let Some(reference) = live.full_stage_reference()? else {
            return Ok(None);
        };
        let saved: Option<(String,String)> = self.connection.query_row(
            "SELECT record_hash,tail_status FROM pairing_full_tail WHERE account_id=?1 AND operation_id=?2 AND stage_id=?3",
            params![self.local_account_id, operation, reference.stage_id], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        let Some((hash, status)) = saved else {
            return Ok(None);
        };
        self.full_source_retirement_owner(operation, &hash, now)?;
        let stage =
            self.open_full_stage_reference_inner(reference, PairingRole::Initiator, now, true)?;
        let adoption = self.pairing_adoption()?.ok_or_else(wrong)?;
        if adoption.local_ref
            != ramflux_protocol::canonical_json_bytes(&stage.resume_record()?.grant.source_ref)?
        {
            return Err(wrong());
        }
        Ok(Some((stage, status)))
    }
    /// Recover public original-A tail status without restoring an epoch or approval.
    /// # Errors
    /// Refuses a wrong generation, invalid J6/cleanup receipt, replaced scope or bad metadata.
    pub fn full_installed_source_tail_scope(
        &self,
        operation: &str,
        generation: u64,
        now: u64,
    ) -> Result<Option<FullInstalledTailScope>, StorageError> {
        if let Some(completion) = self.full_completion(operation, generation, "initiator", now)? {
            return Ok(Some(completion.scope()));
        }
        let Some((stage, status)) = self.source_tail_status_stage(operation, generation, now)?
        else {
            return Ok(None);
        };
        let merged = status == "merged";
        let bytes: Vec<u8> = stage.connection.query_row(
            "SELECT bytes FROM manifest WHERE direction=0 AND (?1 OR kind!='tail') AND length(bytes)<=1048576 ORDER BY cut DESC LIMIT 1",
            params![merged], |row| row.get(0),
        )?;
        let manifest = SourceManifest::from_wire_bytes(&bytes).map_err(|_| wrong())?;
        Ok(Some(FullInstalledTailScope {
            grant: stage.resume_record()?.grant,
            lease_expires_at: stage.reference().lease_expires_at.0,
            bytes_total: manifest.manifest.total_bytes.0,
            cut: manifest.manifest.snapshot_cut.0,
            merged,
            abandoned: status == "abandoned",
        }))
    }
    /// Save this original source's own independently verified tail native floor.
    /// # Errors
    /// Refuses wrong local scope, native rollback/fork or lost original unlock.
    pub fn observe_full_source_tail_native_head(
        &self,
        operation: &str,
        generation: u64,
        current: &VerifiedRecord,
        now: u64,
    ) -> Result<(), StorageError> {
        if self.full_completion(operation, generation, "initiator", now)?.is_some() {
            return Ok(());
        }
        let Some((mut stage, _)) = self.source_tail_status_stage(operation, generation, now)?
        else {
            return Err(wrong());
        };
        stage.observe_full_native_head(current)
    }
}
