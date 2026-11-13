// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Installed recipient status exposes public tail scope without recreating a data session.
use super::FullTransferStage;
use crate::{AccountDb, StorageError};
use ramflux_crypto::custody::{VerifiedRecord, pairing::PairingRole};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::pairing::{
        PairingWire,
        full_transfer::{SourceManifest, lease::DataGrant},
    },
};

/// Public original discovery scope and progress from a retained installed recipient.
/// No epoch, stage key, signer or publication permission is returned.
pub struct FullInstalledTailScope {
    pub grant: DataGrant,
    pub lease_expires_at: u64,
    pub bytes_total: u64,
    pub cut: u64,
}
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl AccountDb {
    pub(super) fn installed_tail_stage(
        &self,
        operation: &str,
        generation: u64,
        now: u64,
    ) -> Result<FullTransferStage<'_>, StorageError> {
        self.require_full_stage_unlock()?;
        let adoption = self.pairing_adoption()?.ok_or_else(wrong)?;
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if self.pairing_head()?.is_some()
            || adoption.account_id != self.local_account_id
            || !matches!(adoption.local_role.as_str(), "primary" | "secondary")
            || adoption.full_generation_nonce.is_none()
            || adoption.full_initial_union_root.is_none()
            || live.role != "responder"
            || live.generation != generation
        {
            return Err(wrong());
        }
        let reference = live.full_stage_reference()?.ok_or_else(wrong)?;
        let stage =
            self.open_full_stage_reference_inner(reference, PairingRole::Responder, now, true)?;
        let record = stage.resume_record()?;
        let (nonce, root): ([u8; 32], [u8; 32]) = stage.connection.query_row(
            "SELECT generation_nonce,union_root FROM receiver_generation WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if adoption.full_generation_nonce.as_deref()
            != Some(ramflux_protocol::encode_base64url(nonce).as_str())
            || adoption.full_initial_union_root.as_deref()
                != Some(ramflux_protocol::encode_base64url(root).as_str())
        {
            return Err(wrong());
        }

        if adoption.local_ref != canonical_json_bytes(&record.grant.destination_ref)? {
            return Err(wrong());
        }
        stage.verified_duplex(now.min(stage.reference().lease_expires_at.0.saturating_sub(1)))?;
        Ok(stage)
    }
    /// Inspect retained installed progress after SDK verifies the exact completed G3 owners.
    /// Historical receipt time is never used for data relay or publication admission.
    /// # Errors
    /// Refuses foreign operations/generations, absent adoption, pending Head or corrupt links.
    pub fn full_installed_recipient_tail_scope(
        &self,
        operation: &str,
        generation: u64,
        now: u64,
    ) -> Result<FullInstalledTailScope, StorageError> {
        let stage = self.installed_tail_stage(operation, generation, now)?;
        // A durably received tail remains pending until its separate semantic application.
        // Display the installed prepublication cut rather than imply that input is merged.
        let bytes: Vec<u8> = stage.connection.query_row(
            "SELECT bytes FROM manifest WHERE direction=0 AND kind!='tail' ORDER BY cut DESC LIMIT 1",
            [], |row| row.get(0),
        )?;
        let manifest = SourceManifest::from_wire_bytes(&bytes).map_err(|_| wrong())?;
        Ok(FullInstalledTailScope {
            grant: stage.resume_record()?.grant,
            lease_expires_at: stage.reference().lease_expires_at.0,
            bytes_total: manifest.manifest.total_bytes.0,
            cut: manifest.manifest.snapshot_cut.0,
        })
    }
    /// Persist this installed endpoint's own verified native tail floor before checking roles.
    /// SDK must independently query authority and verify G3 before this short local loan.
    /// # Errors
    /// Refuses another installed stage, changed digest, native rollback/fork or lost unlock.
    pub fn observe_full_installed_tail_native_head(
        &self,
        operation: &str,
        generation: u64,
        current: &VerifiedRecord,
        now: u64,
    ) -> Result<(), StorageError> {
        self.installed_tail_stage(operation, generation, now)?.observe_full_native_head(current)
    }
}
