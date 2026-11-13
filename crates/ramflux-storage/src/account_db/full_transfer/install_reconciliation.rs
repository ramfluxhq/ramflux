// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A terminal data ceremony may finish its exact published installation without a data epoch.
use super::{
    FullDuplexReceipt, FullPinnedReceiverBase, FullPreparedReceiverDatabase, FullReceiverBaseCopy,
    FullReceiverDatabaseWork, FullSelectedReceiverGeneration, FullTransferStage,
};
use crate::{AccountDb, AdoptionRow, BackupIndexInstall, FullStageReference, StorageError};
use ramflux_crypto::custody::{VerifiedRecord, pairing::PairingRole};
use ramflux_protocol::custody::pairing::PairingWire as _;
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{DeviceRef, Publication, object_hash},
    parse_i_json,
};
use std::path::PathBuf;
fn wrong() -> StorageError {
    StorageError::PairingField("InstallPending")
}

/// Installation-only view of retained B data. Deliberately has no `Deref`, stage/lease/key
/// getter, packet/manifest retention, signing request, cancellation reset or relay operation.
pub struct FullRecipientInstallStage<'a> {
    pub(super) stage: FullTransferStage<'a>,
    pub(super) historical_time: u64,
}
/// Public discovery/identity operands from an exact encrypted pending recipient journal.
/// This carries no resume key owner, epoch, approval or native authority.
pub struct FullRecipientRecoveryIdentity {
    pub grant: ramflux_protocol::custody::pairing::full_transfer::lease::DataGrant,
    pub master_public_key: String,
    pub base_record_hash: String,
    pub base_epoch: u64,
}
impl AccountDb {
    /// Read only the original discovery scope for a pending full recipient installation.
    /// The caller must independently discover the pinned node and query exact native J6.
    /// # Errors
    /// Refuses foreign operations/generations, source roles, missing candidates or corrupt links.
    pub fn full_recipient_recovery_identity(
        &self,
        operation: &str,
        generation: u64,
        now: u64,
    ) -> Result<FullRecipientRecoveryIdentity, StorageError> {
        let head = self.pairing_head()?.ok_or_else(wrong)?;
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if head.operation_id != operation
            || head.generation != generation
            || live.generation != generation
            || live.role != "responder"
            || head.kind != "transfer"
            || !matches!(head.state.as_str(), "prepared" | "acknowledged")
        {
            return Err(wrong());
        }
        let reference = live.full_stage_reference()?.ok_or_else(wrong)?;
        let stage =
            self.open_full_stage_reference_inner(reference, PairingRole::Responder, now, true)?;
        let record = stage.resume_record()?;
        let context =
            ramflux_protocol::custody::pairing::context_v3::TranscriptV3::from_wire_bytes(
                &record.transcript,
            )
            .map_err(|_| wrong())?;
        let publication: Publication = parse_i_json(&head.candidate)?;
        if head.candidate_hash != object_hash(&publication.record).map_err(|_| wrong())?
            || publication.record.body.account_anchor != record.grant.destination_ref.account_anchor
            || publication.record.body.master_certificate.body.primary_device_ref
                != record.grant.destination_ref
            || head.recipient_ref.as_deref()
                != Some(canonical_json_bytes(&record.grant.destination_ref)?.as_slice())
            || head.publisher_ref != canonical_json_bytes(&record.grant.source_ref)?
        {
            return Err(wrong());
        }
        Ok(FullRecipientRecoveryIdentity {
            grant: record.grant,
            master_public_key: context.initiator.common.master_public_key,
            base_epoch: context.initiator.common.device_set_epoch,
            base_record_hash: record.base_record_hash,
        })
    }
    /// Persist this pending endpoint's own verified native floor even when its candidate
    /// is absent. This cannot reopen terminal data state or acknowledge another candidate.
    /// # Errors
    /// Refuses another account, wrong local role/link or native rollback/fork.
    pub fn observe_full_install_native_head(
        &self,
        operation: &str,
        current: &VerifiedRecord,
        now: u64,
    ) -> Result<(), StorageError> {
        let head = self.pairing_head()?.ok_or_else(wrong)?;
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if head.operation_id != operation
            || head.kind != "transfer"
            || !matches!(live.role.as_str(), "initiator" | "responder")
            || (live.role == "initiator"
                && !matches!(head.state.as_str(), "submitted" | "acknowledged"))
            || live.generation != head.generation
        {
            return Err(wrong());
        }
        let reference = live.full_stage_reference()?.ok_or_else(wrong)?;
        let role =
            if live.role == "initiator" { PairingRole::Initiator } else { PairingRole::Responder };
        let mut stage = self.open_full_stage_reference_inner(reference, role, now, true)?;
        stage.observe_full_native_head(current)
    }
    /// Reopen the exact B stage after an independently verified exact native acknowledgement.
    /// The SDK must obtain `current` through its own authenticated query before this loan.
    /// Terminal data state remains terminal; this owner exposes only G1/G2 data installation.
    /// # Errors
    /// Refuses absent/foreign J6, another native candidate/role, changed stage or missing receipts.
    pub fn open_full_recipient_install_stage(
        &self,
        operation: &str,
        current: &VerifiedRecord,
        now: u64,
    ) -> Result<FullRecipientInstallStage<'_>, StorageError> {
        self.require_full_stage_unlock()?;
        let head = self.pairing_head()?.ok_or_else(wrong)?;
        if head.operation_id != operation
            || head.state != "acknowledged"
            || head.kind != "transfer"
            || head.candidate_hash != object_hash(current.envelope()).map_err(|_| wrong())?
        {
            return Err(wrong());
        }
        let candidate: Publication = parse_i_json(&head.candidate)?;
        if canonical_json_bytes(&candidate.record)? != canonical_json_bytes(current.envelope())? {
            return Err(wrong());
        }
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if live.role != "responder" || live.generation != head.generation {
            return Err(wrong());
        }
        let reference = live.full_stage_reference()?.ok_or_else(wrong)?;
        let historical_time = now.min(reference.lease_expires_at.0.saturating_sub(1));
        let mut stage =
            self.open_full_stage_reference_inner(reference, PairingRole::Responder, now, true)?;
        let record = stage.resume_record()?;
        if current.envelope().body.master_certificate.body.primary_device_ref
            != record.grant.destination_ref
            || head.base_record_hash != stage.full_prepublication_record_hash()?
            || head.recipient_ref.as_deref()
                != Some(canonical_json_bytes(&record.grant.destination_ref)?.as_slice())
            || head.publisher_ref != canonical_json_bytes(&record.grant.source_ref)?
        {
            return Err(wrong());
        }
        // A historical data receipt remains an integrity operand after its relay lease
        // expires. No API on this owner can use that historical time for wire admission.
        stage.verified_duplex(historical_time)?;
        stage.observe_full_native_head(current)?;
        Ok(FullRecipientInstallStage { stage, historical_time })
    }
}
impl FullRecipientInstallStage<'_> {
    /// One-way cancellation handle for installation I/O, carrying no data-session rights.
    #[must_use]
    pub fn io_cancel_handle(&self) -> super::FullStageIoCancel {
        self.stage.io_cancel_handle()
    }
    /// Bind fresh installation loans to their root owner's existing cancellation fence.
    /// # Errors
    /// Refuses cancelled I/O or loss of the original local unlock.
    pub fn bind_local_io_cancellation(
        &mut self,
        cancellation: &super::FullStageIoCancel,
    ) -> Result<(), StorageError> {
        self.stage.bind_local_io_cancellation(cancellation)
    }
    /// Pin authenticated retained input for off-loan G1 reconstruction after publication.
    /// No data epoch, packet admission or signing capability is returned.
    /// # Errors
    /// Refuses changed B, selected G2 or incomplete/corrupt retained input.
    pub fn into_receiver_replay_work(
        self,
        copy: FullReceiverBaseCopy,
    ) -> Result<super::FullReceiverReplayWork, StorageError> {
        self.stage.into_receiver_replay_work(copy, self.historical_time)
    }
    /// Check B's retained source approval without reopening the terminal data opportunity.
    /// The SDK must separately supply its own exact independently verified native J6.
    /// # Errors
    /// Refuses absent/corrupt source approval or another candidate/duplex.
    pub fn require_preservation_after_native_ack(
        &self,
        candidate: &ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    ) -> Result<(), StorageError> {
        self.stage
            .require_destination_preservation_after_native_ack(candidate, self.historical_time)
    }

    /// Public destination scope only; never a resume record or signing context.
    /// # Errors
    /// Refuses lost unlock or changed encrypted stage metadata.
    pub fn destination_ref(&self) -> Result<DeviceRef, StorageError> {
        Ok(self.stage.resume_record()?.grant.destination_ref)
    }
    #[must_use]
    pub fn reference(&self) -> &FullStageReference {
        self.stage.reference()
    }
    /// Verify the original exact signed input receipts, without extending their lease.
    /// # Errors
    /// Refuses changed/corrupt durable receipts or an unavailable local owner.
    pub fn verified_duplex(&self) -> Result<FullDuplexReceipt, StorageError> {
        self.stage.verified_duplex(self.historical_time)
    }
    /// Pin current B for replay; imported A can never become independent B provenance.
    /// # Errors
    /// Refuses selected G2, changed local generation or missing immutable base.
    pub fn pin_receiver_base(&self) -> Result<FullPinnedReceiverBase, StorageError> {
        self.stage.pin_receiver_base(&self.stage.resume_record()?.base_manifest_hash)
    }
    /// Replay only the retained authenticated prepublication chain into a fresh current B copy.
    /// # Errors
    /// Refuses changed B or any missing/corrupt input, contribution or receipt.
    pub fn project(&self, copy: &mut FullReceiverBaseCopy) -> Result<(), StorageError> {
        copy.project_retained_chain(&self.stage, self.historical_time)
    }
    /// Prepare G1 using the same immutable receipt and current B selection as a live install.
    /// # Errors
    /// Refuses stale B, unsupported payload ownership or a mismatched adoption receipt.
    pub fn prepare_generation(
        &self,
        copy: FullReceiverBaseCopy,
        path: PathBuf,
        adoption: AdoptionRow,
    ) -> Result<FullReceiverDatabaseWork, StorageError> {
        copy.into_generation_database_work(&self.stage, path, adoption, self.historical_time)
    }
    /// Perform the same atomic current-B G2 checks; no data session or approval is restored.
    /// # Errors
    /// Refuses a changed writer/selection, missing G1 bytes or mismatched install operands.
    pub fn select_generation(
        &self,
        prepared: FullPreparedReceiverDatabase,
        write: &BackupIndexInstall<'_>,
    ) -> Result<FullSelectedReceiverGeneration, StorageError> {
        prepared.select(&self.stage, write, self.historical_time)
    }
}
