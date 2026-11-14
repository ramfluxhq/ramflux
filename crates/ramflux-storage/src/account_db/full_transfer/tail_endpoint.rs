// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Separate data-only tail admission after local J6/G3, never a prepublication shortcut.
use super::{FullSourceDeltaDraft, FullTransferStage, full_transfer_catalog};
use crate::{AccountDb, StorageError};
use ramflux_crypto::custody::{
    VerifiedRecord,
    pairing::{PairingRole, verify_full_tail_authority},
};
use ramflux_protocol::custody::pairing::full_transfer::{ManifestKind, SourceManifest};
use zeroize::Zeroizing;

/// One short original-endpoint loan. No stage/key getter, publication or signing authority.
/// Drop it before any network wait and independently refresh native authority next time.
pub struct FullTailEndpoint<'a> {
    pub(super) operation: String,
    pub(super) stage: FullTransferStage<'a>,
    current: &'a VerifiedRecord,
    admitted_at: u64,
}
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
fn authority_error(error: &ramflux_crypto::CryptoError) -> StorageError {
    match error {
        ramflux_crypto::CryptoError::Pairing("LeaseExpired") => {
            StorageError::PairingField("LeaseExpired")
        }
        _ => StorageError::PairingField("HeadChanged"),
    }
}
impl AccountDb {
    /// Admit only an installed original source or recipient using its own verified native head.
    /// SDK must independently verify completed local authority/G3 before making this loan.
    /// # Errors
    /// Refuses missing J6/G3, another operation/generation, revocation, role/key changes or expiry.
    pub fn open_full_tail_endpoint<'a>(
        &'a self,
        operation: &str,
        generation: u64,
        current: &'a VerifiedRecord,
        now: u64,
    ) -> Result<FullTailEndpoint<'a>, StorageError> {
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if live.generation != generation || self.pairing_head()?.is_some() {
            return Err(wrong());
        }
        let stage = match live.role.as_str() {
            "responder" => self.installed_tail_stage(operation, generation, now)?,
            "initiator" => {
                let reference = live.full_stage_reference()?.ok_or_else(wrong)?;
                let stage = self.open_full_stage_reference_inner(
                    reference,
                    PairingRole::Initiator,
                    now,
                    false,
                )?;
                let identity = stage.tail_capture_identity()?;
                let adoption = self.pairing_adoption()?.ok_or_else(wrong)?;
                let record = stage.resume_record()?;
                if adoption.local_role != "secondary"
                    || adoption.primary_vault_ref.is_some()
                    || adoption.local_ref
                        != ramflux_protocol::canonical_json_bytes(&record.grant.source_ref)?
                {
                    return Err(wrong());
                }
                self.full_source_retirement_owner(operation, &identity.hash, now)?;
                stage.finish_source_tail_capture()?;
                stage
            }
            _ => return Err(wrong()),
        };
        if stage.connection.query_row("SELECT EXISTS(SELECT 1 FROM data_terminal)", [], |row| {
            row.get::<_, bool>(0)
        })? {
            return Err(StorageError::PairingField("Cancelled"));
        }
        let mut endpoint =
            FullTailEndpoint { operation: operation.into(), stage, current, admitted_at: now };
        endpoint.stage.observe_full_native_head(current)?;
        endpoint.require_live(now)?;
        Ok(endpoint)
    }
}
impl FullTailEndpoint<'_> {
    pub(super) fn require_live(&self, now: u64) -> Result<(), StorageError> {
        self.stage.require_io()?;
        self.stage.require_full_native_floor(self.current)?;
        let record = self.stage.resume_record()?;
        let adoption = self.stage.db.pairing_adoption()?.ok_or_else(wrong)?;
        let (role, reference) = match record.role {
            PairingRole::Initiator => ("secondary", &record.grant.source_ref),
            PairingRole::Responder => ("primary", &record.grant.destination_ref),
        };
        if adoption.local_role != role
            || adoption.local_ref != ramflux_protocol::canonical_json_bytes(reference)?
        {
            return Err(StorageError::PairingField("HeadChanged"));
        }
        if now < self.admitted_at {
            return Err(wrong());
        }
        if now >= self.stage.reference().lease_expires_at.0 {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        verify_full_tail_authority(&self.stage.resume_record()?.grant, self.current, now)
            .map_err(|error| authority_error(&error))
    }
    pub(super) fn require_tail(&self, hash: &str, now: u64) -> Result<(), StorageError> {
        self.require_live(now)?;
        if self.stage.forward_manifest(hash)?.manifest.kind != ManifestKind::Tail {
            return Err(wrong());
        }
        Ok(())
    }
    /// Snapshot only a pending tail's locally authenticated data-resume operands.
    /// A new network epoch must never be constructed from a merged or abandoned tail.
    /// # Errors
    /// Refuses terminal/foreign state, changed generation, expired authority or lost unlock.
    pub fn pending_resume_record(
        &self,
        now: u64,
    ) -> Result<ramflux_crypto::custody::pairing::FullResumeRecord, StorageError> {
        self.require_live(now)?;
        let record = self.stage.resume_record()?;
        let pending: bool = match record.role {
            PairingRole::Initiator => self.stage.db.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_full_tail WHERE account_id=?1 AND operation_id=?2 AND stage_id=?3 AND tail_status='pending' AND cut_state='durable')",
                rusqlite::params![self.stage.db.local_account_id, self.operation, self.stage.reference().stage_id], |row| row.get(0),
            )?,
            PairingRole::Responder => self.stage.db.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_full_tail_apply t JOIN pairing_adoption a ON a.full_generation_nonce=t.generation_nonce WHERE t.operation_id=?1 AND t.stage_digest=?2 AND t.tail_status='pending')",
                rusqlite::params![self.operation, record.stage_digest()?.as_slice()], |row| row.get(0),
            )?,
        };
        if !pending {
            return Err(wrong());
        }
        Ok(record)
    }
    /// Read the original completed duplex only from this currently pending installed tail.
    /// No peer-supplied flag, ordinary receipt or terminal stage can restore this position.
    /// # Errors
    /// Refuses terminal/foreign state, stale native scope, expiry or incomplete signed DV.
    pub fn pending_duplex_receipt(
        &self,
        now: u64,
    ) -> Result<super::FullDuplexReceipt, StorageError> {
        self.pending_resume_record(now)?;
        self.stage.verified_duplex(now)
    }
    /// A cancellation fence for this one tail job; contains no data or key.
    #[must_use]
    pub fn io_cancel_handle(&self) -> crate::FullStageIoCancel {
        self.stage.io_cancel_handle()
    }
    /// Pin only the immutable J6 cut for an off-loan local encoder.
    /// # Errors
    /// Refuses stale authority, another role, incomplete J6 or lost local unlock.
    pub fn into_source_encoding_work(
        self,
        now: u64,
    ) -> Result<super::FullSourceTailEncodingWork, StorageError> {
        self.require_live(now)?;
        self.stage.into_source_tail_encoding_work(self.current, now)
    }
    /// Revalidate retained slots before advertising a restart's durable tail prefix.
    /// # Errors
    /// Refuses foreign tails, corrupt storage, stale native authority or expiry.
    pub fn durable_recipient_prefix(
        &self,
        hash: &str,
        now: u64,
    ) -> Result<Option<u64>, StorageError> {
        self.require_tail(hash, now)?;
        if self.stage.resume_record()?.role != PairingRole::Responder {
            return Err(wrong());
        }
        self.stage.revalidate_forward_prefix(hash)
    }
    /// Bind this endpoint's local work to the root owner's cancellation fence.
    /// # Errors
    /// Refuses an already cancelled stage or root; no key or stage capability is exposed.
    pub fn bind_local_io_cancellation(
        &mut self,
        cancelled: &crate::FullStageIoCancel,
    ) -> Result<(), StorageError> {
        self.stage.bind_local_io_cancellation(cancelled)
    }
    /// Return signing bytes only for this original source's exact immutable J6 draft.
    /// # Errors
    /// Refuses a foreign draft, wrong native roles/keys, a recut or expired admission.
    pub fn source_manifest_signing_bytes(
        &self,
        draft: &FullSourceDeltaDraft,
        now: u64,
    ) -> Result<Vec<u8>, StorageError> {
        self.require_live(now)?;
        let identity = self.stage.tail_capture_identity()?;
        let record = self.stage.resume_record()?;
        if record.role != PairingRole::Initiator
            || draft.manifest().kind != ManifestKind::Tail
            || draft.stage_digest() != record.stage_digest()?
            || draft.expected_branch_key() != record.grant.branch_keys.source
            || draft.manifest().snapshot_id != identity.snapshot
            || draft.manifest().snapshot_cut.0 != identity.ordinal
        {
            return Err(wrong());
        }
        draft.manifest().signing_bytes().map_err(|_| wrong())
    }
    /// Retain only the original source's exact locally encoded immutable J6 tail.
    /// # Errors
    /// Refuses foreign drafts, a later recut, changed signatures/bytes, quota or stale admission.
    pub fn retain_source(
        &mut self,
        draft: &FullSourceDeltaDraft,
        manifest: &SourceManifest,
        now: u64,
    ) -> Result<(), StorageError> {
        self.require_live(now)?;
        let identity = self.stage.tail_capture_identity()?;
        let record = self.stage.resume_record()?;
        if record.role != PairingRole::Initiator
            || draft.manifest().kind != ManifestKind::Tail
            || draft.manifest() != &manifest.manifest
            || draft.stage_digest() != record.stage_digest()?
            || draft.expected_branch_key() != record.grant.branch_keys.source
            || manifest.manifest.snapshot_id != identity.snapshot
            || manifest.manifest.snapshot_cut.0 != identity.ordinal
        {
            return Err(wrong());
        }
        draft.signed_manifest(manifest.source_signature.clone())?;
        self.stage.retain_own_manifest(manifest, full_transfer_catalog(), true)
    }
    /// Retain a source-signed tail only after this B's completed G3 and own native admission.
    /// This records input metadata only; it grants no semantic receipt or live data mutation.
    /// # Errors
    /// Refuses another role/chain/catalog/key, repeated conflicting tail, quota or stale admission.
    pub fn retain_recipient(
        &mut self,
        manifest: &SourceManifest,
        now: u64,
    ) -> Result<(), StorageError> {
        self.require_live(now)?;
        if self.stage.resume_record()?.role != PairingRole::Responder {
            return Err(wrong());
        }
        let catalog = full_transfer_catalog()
            .iter()
            .map(super::FamilyRule::manifest_family)
            .collect::<Result<Vec<_>, _>>()?;
        self.stage.retain_tail_manifest_for_role(manifest, &catalog, PairingRole::Responder)
    }
    /// Read one bounded original-source encrypted-spool chunk after fresh local admission.
    /// # Errors
    /// Refuses foreign kind/hash/index, unavailable source bytes or expired native scope.
    pub fn read_source_chunk(
        &self,
        hash: &str,
        index: u64,
        now: u64,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        self.require_tail(hash, now)?;
        self.stage.read_source_wire_chunk_for_kind(hash, index, true)
    }
    /// Durably receive one bounded tail slot. A durable slot is not semantic verification.
    /// # Errors
    /// Refuses another role/kind/hash/index, corruption, conflicts, low space or stale admission.
    pub fn retain_recipient_chunk(
        &self,
        hash: &str,
        index: u64,
        bytes: &[u8],
        now: u64,
    ) -> Result<bool, StorageError> {
        self.require_tail(hash, now)?;
        if self.stage.resume_record()?.role != PairingRole::Responder {
            return Err(wrong());
        }
        self.stage.retain_forward_chunk(hash, index, bytes)
    }
}
