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
    stage: FullTransferStage<'a>,
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
        let mut endpoint = FullTailEndpoint { stage, current, admitted_at: now };
        endpoint.stage.observe_full_native_head(current)?;
        endpoint.require_live(now)?;
        Ok(endpoint)
    }
}
impl FullTailEndpoint<'_> {
    fn require_live(&self, now: u64) -> Result<(), StorageError> {
        self.stage.require_io()?;
        if now < self.admitted_at {
            return Err(wrong());
        }
        if now >= self.stage.reference().lease_expires_at.0 {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        verify_full_tail_authority(&self.stage.resume_record()?.grant, self.current, now)
            .map_err(|error| authority_error(&error))
    }
    fn require_tail(&self, hash: &str, now: u64) -> Result<(), StorageError> {
        self.require_live(now)?;
        if self.stage.forward_manifest(hash)?.manifest.kind != ManifestKind::Tail {
            return Err(wrong());
        }
        Ok(())
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
