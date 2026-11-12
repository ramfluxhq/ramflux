// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Short local source-cut and original-branch signing owners. Never a publication signer.
use super::super::{
    FullResumeProofSigningRequest, FullSourceManifestSigningRequest, LocalPairingParticipant,
};
use crate::{SdkError, custody};
use ed25519_dalek::Signer as _;
use ramflux_protocol::{custody::DeviceRef, encode_base64url};
use ramflux_storage::{AccountDb, AccountIndex, FullSourcePreparationCancel, PreparedFullSource};

mod stage;

fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
impl LocalPairingParticipant {
    fn full_selected_db(&self, db: &AccountDb, anchor: Option<&str>) -> Result<(), SdkError> {
        if db.local_account_id != self.account_id {
            return Err(wrong());
        }
        let index = AccountIndex::open(&self.root)?;
        let selected = index.account(&self.account_id)?;
        if selected.account_state == "removed"
            || anchor.is_some_and(|anchor| anchor != selected.principal_commitment)
            || std::fs::canonicalize(&db.path)?
                != std::fs::canonicalize(self.root.join(selected.db_relative_path))?
        {
            return Err(wrong());
        }
        Ok(())
    }
    /// Fetch/verify the exact public native base before freezing the v3 SAS context.
    /// No account/vault mutex is held over the existing native query port.
    /// # Errors
    /// Refuses a changed head/master/root or unavailable existing native freshness.
    pub(crate) fn full_sas_base(
        &self,
        common: &ramflux_protocol::custody::pairing::context_v3::CommonV3,
        source: &DeviceRef,
    ) -> Result<ramflux_crypto::custody::VerifiedRecord, SdkError> {
        let authority = self.query.current_authority(&common.account_anchor)?;
        let verified =
            ramflux_crypto::custody::verify_publication(&authority, custody::network_now()?)?;
        let body = &verified.envelope().body;
        if body.account_anchor != common.account_anchor
            || body.master_certificate.body.master_public_key != common.master_public_key
            || body.master_certificate.body.primary_device_ref != *source
            || body.device_set_epoch != common.device_set_epoch
            || ramflux_protocol::custody::object_hash(verified.envelope())? != common.record_hash
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        Ok(verified)
    }
    /// Complete typed preflight/cut/root before the coordinator invokes native Issue.
    /// Returns no DB/vault lock, key, SAS approval or publication permission.
    /// # Errors
    /// Refuses locked/stale scope, unknown nonempty owners or failed encrypted preparation.
    pub fn prepare_full_source(
        &self,
    ) -> Result<(PreparedFullSource, FullSourcePreparationCancel), SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        self.full_selected_db(db, None)?;
        let mut source = db.prepare_full_transfer_source()?;
        let cancel = source.cancel_handle();
        let snapshot = encode_base64url(ramflux_crypto::random_32()?);
        source.capture_base_cut(&snapshot)?;
        source.encode_fixed_base_source(&snapshot, std::io::sink())?;
        Ok((source.close_ready()?, cancel))
    }
    pub(super) fn with_full_branch<R>(
        &self,
        reference: &DeviceRef,
        expected_key: &str,
        use_branch: impl FnOnce(&custody::BranchCredentials) -> Result<R, SdkError>,
    ) -> Result<R, SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        self.full_selected_db(db, Some(&reference.account_anchor))?;
        let pending = super::super::install_store::list_pending(&self.root, &self.account_id)?
            .into_iter()
            .find(|row| &row.recipient_ref == reference);
        let vault_ref = if let Some(pending) = pending {
            pending.branch_vault_ref
        } else {
            let account =
                custody::load_data_account(&self.root, &self.account_id, custody::network_now()?)?;
            if account.local_device_id()? != reference.device_id
                || account.record().body.account_anchor != reference.account_anchor
            {
                return Err(wrong());
            }
            account.branch_vault_ref().to_owned()
        };
        let branch = self.vault.load_branch(&vault_ref, &reference.account_anchor, reference)?;
        if encode_base64url(branch.signing.signing_key.verifying_key().to_bytes()) != expected_key {
            return Err(wrong());
        }
        use_branch(&branch)
    }
    /// Sign only the bootstrap's exact mutually-confirmed, actual prepared source manifest.
    /// # Errors
    /// Refuses locked/foreign local ownership, changed source/context or wrong branch key.
    pub fn sign_full_source_manifest(
        &self,
        request: &FullSourceManifestSigningRequest<'_>,
    ) -> Result<String, SdkError> {
        let context = request.context();
        let source = &context.initiator;
        let manifest = request.manifest();
        if request.local_account_id() != self.account_id
            || manifest.source_ref != source.device_ref
            || manifest.destination_ref != context.responder.device_ref
            || manifest.account_anchor != source.common.account_anchor
            || manifest.base_record_hash != source.common.record_hash
            || Some(&manifest.transfer_id) != source.common.transfer_id.as_ref()
        {
            return Err(wrong());
        }
        let bytes =
            manifest.signing_bytes().map_err(|error| super::super::transport::wire(&error))?;
        self.with_full_branch(&source.device_ref, &source.branch_key, |branch| {
            Ok(encode_base64url(branch.signing.signing_key.sign(&bytes).to_bytes()))
        })
    }
    /// Sign only an A3 template matched to this endpoint's own frozen epoch and keys.
    /// The typed request cannot be constructed from a generic bus/relay proof body.
    /// # Errors
    /// Refuses stale local unlock/account selection, foreign original branch or bad proof.
    pub fn sign_full_resume(
        &self,
        request: &FullResumeProofSigningRequest<'_>,
    ) -> Result<String, SdkError> {
        let bytes = request
            .proof()
            .signing_bytes()
            .map_err(|error| super::super::transport::wire(&error))?;
        self.with_full_branch(request.own_ref(), request.own_branch_key(), |branch| {
            Ok(encode_base64url(branch.signing.signing_key.sign(&bytes).to_bytes()))
        })
    }
}

#[cfg(test)]
mod tests;
