// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attended B-local J3. No phrase enters a DTO, stage, publication or native RPC.
use super::super::super::{
    install_store::{self, Install},
    local_credential,
};
use super::{LocalPairingParticipant, custody, wrong};
use crate::SdkError;
use ramflux_crypto::custody::{
    CooperativeTransferInput, MasterKey, RecoveryPhrase, SelfSigningKey,
    cooperative_transfer_preserving_devices,
};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{
        BranchCertificate, Publication, object_hash,
        pairing::{
            PairingWire,
            context_v3::TranscriptV3,
            local_dto::{CredentialRequest, Prepare},
        },
    },
    encode_base64url,
};
use ramflux_storage::{AccountDb, FullDuplexReceipt, HeadRow, LiveRow};
mod frontend;
mod recovery;

/// Frozen candidate and B-local owners. No source preservation or publication approval.
pub struct FullPreparedTransferCandidate {
    previous: Box<ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>>,
    publication: Publication,
    install: Install,
    duplex: FullDuplexReceipt,
}
impl FullPreparedTransferCandidate {
    pub(crate) fn previous(
        &self,
    ) -> &ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet> {
        &self.previous
    }
    #[must_use]
    pub const fn publication(&self) -> &Publication {
        &self.publication
    }
    #[must_use]
    pub const fn install(&self) -> &Install {
        &self.install
    }
    #[must_use]
    pub const fn duplex(&self) -> &FullDuplexReceipt {
        &self.duplex
    }
}
struct Scope {
    bound_hash: String,
    bound_epoch: u64,
    context: TranscriptV3,
    live: LiveRow,
    install: Install,
    duplex: FullDuplexReceipt,
}
impl LocalPairingParticipant {
    fn candidate_scope_in(
        &self,
        db: &AccountDb,
        request: &Prepare,
        now: u64,
    ) -> Result<Scope, SdkError> {
        request.validate().map_err(|error| super::super::super::transport::wire(&error))?;
        self.full_selected_db(db, None)?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == request.operation_id)
            .ok_or_else(wrong)?;
        if live.generation != request.generation
            || live.role != "responder"
            || live.phase != "mutually_confirmed"
            || db.pairing_head()?.is_some()
        {
            return Err(wrong());
        }
        let stage = db.open_full_transfer_stage(
            &request.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            now,
        )?;
        let record = stage.resume_record()?;
        if encode_base64url(record.th) != request.transcript_hash {
            return Err(wrong());
        }
        let context = TranscriptV3::from_wire_bytes(&record.transcript)
            .map_err(|error| super::super::super::transport::wire(&error))?;
        if context.initiator.common.purpose != "primary_transfer" {
            return Err(wrong());
        }
        let duplex = stage.verified_duplex(now)?;
        super::require_candidate_lease(duplex.expires_at(), now)?;
        let install =
            install_store::read_pending(&self.root, &self.account_id, &request.operation_id)?
                .ok_or_else(wrong)?;
        if install.recipient_ref != record.grant.destination_ref
            || install.install_purpose != "transfer_destination"
            || install.record_hash.is_some()
            || install.primary_vault_ref.is_none()
            || install.state != "vault_durable"
            || install.full_transfer.is_some()
        {
            return Err(wrong());
        }
        Ok(Scope {
            bound_hash: stage.full_prepublication_record_hash()?,
            bound_epoch: stage.full_prepublication_record_epoch()?,
            context,
            live,
            install,
            duplex,
        })
    }
    /// Explicit attended prepare. Reads and native queries release the actual DB loan
    /// before invoking the private provider. This is never a recovery ceremony.
    /// # Errors
    /// Refuses A/wrong stage/TH/generation before any phrase request; late callbacks,
    /// wrong phrase, changed native base or lost local ownership cannot release a candidate.
    pub fn prepare_full_transfer_candidate(
        &self,
        request: &Prepare,
        frontend_generation: u64,
    ) -> Result<FullPreparedTransferCandidate, SdkError> {
        let work = {
            let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
            let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
            self.prepare_full_candidate_work(db, request.clone(), frontend_generation)?
        };
        let draft = work.prepare(self)?;
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        draft.finish(self, slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?)
    }
    fn full_candidate_publication(
        &self,
        scope: &Scope,
        current: &ramflux_crypto::custody::VerifiedRecord,
        master: &MasterKey,
        primary: &SelfSigningKey,
        now: u64,
    ) -> Result<Publication, SdkError> {
        let context = &scope.context;
        let common = &context.initiator.common;
        let branch = self.vault.load_branch(
            &scope.install.branch_vault_ref,
            &current.envelope().body.principal_id,
            &scope.install.recipient_ref,
        )?;
        if encode_base64url(branch.signing.signing_key.verifying_key().to_bytes())
            != context.responder.branch_key
            || encode_base64url(branch.agreement.public) != context.responder.agreement_key
        {
            return Err(wrong());
        }
        let fresh_destination = if common.recipient_mode == "new" {
            Some(BranchCertificate {
                schema: ramflux_protocol::domain::CUSTODY_BRANCH_CERTIFICATE.into(),
                version: 1,
                account_anchor: common.account_anchor.clone(),
                master_certificate_hash: object_hash(&current.envelope().body.master_certificate)?,
                device_id: scope.install.recipient_ref.device_id.clone(),
                device_epoch: scope.install.recipient_ref.device_epoch,
                principal_kind: current.envelope().body.principal_kind,
                branch_signing_public_key: context.responder.branch_key.clone(),
                agreement_identity_public_key: context.responder.agreement_key.clone(),
                capabilities: common.capabilities.clone(),
                not_before: common.lease_not_before,
                expires_at: common.lease_expires_at,
                cert_id: encode_base64url(ramflux_crypto::random_32()?),
            })
        } else {
            None
        };
        let record = cooperative_transfer_preserving_devices(
            master,
            primary,
            current,
            CooperativeTransferInput {
                destination: scope.install.recipient_ref.clone(),
                fresh_destination,
                highest_observed_range: ramflux_protocol::custody::decode_epoch(
                    current.envelope().body.device_set_epoch,
                )?
                .0,
                issued_at: now,
                master_cert_id: encode_base64url(ramflux_crypto::random_32()?),
            },
        )?;
        Ok(Publication { record, compacted_ids: None })
    }
    fn retain_full_candidate_in(
        &self,
        db: &AccountDb,
        request: &Prepare,
        scope: &Scope,
        publication: &Publication,
        now: u64,
    ) -> Result<(), SdkError> {
        self.full_selected_db(db, Some(&scope.install.account_anchor))?;
        let stage = db.open_full_transfer_stage(
            &request.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            now,
        )?;
        let proof = stage.verified_duplex(now)?;
        if stage.full_prepublication_record_hash()? != scope.bound_hash
            || stage.full_prepublication_record_epoch()? != scope.bound_epoch
            || proof.manifest_chain_hash() != scope.duplex.manifest_chain_hash()
            || proof.data_verified_hash() != scope.duplex.data_verified_hash()
            || encode_base64url(stage.resume_record()?.th) != request.transcript_hash
        {
            return Err(wrong());
        }
        db.commit_pairing_head(&HeadRow {
            account_id: self.account_id.clone(),
            operation_id: request.operation_id.clone(),
            invitation_id: Some(scope.live.invitation_id.clone()),
            generation: request.generation,
            kind: "transfer".into(),
            base_record_hash: scope.bound_hash.clone(),
            base_epoch: scope.bound_epoch,
            publisher_ref: canonical_json_bytes(&scope.context.initiator.device_ref)?,
            candidate: canonical_json_bytes(publication)?,
            candidate_hash: object_hash(&publication.record)?,
            state: "prepared".into(),
            ack: None,
            recipient_ref: Some(canonical_json_bytes(&scope.install.recipient_ref)?),
            revoked_ref: None,
            created_at: now,
        })?;
        Ok(())
    }
}
