// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local storage/vault participant used by the shared ceremony coordinator.

use super::recipient::{
    RecipientKeyStaging, StageExisting, StageNew, stage_existing_for_generation,
    stage_new_for_generation,
};
use super::{
    HeadKind, HeadWrite, Installation, NodeHeadPersist, PairingAuthorityQuery, PublishedHead,
};
use crate::{RamfluxClient, SdkError, custody};
use ed25519_dalek::Signer;
use ramflux_protocol::custody::pairing::channel::EnrollmentBody;
use ramflux_protocol::custody::pairing::native::Invitation;
use ramflux_protocol::custody::pairing::{PairingWire, Transcript};
use ramflux_protocol::custody::{
    BranchCertificate, DeviceRef, Envelope, object_hash, signing_bytes,
};
use ramflux_storage::{AccountDb, FloorRow, HeadRow, LiveRow};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// Public, frozen ceremony context. Never contains SAS keys, tokens or credentials.
#[derive(Clone)]
pub struct ParticipantContext {
    pub invitation: Envelope<Invitation>,
    pub transcript: Transcript,
    pub transcript_hash: String,
    pub generation: u64,
}

/// One device's real account, vault and authenticated publication/query ports.
/// Ordinary frontends loan their account client for a coordinator operation; direct SDK
/// consumers may retain it here. No second account store or copied account key is opened.
pub struct LocalPairingParticipant {
    pub root: PathBuf,
    pub account_id: String,
    pub vault: Arc<dyn custody::PrimaryVault>,
    pub provider: Arc<dyn super::LocalCredentialProvider>,
    pub db: Mutex<Option<AccountDb>>,
    pub persist: Arc<dyn NodeHeadPersist>,
    pub query: Arc<dyn PairingAuthorityQuery>,
}

impl RecipientKeyStaging for LocalPairingParticipant {
    fn stage(
        &self,
        invitation: &Envelope<Invitation>,
        frontend_generation: u64,
    ) -> Result<DeviceRef, SdkError> {
        self.stage_with_generation(invitation, frontend_generation, 1)
    }
    fn stage_with_generation(
        &self,
        invitation: &Envelope<Invitation>,
        generation: u64,
        ceremony_generation: u64,
    ) -> Result<DeviceRef, SdkError> {
        let mut slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        if invitation.body.recipient_mode == "existing" {
            let mut client = RamfluxClient::new();
            client.active_account_db = slot.take();
            let result = (|| {
                let native =
                    custody::load_account(&self.root, &self.account_id, custody::network_now()?)?;
                let reference = invitation
                    .body
                    .destination_ref
                    .clone()
                    .ok_or(SdkError::PairingField("destination_ref"))?;
                let data_ref = ramflux_storage::FileVaultSecretSource::owner_ref(&self.account_id);
                let staged = stage_existing_for_generation(
                    &StageExisting {
                        new: StageNew {
                            root: &self.root,
                            account_id: &self.account_id,
                            invitation,
                            vault: self.vault.as_ref(),
                            provider: self.provider.as_ref(),
                            frontend_generation: generation,
                        },
                        recipient_ref: reference,
                        branch_vault_ref: native.branch_vault_ref(),
                        data_vault_ref: &data_ref,
                    },
                    &mut client,
                    ceremony_generation,
                )?;
                Ok(staged.recipient_ref)
            })();
            *slot = client.active_account_db.take();
            return result;
        }
        if slot.is_some() {
            return Err(SdkError::PairingCode("Busy"));
        }
        let mut client = RamfluxClient::new();
        let staged = stage_new_for_generation(
            &StageNew {
                root: &self.root,
                account_id: &self.account_id,
                invitation,
                vault: self.vault.as_ref(),
                provider: self.provider.as_ref(),
                frontend_generation: generation,
            },
            &mut client,
            ceremony_generation,
        )?;
        *slot = client.active_account_db.take();
        Ok(staged.recipient_ref)
    }
}

impl LocalPairingParticipant {
    pub(crate) fn next_generation(&self) -> Result<u64, SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        Ok(match slot.as_ref() {
            Some(db) => db.pairing_floor()?.map_or(1, |row| row.next_generation),
            None => 1,
        })
    }

    pub(crate) fn finish_install(
        &self,
        operation_id: &str,
        record_hash: &str,
    ) -> Result<(), SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        let live = db.pairing_live_rows()?.into_iter().find(|row| row.operation_id == operation_id);
        let Some(live) = live else {
            if db.pairing_terminal_rows()?.iter().any(|row| {
                row.operation_id == operation_id && row.record_hash.as_deref() == Some(record_hash)
            }) {
                return Ok(());
            }
            return Err(SdkError::PairingCode("PublicationPending"));
        };
        let adopted = db.pairing_adoption()?.ok_or(SdkError::PairingCode("PublicationPending"))?;
        if adopted.operation_id != operation_id || adopted.record_hash != record_hash {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        db.commit_pairing_adoption_cleanup(
            &adopted,
            &ramflux_storage::TerminalRow {
                account_id: self.account_id.clone(),
                operation_id: operation_id.into(),
                invitation_id: live.invitation_id,
                issuer_seq: live.issuer_seq,
                local_seq: live.local_seq,
                generation: live.generation,
                outcome: "completed".into(),
                record_hash: Some(record_hash.into()),
                finished_at: custody::network_now()?,
                cleanup: "done".into(),
            },
        )?;
        Ok(())
    }

    /// Loan the unlocked account DB for a bounded coordinator operation.
    /// # Errors
    /// Refuses a second owner or locked client. No account key is copied or reopened.
    pub fn take_client(&self, client: &mut RamfluxClient) -> Result<(), SdkError> {
        let mut slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        if slot.is_some() {
            return Err(SdkError::PairingCode("Busy"));
        }
        if client.account_db()?.local_account_id != self.account_id {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        *slot = client.active_account_db.take();
        Ok(())
    }

    /// Return the same DB capability to its frontend, with current local authority.
    /// # Errors
    /// Refuses another account owner or unresolved native authority.
    pub fn return_client(&self, client: &mut RamfluxClient) -> Result<(), SdkError> {
        if client.active_account_db.is_some() {
            return Err(SdkError::PairingCode("Busy"));
        }
        client.open_account_index(&self.root)?;
        client.born_v3_account = Some(Box::new(custody::load_account(
            &self.root,
            &self.account_id,
            custody::network_now()?,
        )?));
        client.active_account_db =
            self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?.take();
        Ok(())
    }

    /// Load the public keys from the exact staged or installed branch vault entry.
    /// # Errors
    /// Missing or foreign local entries refuse before commitment.
    pub fn public_keys(&self, reference: &DeviceRef) -> Result<(String, String), SdkError> {
        let entry = super::install_store::list_pending(&self.root, &self.account_id)?
            .into_iter()
            .find(|row| &row.recipient_ref == reference);
        let vault_ref = match entry {
            Some(row) => row.branch_vault_ref,
            None => {
                custody::load_data_account(&self.root, &self.account_id, custody::network_now()?)?
                    .branch_vault_ref()
                    .into()
            }
        };
        let branch = self.vault.load_branch(&vault_ref, &reference.account_anchor, reference)?;
        Ok((
            ramflux_protocol::encode_base64url(
                branch.signing.signing_key.verifying_key().to_bytes(),
            ),
            ramflux_protocol::encode_base64url(branch.agreement.public),
        ))
    }

    /// Sign the one exact data grant authorized by the mutually confirmed full bootstrap.
    /// No arbitrary caller can construct this authorization or supply a replacement peer key.
    /// # Errors
    /// Refuses a locked account, foreign local branch or altered transcript/grant.
    pub fn sign_full_grant(
        &self,
        authorization: &super::FullGrantSigningRequest<'_>,
    ) -> Result<String, SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        if db.local_account_id != self.account_id {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let request = authorization.request();
        let context = authorization.context();
        request
            .bind_transcript(context, &request.transcript_hash)
            .map_err(|error| super::transport::wire(&error))?;
        let local = match authorization.role() {
            "initiator" => &context.initiator,
            "responder" => &context.responder,
            _ => return Err(SdkError::PairingCode("WrongRole")),
        };
        let pending = super::install_store::list_pending(&self.root, &self.account_id)?
            .into_iter()
            .find(|row| row.recipient_ref == local.device_ref);
        let vault_ref = if let Some(row) = pending {
            row.branch_vault_ref
        } else {
            let account =
                custody::load_data_account(&self.root, &self.account_id, custody::network_now()?)?;
            if account.local_device_id()? != local.device_ref.device_id
                || account.record().body.account_anchor != local.device_ref.account_anchor
            {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            account.branch_vault_ref().into()
        };
        let branch = self.vault.load_branch(
            &vault_ref,
            &local.device_ref.account_anchor,
            &local.device_ref,
        )?;
        if ramflux_protocol::encode_base64url(branch.signing.signing_key.verifying_key().to_bytes())
            != local.branch_key
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let bytes = request
            .signing_bytes(authorization.role())
            .map_err(|error| super::transport::wire(&error))?;
        Ok(ramflux_protocol::encode_base64url(branch.signing.signing_key.sign(&bytes).to_bytes()))
    }

    pub(crate) fn record_invitation(
        &self,
        invitation: &Envelope<Invitation>,
        generation: u64,
    ) -> Result<(), SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        if db.pairing_live_rows()?.iter().any(|row| row.operation_id == invitation.body.request_id)
        {
            return Ok(());
        }
        let floor = db.pairing_floor()?;
        let seq = floor.as_ref().map_or(Ok(1), |row| {
            row.issued_seq.checked_add(1).ok_or(SdkError::PairingCode("Busy"))
        })?;
        let body = &invitation.body;
        let live = LiveRow {
            account_id: self.account_id.clone(),
            operation_id: body.request_id.clone(),
            invitation_id: body.invitation_id.clone(),
            issuer_seq: body.issuer_seq,
            local_seq: seq,
            generation,
            role: "initiator".into(),
            descriptor: ramflux_protocol::canonical_json_bytes(invitation)?,
            phase: "invited".into(),
            context: None,
            transcript_hash: None,
            proposal_hash: None,
            transfer_ciphertext_hash: None,
            candidate_id: None,
            branch_reservation: None,
            branch_vault_ref: None,
            primary_vault_ref: None,
            base_record_hash: body.base_record_hash.clone(),
            base_epoch: body.base_epoch,
            expires_at: body.expires_at,
            result: None,
        };
        db.commit_pairing_invitation(
            &FloorRow {
                account_id: self.account_id.clone(),
                account_anchor: body.account_anchor.clone(),
                issued_seq: seq,
                next_generation: generation.checked_add(1).ok_or(SdkError::PairingCode("Busy"))?,
            },
            &live,
        )?;
        Ok(())
    }

    pub(crate) fn proposal(
        &self,
        context: &ParticipantContext,
    ) -> Result<Envelope<EnrollmentBody>, SdkError> {
        let local = &context.transcript.responder;
        let common = &local.common;
        let pending = super::install_store::read_pending(
            &self.root,
            &self.account_id,
            &context.invitation.body.request_id,
        )?
        .ok_or(SdkError::PairingField("operation_id"))?;
        if pending.recipient_ref != local.device_ref {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let branch = self.vault.load_branch(
            &pending.branch_vault_ref,
            &common.account_anchor,
            &local.device_ref,
        )?;
        let body = EnrollmentBody {
            schema: "ramflux.identity.pairing.enrollment.v1".into(),
            version: 1,
            invitation_id: common.invitation_id.clone(),
            transcript_hash: context.transcript_hash.clone(),
            base_record_hash: common.record_hash.clone(),
            base_epoch: common.device_set_epoch,
            recipient_ref: local.device_ref.clone(),
            branch_signing_key: local.branch_key.clone(),
            agreement_key: local.agreement_key.clone(),
            requested_role: "secondary".into(),
            capabilities: common.capabilities.clone(),
            lease_expires_at: common.lease_expires_at,
            display_name: local.display_name.clone(),
        };
        body.validate().map_err(|error| super::transport::wire(&error))?;
        let signature = ramflux_protocol::encode_base64url(
            branch.signing.signing_key.sign(&signing_bytes(&body.schema, &body)?).to_bytes(),
        );
        let proposal = Envelope { body, signature };
        self.save_context(context, &proposal)?;
        Ok(proposal)
    }

    pub(crate) fn save_context(
        &self,
        context: &ParticipantContext,
        proposal: &Envelope<EnrollmentBody>,
    ) -> Result<(), SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        let mut live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == context.invitation.body.request_id)
            .ok_or(SdkError::PairingField("operation_id"))?;
        live.context = Some(ramflux_protocol::canonical_json_bytes(&serde_json::json!({
            "initiator": context.transcript.initiator, "responder": context.transcript.responder,
        }))?);
        live.transcript_hash = Some(context.transcript_hash.clone());
        live.proposal_hash = Some(object_hash(proposal)?);
        live.phase = "proposal_pending".into();
        db.put_pairing_live(&live)?;
        Ok(())
    }

    pub(crate) fn publish_enrollment(
        &self,
        context: &ParticipantContext,
        proposal: &Envelope<EnrollmentBody>,
    ) -> Result<PublishedHead, SdkError> {
        let p = &proposal.body;
        ramflux_crypto::verify_canonical_signature(
            &signing_bytes(&p.schema, p)?,
            &proposal.signature,
            &p.branch_signing_key,
        )?;
        let account = custody::load_account(&self.root, &self.account_id, custody::network_now()?)?;
        let common = &context.transcript.initiator.common;
        if object_hash(account.record())? != common.record_hash {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        let primary = account.group_primary(self.vault.as_ref())?;
        let certificate = primary.certify_branch(BranchCertificate {
            schema: ramflux_protocol::domain::CUSTODY_BRANCH_CERTIFICATE.into(),
            version: 1,
            account_anchor: common.account_anchor.clone(),
            master_certificate_hash: object_hash(&account.record().body.master_certificate)?,
            device_id: p.recipient_ref.device_id.clone(),
            device_epoch: p.recipient_ref.device_epoch,
            principal_kind: account.record().body.principal_kind,
            branch_signing_public_key: p.branch_signing_key.clone(),
            agreement_identity_public_key: p.agreement_key.clone(),
            capabilities: p.capabilities.clone(),
            not_before: common.lease_not_before,
            expires_at: p.lease_expires_at,
            cert_id: ramflux_protocol::encode_base64url(*super::super::random()?),
        })?;
        let mut slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.take().ok_or(SdkError::AccountDbNotUnlocked)?;
        let db = Mutex::new(db);
        let result = (|| {
            let live = db
                .lock()
                .map_err(|_| SdkError::PairingCode("Busy"))?
                .pairing_live_rows()?
                .into_iter()
                .find(|row| row.operation_id == context.invitation.body.request_id)
                .ok_or(SdkError::PairingField("operation_id"))?;
            let write = HeadWrite {
                account_id: self.account_id.clone(),
                operation_id: live.operation_id,
                invitation_id: Some(live.invitation_id),
                generation: live.generation,
                issuer_seq: live.issuer_seq,
                local_seq: live.local_seq,
                kind: HeadKind::Enroll,
                publisher_ref: context.transcript.initiator.device_ref.clone(),
                local_ref: context.transcript.initiator.device_ref.clone(),
                recipient_ref: Some(p.recipient_ref.clone()),
                revoked_id: None,
                certificate: Some(certificate),
                display_name: None,
                now: custody::network_now()?,
                branch_vault_ref: account.branch_vault_ref().into(),
                data_vault_ref: ramflux_storage::FileVaultSecretSource::owner_ref(&self.account_id),
                primary_vault_ref: Some(account.primary_vault_ref().into()),
            };
            super::publication::publish_ceremony_head(
                &db,
                &self.root,
                self.vault.as_ref(),
                &write,
                self.persist.as_ref(),
            )
        })();
        *slot = Some(db.into_inner().map_err(|_| SdkError::PairingCode("Busy"))?);
        result
    }

    pub(crate) fn install_enrollment(
        &self,
        context: &ParticipantContext,
        hash: &str,
        epoch: u64,
    ) -> Result<(), SdkError> {
        let authority = self.query.current_authority(&context.invitation.body.account_anchor)?;
        if object_hash(&authority.publication.record)? != hash
            || authority.publication.record.body.device_set_epoch != epoch
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        let mut install = super::install_store::read_pending(
            &self.root,
            &self.account_id,
            &context.invitation.body.request_id,
        )?
        .ok_or(SdkError::PairingField("operation_id"))?;
        install.record_hash = Some(hash.into());
        let head = HeadRow {
            account_id: self.account_id.clone(),
            operation_id: context.invitation.body.request_id.clone(),
            invitation_id: Some(context.invitation.body.invitation_id.clone()),
            generation: context.generation,
            kind: "enroll".into(),
            base_record_hash: context.invitation.body.base_record_hash.clone(),
            base_epoch: context.invitation.body.base_epoch,
            publisher_ref: ramflux_protocol::canonical_json_bytes(
                &context.transcript.initiator.device_ref,
            )?,
            candidate: ramflux_protocol::canonical_json_bytes(&authority.publication)?,
            candidate_hash: hash.into(),
            state: "acknowledged".into(),
            ack: Some(ramflux_protocol::canonical_json_bytes(
                &serde_json::json!({"record_hash": hash, "device_set_epoch": epoch}),
            )?),
            recipient_ref: Some(ramflux_protocol::canonical_json_bytes(&install.recipient_ref)?),
            revoked_ref: None,
            created_at: custody::network_now()?,
        };
        custody::verify_pairing_local(
            &install,
            &authority,
            self.vault.as_ref(),
            custody::network_now()?,
        )?;
        db.commit_pairing_head(&head)?;
        super::install_store::write_pending(&self.root, &install)?;
        super::activate_recipient(
            &Installation {
                root: &self.root,
                db,
                vault: self.vault.as_ref(),
                now: custody::network_now()?,
            },
            &install,
            hash,
            self.query.as_ref(),
        )?;
        Ok(())
    }
}

mod full;
