// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source add-device publication with short frontend writer operations around native I/O.
use super::{HeadWrite, LocalPairingParticipant, ParticipantContext, PublishedHead, SdkError};
use crate::custody::pairing::{NodeHeadPersist, PairingAuthorityQuery};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{
        CustodyAuthority, Envelope, Publication, object_hash, pairing::channel::EnrollmentBody,
    },
};
use ramflux_storage::{AccountDb, FullLocalUnlockGuard};
use std::{path::PathBuf, sync::Arc};

use super::{BranchCertificate, HeadKind, custody, signing_bytes};
pub(crate) struct PreparedEnrollment {
    root: PathBuf,
    write: HeadWrite,
    publication: Publication,
    unlock: FullLocalUnlockGuard,
    persist: Arc<dyn NodeHeadPersist>,
    query: Arc<dyn PairingAuthorityQuery>,
}
pub(crate) struct ObservedEnrollment {
    work: PreparedEnrollment,
    authority: CustodyAuthority,
}
impl PreparedEnrollment {
    pub(crate) fn submit(self) -> Result<ObservedEnrollment, SdkError> {
        self.unlock.require_unlocked()?;
        let expected = object_hash(&self.publication.record)?;
        let anchor = &self.publication.record.body.account_anchor;
        let before = self.query.current_authority(anchor)?;
        let before =
            ramflux_crypto::custody::verify_publication(&before, crate::custody::network_now()?)?;
        let current = object_hash(before.envelope())?;
        self.unlock.require_unlocked()?;
        if current != expected {
            if before.envelope().body.device_set_epoch
                >= self.publication.record.body.device_set_epoch
                || self.publication.record.body.previous_record_hash.as_deref()
                    != Some(current.as_str())
            {
                return Err(SdkError::PairingCode("HeadChanged"));
            }
            if self.persist.persist_head(&self.publication, crate::custody::network_now()?)?
                != expected
            {
                return Err(SdkError::PairingCode("HeadChanged"));
            }
        }
        self.unlock.require_unlocked()?;
        let authority = self.query.current_authority(anchor)?;
        let verified = ramflux_crypto::custody::verify_publication(
            &authority,
            crate::custody::network_now()?,
        )?;
        if object_hash(verified.envelope())? != expected
            || canonical_json_bytes(&authority.publication)?
                != canonical_json_bytes(&self.publication)?
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        self.unlock.require_unlocked()?;
        Ok(ObservedEnrollment { work: self, authority })
    }
}
impl ObservedEnrollment {
    pub(crate) fn acknowledge(
        self,
        participant: &LocalPairingParticipant,
        db: &AccountDb,
    ) -> Result<PublishedHead, SdkError> {
        self.work.unlock.require_unlocked()?;
        participant
            .full_selected_db(db, Some(&self.work.publication.record.body.account_anchor))?;
        if std::fs::canonicalize(&participant.root)? != std::fs::canonicalize(&self.work.root)?
            || participant.account_id != self.work.write.account_id
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        super::super::publication::acknowledge_ceremony_in(
            db,
            &self.work.root,
            participant.vault.as_ref(),
            &self.work.write,
            &self.authority,
        )
    }
}
impl LocalPairingParticipant {
    pub(super) fn enrollment_write(
        &self,
        db: &AccountDb,
        context: &ParticipantContext,
        proposal: &Envelope<EnrollmentBody>,
    ) -> Result<HeadWrite, SdkError> {
        self.full_selected_db(db, Some(&context.invitation.body.account_anchor))?;
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
            cert_id: ramflux_protocol::encode_base64url(*crate::custody::random()?),
        })?;
        drop(primary); // The public certificate goes to a separate head signing owner.
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == context.invitation.body.request_id)
            .ok_or(SdkError::PairingField("operation_id"))?;
        Ok(HeadWrite {
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
        })
    }

    pub(crate) fn prepare_enrollment_in(
        &self,
        db: &AccountDb,
        context: &ParticipantContext,
        proposal: &Envelope<EnrollmentBody>,
    ) -> Result<PreparedEnrollment, SdkError> {
        let write = self.enrollment_write(db, context, proposal)?;
        let publication = super::super::publication::prepare_head_submission_in(
            db,
            &self.root,
            self.vault.as_ref(),
            &write,
        )?;
        Ok(PreparedEnrollment {
            root: self.root.clone(),
            write,
            publication,
            unlock: db.full_local_unlock_guard()?,
            persist: self.persist.clone(),
            query: self.query.clone(),
        })
    }
}
