// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attended private provider/native waits own no ordinary account database loan.
use super::{
    AccountDb, CredentialRequest, FullPreparedTransferCandidate, LocalPairingParticipant,
    MasterKey, Prepare, RecoveryPhrase, Scope, SdkError, SelfSigningKey, custody, install_store,
    local_credential, object_hash, wrong,
};
use ramflux_storage::FullLocalUnlockGuard;

pub(crate) struct FullCandidateWork {
    scope: Scope,
    request: Prepare,
    frontend_generation: u64,
    guard: FullLocalUnlockGuard,
}
pub(crate) struct FullCandidateDraft {
    scope: Scope,
    request: Prepare,
    frontend_generation: u64,
    reservation: String,
    guard: FullLocalUnlockGuard,
    publication: ramflux_protocol::custody::Publication,
    previous: Box<ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>>,
    primary: SelfSigningKey,
}
impl LocalPairingParticipant {
    pub(crate) fn prepare_full_candidate_work(
        &self,
        db: &AccountDb,
        request: Prepare,
        frontend_generation: u64,
    ) -> Result<FullCandidateWork, SdkError> {
        let scope = self.candidate_scope_in(db, &request, custody::network_now()?)?;
        Ok(FullCandidateWork {
            scope,
            request,
            frontend_generation,
            guard: db.full_local_unlock_guard()?,
        })
    }
}
impl FullCandidateWork {
    pub(crate) fn prepare(
        self,
        participant: &LocalPairingParticipant,
    ) -> Result<FullCandidateDraft, SdkError> {
        self.guard.require_unlocked()?;
        let common = &self.scope.context.initiator.common;
        let now = custody::network_now()?;
        let current = participant.full_native_stream_head(
            &common.account_anchor,
            Some((&self.request.operation_id, &self.scope.install.recipient_ref)),
        )?;
        if object_hash(current.envelope())? != self.scope.bound_hash {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        let stored =
            local_credential::load_reservation(&participant.root, &participant.account_id)?
                .ok_or_else(wrong)?;
        if stored.frontend_generation != self.frontend_generation {
            return Err(wrong());
        }
        let expected = CredentialRequest {
            local_account_id: participant.account_id.clone(),
            reservation_id: stored.reservation_id.clone(),
            frontend_generation: self.frontend_generation,
            action: "phrase".into(),
        };
        let binding = crate::custody::pairing::private_credential::PrivateCredentialScope::phrase(
            expected.clone(),
            self.request.operation_id.clone(),
            None,
            &self.scope.live.role,
            "awaiting_prepare",
        )?;
        let provider = local_credential::scoped(participant.provider.as_ref(), binding);
        let secret =
            local_credential::acquire_phrase(&participant.root, &expected, &provider, &stored)?;
        self.guard.require_unlocked()?;
        let phrase =
            RecoveryPhrase::parse(std::str::from_utf8(secret.as_bytes()).map_err(|_| wrong())?)?;
        let master = MasterKey::from_phrase(&phrase)?;
        drop(phrase);
        drop(secret);
        if master.public_key() != common.master_public_key {
            return Err(wrong());
        }
        let primary = SelfSigningKey::generate()?;
        let mut publication = participant.full_candidate_publication(
            &self.scope,
            &current,
            &master,
            &primary,
            now,
        )?;
        drop(master);
        let latest = participant.full_native_stream_head(
            &common.account_anchor,
            Some((&self.request.operation_id, &self.scope.install.recipient_ref)),
        )?;
        if object_hash(latest.envelope())? != self.scope.bound_hash {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        let authority = participant.query.current_authority(&common.account_anchor)?;
        let verified =
            ramflux_crypto::custody::verify_publication(&authority, custody::network_now()?)?;
        if object_hash(verified.envelope())? != self.scope.bound_hash {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        publication.compacted_ids = authority.publication.compacted_ids;
        ramflux_crypto::custody::verify_publication(
            &ramflux_protocol::custody::CustodyAuthority {
                publication: publication.clone(),
                custodian_publication: None,
            },
            custody::network_now()?,
        )?;
        self.guard.require_unlocked()?;
        Ok(FullCandidateDraft {
            scope: self.scope,
            request: self.request,
            frontend_generation: self.frontend_generation,
            reservation: stored.reservation_id,
            guard: self.guard,
            previous: Box::new(current.envelope().clone()),
            publication,
            primary,
        })
    }
}
impl FullCandidateDraft {
    pub(crate) fn finish(
        self,
        participant: &LocalPairingParticipant,
        db: &AccountDb,
    ) -> Result<FullPreparedTransferCandidate, SdkError> {
        self.guard.require_unlocked()?;
        let fresh = participant.candidate_scope_in(db, &self.request, custody::network_now()?)?;
        let stored =
            local_credential::load_reservation(&participant.root, &participant.account_id)?
                .ok_or_else(wrong)?;
        if fresh.install != self.scope.install
            || fresh.context != self.scope.context
            || fresh.bound_hash != self.scope.bound_hash
            || fresh.bound_epoch != self.scope.bound_epoch
            || fresh.duplex.manifest_chain_hash() != self.scope.duplex.manifest_chain_hash()
            || fresh.duplex.data_verified_hash() != self.scope.duplex.data_verified_hash()
            || stored.reservation_id != self.reservation
            || stored.frontend_generation != self.frontend_generation
        {
            return Err(wrong());
        }
        let mut install = self.scope.install.clone();
        let reference = install.primary_vault_ref.clone().ok_or_else(wrong)?;
        participant.vault.store_new(&reference, &self.primary)?;
        install.primary_vault_ref = Some(reference);
        install.record_hash = Some(object_hash(&self.publication.record)?);
        install_store::write_pending(&participant.root, &install)?;
        participant.retain_full_candidate_in(
            db,
            &self.request,
            &self.scope,
            &self.publication,
            custody::network_now()?,
        )?;
        Ok(FullPreparedTransferCandidate {
            previous: self.previous,
            publication: self.publication,
            install,
            duplex: self.scope.duplex,
        })
    }
}
