// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original A primary signs only the same live actor's exact data-bound preservation.
use super::{LocalPairingParticipant, custody, wrong};
use crate::SdkError;
use ramflux_protocol::{
    custody::{
        Envelope, object_hash,
        pairing::{PairingWire, context_v3::TranscriptV3, full_transfer::PreservationFull},
    },
    encode_base64url,
};
impl LocalPairingParticipant {
    pub(in crate::custody::pairing) fn preserve_full_candidate(
        &self,
        observation: &super::FullSourceCandidateObservation,
    ) -> Result<Envelope<PreservationFull>, SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        self.preserve_candidate(db, observation, true)
    }
    pub(in crate::custody::pairing) fn retained_full_candidate(
        &self,
        observation: &super::FullSourceCandidateObservation,
    ) -> Result<Envelope<PreservationFull>, SdkError> {
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        self.preserve_candidate(db, observation, false)
    }
    pub(super) fn retained_full_candidate_in(
        &self,
        db: &ramflux_storage::AccountDb,
        observation: &super::FullSourceCandidateObservation,
    ) -> Result<Envelope<PreservationFull>, SdkError> {
        self.preserve_candidate(db, observation, false)
    }
    pub(in crate::custody::pairing) fn preserve_full_candidate_in(
        &self,
        db: &ramflux_storage::AccountDb,
        observation: &super::FullSourceCandidateObservation,
    ) -> Result<Envelope<PreservationFull>, SdkError> {
        if self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?.is_some() {
            return Err(SdkError::PairingCode("Busy"));
        }
        self.preserve_candidate(db, observation, true)
    }
    fn preserve_candidate(
        &self,
        db: &ramflux_storage::AccountDb,
        observation: &super::FullSourceCandidateObservation,
        allow_new_signature: bool,
    ) -> Result<Envelope<PreservationFull>, SdkError> {
        let (operation, generation, th) = &observation.scope;
        self.require_source_observation(observation, &observation.scope)?;
        let candidate = &observation.candidate;
        let authority = &observation.authority;
        let anchor = &candidate.record.body.account_anchor;
        let now = custody::network_now()?;
        let current = ramflux_crypto::custody::verify_publication(authority, now)?;
        if candidate.compacted_ids != authority.publication.compacted_ids {
            return Err(wrong());
        }
        let proposed = ramflux_crypto::custody::verify_publication(
            &ramflux_protocol::custody::CustodyAuthority {
                publication: candidate.clone(),
                custodian_publication: authority.custodian_publication.clone(),
            },
            now,
        )?;
        self.full_selected_db(db, Some(anchor))?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == *operation)
            .ok_or_else(wrong)?;
        if live.generation != *generation
            || live.role != "initiator"
            || !matches!(live.phase.as_str(), "mutually_confirmed" | "prepared" | "submitted")
        {
            return Err(wrong());
        }
        let mut stage = db.open_full_transfer_stage(
            operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            now,
        )?;
        stage.observe_full_native_head(&current)?;
        let record = stage.resume_record()?;
        let bound_hash = stage.full_prepublication_record_hash()?;
        stage.require_full_prepublication_record(&current)?;
        if record.th != *th
            || bound_hash != object_hash(current.envelope())?
            || record.grant.source_ref
                != current.envelope().body.master_certificate.body.primary_device_ref
        {
            return Err(wrong());
        }
        let context = TranscriptV3::from_wire_bytes(&record.transcript)
            .map_err(|error| super::super::super::transport::wire(&error))?;
        require_destination(&context, &proposed, &record.grant.destination_ref, now)?;
        let proof = stage.verified_duplex(now)?;
        let account = custody::load_account(&self.root, &self.account_id, now)?;
        if object_hash(account.record())? != bound_hash {
            return Err(wrong());
        }
        let renew = allow_new_signature
            && stage.has_expired_source_full_preservation(
                current.envelope(),
                &candidate.record,
                now,
            )?;
        if !renew
            && let Some(saved) = stage.retained_source_full_preservation(
                current.envelope(),
                &candidate.record,
                now,
            )?
        {
            require_original_owner(
                &stage,
                &account,
                &current.envelope().body.master_certificate.body.self_signing_public_key,
            )?;
            return Ok(saved);
        }
        if !allow_new_signature {
            return Err(wrong());
        }
        require_new_preservation_scope(db, &live, candidate, &bound_hash)?;
        super::require_candidate_lease(proof.expires_at(), now)?;
        let primary = account.group_primary(self.vault.as_ref())?;
        stage.retain_source_primary_owner(account.primary_vault_ref(), current.envelope())?;
        let body = preservation_body(
            observation,
            record,
            &proof,
            context.initiator.common.recipient_mode,
            bound_hash,
            now,
        )?;
        let signed = primary.sign_cooperative_full_preservation(&current, &proposed, body, now)?;
        stage.retain_source_full_preservation(
            current.envelope(),
            &candidate.record,
            &signed,
            now,
        )?;
        Ok(signed)
    }
}

fn preservation_body(
    observation: &super::FullSourceCandidateObservation,
    record: ramflux_crypto::custody::pairing::FullResumeRecord,
    proof: &ramflux_storage::FullDuplexReceipt,
    recipient_mode: String,
    bound_hash: String,
    now: u64,
) -> Result<PreservationFull, SdkError> {
    Ok(PreservationFull {
        schema: "ramflux.identity.transfer.preserve.full.v1".into(),
        version: 1,
        transfer_id: record.transfer_id,
        transcript_hash: encode_base64url(record.th),
        old_record_hash: bound_hash,
        new_record_hash: object_hash(&observation.candidate.record)?,
        destination_ref: record.grant.destination_ref,
        recipient_mode,
        policy: "preserve_all_existing".into(),
        expires_at: now.saturating_add(300).min(proof.expires_at()),
        manifest_chain_hash: proof.manifest_chain_hash().into(),
        data_verified_hash: proof.data_verified_hash().into(),
        target_restrictions_root: proof.target_restrictions_root().into(),
    })
}

fn require_new_preservation_scope(
    db: &ramflux_storage::AccountDb,
    live: &ramflux_storage::LiveRow,
    candidate: &ramflux_protocol::custody::Publication,
    base: &str,
) -> Result<(), SdkError> {
    match live.phase.as_str() {
        "mutually_confirmed" if db.pairing_head()?.is_none() => Ok(()),
        "prepared" => {
            let head = db.pairing_head()?.ok_or_else(wrong)?;
            if head.state != "prepared"
                || head.ack.is_some()
                || head.operation_id != live.operation_id
                || head.generation != live.generation
                || head.base_record_hash != base
                || head.candidate_hash != object_hash(&candidate.record)?
                || head.candidate != ramflux_protocol::canonical_json_bytes(candidate)?
            {
                return Err(wrong());
            }
            Ok(())
        }
        _ => Err(wrong()),
    }
}

fn require_original_owner(
    stage: &ramflux_storage::FullTransferStage,
    account: &custody::BornAccount,
    old_self_key: &str,
) -> Result<(), SdkError> {
    let owner = stage.source_primary_owner()?.ok_or_else(wrong)?;
    if owner.reference() != account.primary_vault_ref() || owner.public_key() != old_self_key {
        return Err(wrong());
    }
    Ok(())
}

pub(in crate::custody::pairing) fn require_destination(
    context: &TranscriptV3,
    proposed: &ramflux_crypto::custody::VerifiedRecord,
    reference: &ramflux_protocol::custody::DeviceRef,
    now: u64,
) -> Result<(), SdkError> {
    let common = &context.initiator.common;
    let destination = proposed.authorize(reference, "register", now)?;
    if destination.branch_signing_public_key != context.responder.branch_key
        || destination.agreement_identity_public_key != context.responder.agreement_key
        || (common.recipient_mode == "new"
            && (destination.capabilities != common.capabilities
                || destination.not_before != common.lease_not_before
                || destination.expires_at != common.lease_expires_at))
    {
        return Err(wrong());
    }
    Ok(())
}
