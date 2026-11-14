// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reuse the exact durable B candidate; recovery never creates a key or signature.
use super::{
    FullPreparedTransferCandidate, LocalPairingParticipant, SdkError, install_store, wrong,
};
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{Publication, object_hash},
};
use ramflux_storage::{AccountDb, LiveRow};
impl LocalPairingParticipant {
    pub(crate) fn restore_prepared_full_candidate_in(
        &self,
        db: &AccountDb,
        live: &LiveRow,
        current: &VerifiedRecord,
        now: u64,
    ) -> Result<Option<FullPreparedTransferCandidate>, SdkError> {
        let Some(head) = db.pairing_head()? else { return Ok(None) };
        if live.role != "responder"
            || live.phase != "prepared"
            || head.state != "prepared"
            || head.kind != "transfer"
            || head.operation_id != live.operation_id
            || head.generation != live.generation
            || head.ack.is_some()
        {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        self.full_selected_db(db, Some(&current.envelope().body.account_anchor))?;
        let mut stage = db.open_full_transfer_stage(
            &live.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            now,
        )?;
        stage.observe_full_native_head(current)?;
        let record = stage.resume_record()?;
        ramflux_crypto::custody::pairing::verify_full_prepublication_authority(
            &record.grant,
            current,
            now,
        )?;
        let publication: Publication = ramflux_protocol::parse_i_json(&head.candidate)?;
        let install =
            install_store::read_pending(&self.root, &self.account_id, &live.operation_id)?
                .ok_or_else(wrong)?;
        let base = object_hash(current.envelope())?;
        if head.base_record_hash != base
            || head.base_epoch != current.envelope().body.device_set_epoch
            || stage.full_prepublication_record_hash()? != base
            || publication.record.body.previous_record_hash.as_deref() != Some(base.as_str())
            || canonical_json_bytes(&publication)? != head.candidate
            || object_hash(&publication.record)? != head.candidate_hash
            || install.record_hash.as_deref() != Some(head.candidate_hash.as_str())
            || install.install_purpose != "transfer_destination"
            || install.state != "vault_durable"
            || install.primary_vault_ref.is_none()
            || install.full_transfer.is_some()
            || install.recipient_ref != record.grant.destination_ref
            || publication.record.body.master_certificate.body.primary_device_ref
                != install.recipient_ref
            || head.recipient_ref.as_deref()
                != Some(canonical_json_bytes(&install.recipient_ref)?.as_slice())
            || head.publisher_ref != canonical_json_bytes(&record.grant.source_ref)?
        {
            return Err(wrong());
        }
        ramflux_crypto::custody::verify_publication(
            &ramflux_protocol::custody::CustodyAuthority {
                publication: publication.clone(),
                custodian_publication: None,
            },
            now,
        )?;
        Ok(Some(FullPreparedTransferCandidate {
            previous: Box::new(current.envelope().clone()),
            publication,
            install,
            duplex: stage.verified_duplex(now)?,
        }))
    }
}

impl LocalPairingParticipant {
    pub(crate) fn restore_prepared_full_source_candidate_in(
        &self,
        db: &AccountDb,
        live: &LiveRow,
        current: &VerifiedRecord,
        now: u64,
    ) -> Result<Option<Publication>, SdkError> {
        let Some(head) = db.pairing_head()? else { return Ok(None) };
        if live.role != "initiator" {
            return Ok(None);
        }
        if live.phase != "prepared"
            || head.state != "prepared"
            || head.kind != "transfer"
            || head.operation_id != live.operation_id
            || head.generation != live.generation
            || head.ack.is_some()
        {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        self.full_selected_db(db, Some(&current.envelope().body.account_anchor))?;
        let mut stage = db.open_full_transfer_stage(
            &live.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            now,
        )?;
        stage.observe_full_native_head(current)?;
        let record = stage.resume_record()?;
        ramflux_crypto::custody::pairing::verify_full_prepublication_authority(
            &record.grant,
            current,
            now,
        )?;
        let candidate: Publication = ramflux_protocol::parse_i_json(&head.candidate)?;
        let base = object_hash(current.envelope())?;
        let owner = stage.source_primary_owner()?.ok_or_else(wrong)?;
        let account = crate::custody::load_data_account(&self.root, &self.account_id, now)?;
        if head.base_record_hash != base
            || head.base_epoch != current.envelope().body.device_set_epoch
            || stage.full_prepublication_record_hash()? != base
            || candidate.record.body.previous_record_hash.as_deref() != Some(base.as_str())
            || canonical_json_bytes(&candidate)? != head.candidate
            || object_hash(&candidate.record)? != head.candidate_hash
            || head.publisher_ref != canonical_json_bytes(&record.grant.source_ref)?
            || head.recipient_ref.as_deref()
                != Some(canonical_json_bytes(&record.grant.destination_ref)?.as_slice())
            || candidate.record.body.master_certificate.body.primary_device_ref
                != record.grant.destination_ref
            || owner.reference() != account.primary_vault_ref()
            || owner.public_key()
                != current.envelope().body.master_certificate.body.self_signing_public_key
        {
            return Err(wrong());
        }
        stage.verified_duplex(now)?;
        Ok(Some(candidate))
    }
}
