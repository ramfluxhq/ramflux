// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original A primary signs only the same live actor's exact data-bound preservation.
use super::{LocalPairingParticipant, custody, wrong};
use crate::SdkError;
use ramflux_protocol::{
    custody::{
        Envelope, Publication, object_hash,
        pairing::{PairingWire, context_v3::TranscriptV3, full_transfer::PreservationFull},
    },
    encode_base64url,
};
impl LocalPairingParticipant {
    pub(in crate::custody::pairing) fn preserve_full_candidate(
        &self,
        operation: &str,
        generation: u64,
        th: [u8; 32],
        candidate: &Publication,
    ) -> Result<Envelope<PreservationFull>, SdkError> {
        // Independent native freshness completes before borrowing the actual A writer.
        let anchor = &candidate.record.body.account_anchor;
        let current = self.full_native_head(anchor)?;
        let authority = self.query.current_authority(anchor)?;
        let now = custody::network_now()?;
        let verified = ramflux_crypto::custody::verify_publication(&authority, now)?;
        if object_hash(verified.envelope())? != object_hash(current.envelope())?
            || candidate.compacted_ids != authority.publication.compacted_ids
        {
            return Err(wrong());
        }
        let proposed = ramflux_crypto::custody::verify_publication(
            &ramflux_protocol::custody::CustodyAuthority {
                publication: candidate.clone(),
                custodian_publication: None,
            },
            now,
        )?;
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        self.full_selected_db(db, Some(anchor))?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if live.generation != generation
            || live.role != "initiator"
            || live.phase != "mutually_confirmed"
        {
            return Err(wrong());
        }
        let stage = db.open_full_transfer_stage(
            operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            now,
        )?;
        let record = stage.resume_record()?;
        if record.th != th
            || record.base_record_hash != object_hash(current.envelope())?
            || record.grant.source_ref
                != current.envelope().body.master_certificate.body.primary_device_ref
        {
            return Err(wrong());
        }
        let context = TranscriptV3::from_wire_bytes(&record.transcript)
            .map_err(|error| super::super::super::transport::wire(&error))?;
        let common = &context.initiator.common;
        let destination = proposed.authorize(&record.grant.destination_ref, "register", now)?;
        if destination.branch_signing_public_key != context.responder.branch_key
            || destination.agreement_identity_public_key != context.responder.agreement_key
            || (common.recipient_mode == "new"
                && (destination.capabilities != common.capabilities
                    || destination.not_before != common.lease_not_before
                    || destination.expires_at != common.lease_expires_at))
        {
            return Err(wrong());
        }
        let proof = stage.verified_duplex(now)?;
        super::require_candidate_lease(proof.expires_at(), now)?;
        let account = custody::load_account(&self.root, &self.account_id, now)?;
        if object_hash(account.record())? != record.base_record_hash {
            return Err(wrong());
        }
        if let Some(saved) =
            stage.retained_source_full_preservation(current.envelope(), &candidate.record, now)?
        {
            return Ok(saved);
        }
        let primary = account.group_primary(self.vault.as_ref())?;
        let body = PreservationFull {
            schema: "ramflux.identity.transfer.preserve.full.v1".into(),
            version: 1,
            transfer_id: record.transfer_id,
            transcript_hash: encode_base64url(th),
            old_record_hash: record.base_record_hash,
            new_record_hash: object_hash(&candidate.record)?,
            destination_ref: record.grant.destination_ref,
            recipient_mode: context.initiator.common.recipient_mode,
            policy: "preserve_all_existing".into(),
            expires_at: now.saturating_add(300).min(proof.expires_at()),
            manifest_chain_hash: proof.manifest_chain_hash().into(),
            data_verified_hash: proof.data_verified_hash().into(),
            target_restrictions_root: proof.target_restrictions_root().into(),
        };
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
