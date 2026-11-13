// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh data-stage linking only; no candidate replacement or approval.
use super::{
    LocalPairingParticipant, PreparedFullSource, SdkError, custody, encode_base64url, wrong,
};

impl LocalPairingParticipant {
    /// Persist a terminal data fence while preserving every stage and uncertain candidate.
    /// Before a lease is linked there is no data stage to reopen; legacy early rows stay fenced
    /// by their absence of a stage reference. Only the own encrypted terminal marker is written.
    pub(crate) fn mark_full_data_terminal(
        &self,
        operation: &str,
        generation: u64,
        phase: &str,
    ) -> Result<(), SdkError> {
        if !matches!(phase, "cancelled" | "expired" | "rejected") {
            return Err(wrong());
        }
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        self.full_selected_db(db, None)?;
        let Some(mut row) =
            db.pairing_live_rows()?.into_iter().find(|row| row.operation_id == operation)
        else {
            return Ok(());
        };
        if row.generation != generation {
            return Err(wrong());
        }
        if matches!(row.phase.as_str(), "completed" | "cancelled" | "expired" | "rejected") {
            return Ok(());
        }
        if row.full_stage_reference()?.is_none() {
            return Ok(());
        }
        // Close data durably before changing the account projection. A later exact
        // installation may change that projection without reviving the data epoch.
        let role = if row.role == "initiator" {
            ramflux_crypto::custody::pairing::PairingRole::Initiator
        } else {
            ramflux_crypto::custody::pairing::PairingRole::Responder
        };
        db.mark_full_transfer_data_terminal(operation, role, phase, custody::network_now()?)?;
        // An uncertain publication is retained verbatim for a separate reconciliation owner.
        row.phase = phase.into();
        db.put_pairing_live(&row)?;
        Ok(())
    }
    /// Commit/fsync the encrypted data-only record before updating its actual live-row link.
    /// Source binding consumes only a locally prepared cut and original-source-signed manifest.
    /// No SAS approval, epoch token/key, native authority or candidate is restored by this link.
    /// # Errors
    /// Refuses stale local scope/generation/descriptor, a foreign trust/base or failed I/O.
    pub(crate) fn retain_full_data_stage(
        &self,
        operation: &str,
        generation: u64,
        trust: &ramflux_crypto::custody::pairing::FullResumeTrust,
        base: &ramflux_crypto::custody::VerifiedRecord,
        source: Option<(
            &PreparedFullSource,
            &ramflux_protocol::custody::pairing::full_transfer::SourceManifest,
        )>,
    ) -> Result<ramflux_storage::FullStageIoCancel, SdkError> {
        use ramflux_crypto::custody::pairing::PairingRole;
        use ramflux_protocol::custody::pairing::{PairingWire, context_v3::TranscriptV3};
        let saved = trust.local_stage_record()?;
        let context = TranscriptV3::from_wire_bytes(&saved.transcript)
            .map_err(|error| crate::custody::pairing::transport::wire(&error))?;
        let slot = self.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        let db = slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?;
        self.full_selected_db(db, Some(&context.initiator.common.account_anchor))?;
        let mut row = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if !matches!(
            row.phase.as_str(),
            "invited" | "commitments" | "revealed" | "sas_pending" | "mutually_confirmed"
        ) || row.candidate_id.is_some()
            || row.proposal_hash.is_some()
            || row.full_stage_reference()?.is_some()
        {
            return Err(wrong());
        }
        let invitation: ramflux_protocol::custody::Envelope<
            ramflux_protocol::custody::pairing::native::Invitation,
        > = ramflux_protocol::custody::decode(&row.descriptor, 16_384)?;
        let expected =
            ramflux_protocol::custody::pairing::context_v3::CommonV3::from_full_invitation(
                &invitation.body,
                context.initiator.common.master_public_key.clone(),
            )
            .map_err(|error| crate::custody::pairing::transport::wire(&error))?;
        if expected != context.initiator.common {
            return Err(wrong());
        }
        if row.generation != generation
            || row.role != saved.role.as_str()
            || row.invitation_id != context.initiator.common.invitation_id
            || row.issuer_seq != context.initiator.common.issuer_seq
            || row.base_record_hash != saved.base_record_hash
            || row.base_epoch != context.initiator.common.device_set_epoch
        {
            return Err(wrong());
        }
        let stage = match (saved.role, source) {
            (PairingRole::Initiator, Some((prepared, manifest))) => db
                .open_full_source_preparation(prepared)?
                .bind_full_transfer(trust, base, manifest, custody::network_now()?)?,
            (PairingRole::Responder, None) => db.create_full_transfer_stage(trust, base)?,
            _ => return Err(wrong()),
        };
        let cancel = stage.io_cancel_handle();
        row.phase = "mutually_confirmed".into();
        row.expires_at = trust.lease_expires_at();
        row.context = Some(
            stage
                .reference()
                .to_wire_bytes()
                .map_err(|error| crate::custody::pairing::transport::wire(&error))?,
        );
        row.transcript_hash = Some(encode_base64url(saved.th));
        // Only the fresh, candidate-free phase above may install this data-only link.
        db.put_pairing_live(&row)?;
        drop(stage);
        Ok(cancel)
    }
}
