// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original branch signatures admitted only by the current local installed tail endpoint.
use crate::{SdkError, custody::pairing::LocalPairingParticipant};
use ed25519_dalek::Signer as _;
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::{
    custody::pairing::full_transfer::{DataPacket, SourceManifest},
    encode_base64url,
};
use ramflux_storage::{AccountDb, FullSourceDeltaDraft};

/// A fresh native observation and exact local operation for one short tail action.
/// This public context carries no signer, data key or reusable admission right.
pub struct FullTailContext<'a> {
    pub operation: &'a str,
    pub generation: u64,
    pub current: &'a VerifiedRecord,
    pub now: u64,
}
impl LocalPairingParticipant {
    /// Sign and durably retain only this original A's immutable J6 tail.
    /// # Errors
    /// Refuses a foreign selected writer/draft, stale native authority, expiry or changed key.
    pub fn sign_and_retain_full_tail_manifest(
        &self,
        db: &AccountDb,
        context: &FullTailContext<'_>,
        draft: &FullSourceDeltaDraft,
    ) -> Result<SourceManifest, SdkError> {
        self.full_selected_db(db, Some(&draft.manifest().account_anchor))?;
        let mut endpoint = db.open_full_tail_endpoint(
            context.operation,
            context.generation,
            context.current,
            context.now,
        )?;
        let bytes = endpoint.source_manifest_signing_bytes(draft, context.now)?;
        let manifest = self.with_full_branch_in(
            db,
            &draft.manifest().source_ref,
            draft.expected_branch_key(),
            |branch| {
                let signature =
                    encode_base64url(branch.signing.signing_key.sign(&bytes).to_bytes());
                Ok(draft.signed_manifest(signature)?)
            },
        )?;
        endpoint.retain_source(draft, &manifest, context.now)?;
        Ok(manifest)
    }
    /// Sign and durably retain B's receipt only after both selected-writer merge passes.
    /// # Errors
    /// Refuses partial/foreign input, a replaced writer, stale native authority or lost branch.
    pub fn commit_full_tail_receipt(
        &self,
        db: &AccountDb,
        context: &FullTailContext<'_>,
        hash: &str,
    ) -> Result<DataPacket, SdkError> {
        self.full_selected_db(db, None)?;
        let endpoint = db.open_full_tail_endpoint(
            context.operation,
            context.generation,
            context.current,
            context.now,
        )?;
        let application = endpoint.applied_receipt(hash, context.now)?;
        let DataPacket::DataVerified { destination_ref, .. } = application.packet() else {
            return Err(SdkError::PairingCode("WrongContext"));
        };
        let packet = self.with_full_branch_in(
            db,
            destination_ref,
            application.expected_branch_key(),
            |branch| {
                let bytes = application
                    .packet()
                    .data_verified_signing_bytes()
                    .map_err(|_| SdkError::PairingCode("WrongContext"))?;
                let signature =
                    encode_base64url(branch.signing.signing_key.sign(&bytes).to_bytes());
                Ok(application.signed_packet(signature)?)
            },
        )?;
        endpoint.record_applied_receipt(&application, &packet, context.now)?;
        Ok(packet)
    }
}

/// Only authenticated local pending state can create a fresh tail epoch.
pub(in crate::custody::pairing) struct FullTailResume {
    pub(in crate::custody::pairing) trust: ramflux_crypto::custody::pairing::FullResumeTrust,
    pub(in crate::custody::pairing) signer: std::sync::Arc<super::proof_signer::FullProofSigner>,
    pub(in crate::custody::pairing) cancelled: ramflux_storage::FullStageIoCancel,
    pub(in crate::custody::pairing) origin: String,
}
impl LocalPairingParticipant {
    pub(in crate::custody::pairing) fn restore_full_tail_in(
        &self,
        db: &AccountDb,
        request: &ramflux_protocol::custody::pairing::local_dto::StatusRequest,
        node: &ramflux_crypto::custody::VerifiedNodeRecord,
        current: &VerifiedRecord,
    ) -> Result<FullTailResume, SdkError> {
        use ramflux_crypto::custody::pairing::{FullResumeTrust, PairingRole};
        use ramflux_protocol::custody::pairing::{PairingWire as _, context_v3::TranscriptV3};
        let now = crate::custody::network_now()?;
        self.full_selected_db(db, None)?;
        let endpoint =
            db.open_full_tail_endpoint(&request.operation_id, request.generation, current, now)?;
        let record = endpoint.pending_resume_record(now)?;
        if record.role == PairingRole::Responder {
            let install = crate::custody::pairing::install_store::read_installed(
                &self.root,
                &self.account_id,
            )?
            .ok_or(SdkError::PairingCode("PublicationPending"))?;
            let native = crate::custody::load_data_account(&self.root, &self.account_id, now)?;
            let adoption = db.pairing_adoption()?.ok_or(SdkError::PairingCode("WrongContext"))?;
            crate::custody::pairing::full_generation::require_completed_full_generation(
                &self.root, &native, &install, &adoption,
            )?;
        }
        let context = TranscriptV3::from_wire_bytes(&record.transcript)
            .map_err(|_| SdkError::PairingCode("WrongContext"))?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == request.operation_id)
            .ok_or(SdkError::PairingCode("WrongContext"))?;
        let invitation = super::data_resume::resume_invitation(&live, &context, node)?;
        let reference = match record.role {
            PairingRole::Initiator => &record.grant.source_ref,
            PairingRole::Responder => &record.grant.destination_ref,
        };
        let reference = reference.clone();
        let own_key = self.public_keys(&reference)?.0;
        let trust = FullResumeTrust::restore_local_stage(record, node, &reference, &own_key, now)?;
        let cancelled = endpoint.io_cancel_handle();
        drop(endpoint);
        let signer = self.prepare_full_proof_signer_in(
            db,
            &request.operation_id,
            request.generation,
            &trust,
        )?;
        Ok(FullTailResume {
            trust,
            signer: std::sync::Arc::new(signer),
            cancelled,
            origin: invitation.body.public_origin,
        })
    }
}
