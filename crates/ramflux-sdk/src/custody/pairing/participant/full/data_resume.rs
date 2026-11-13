// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary unlock plus original node/branch proofs restore data trust only.
use super::{LocalPairingParticipant, custody, wrong};
use crate::SdkError;
use ramflux_crypto::custody::{
    VerifiedNodeRecord, VerifiedRecord,
    pairing::{
        FullResumeKeyOwner, FullResumeTrust, PairingRole, verify_full_prepublication_authority,
    },
};
use ramflux_protocol::custody::{
    DeviceRef, Envelope,
    pairing::{
        PairingWire,
        context_v3::{CommonV3, TranscriptV3},
        local_dto::StatusRequest,
        native::Invitation,
    },
};
use ramflux_storage::{AccountDb, FullStageIoCancel, LiveRow};
use std::sync::Arc;

pub(crate) struct FullDataResume {
    pub(in crate::custody::pairing) live: LiveRow,
    pub(in crate::custody::pairing) invitation: Envelope<Invitation>,
    pub(in crate::custody::pairing) context: TranscriptV3,
    pub(in crate::custody::pairing) trust: FullResumeTrust,
    pub(in crate::custody::pairing) keys: FullResumeKeyOwner,
    pub(in crate::custody::pairing) signer: Arc<super::proof_signer::FullProofSigner>,
    pub(in crate::custody::pairing) cancel: FullStageIoCancel,
    pub(in crate::custody::pairing) position: ramflux_storage::FullForwardResumePosition,
    pub(in crate::custody::pairing) frontend_generation: Option<u64>,
}
impl LocalPairingParticipant {
    pub(crate) fn restore_full_data_in(
        &self,
        db: &AccountDb,
        request: &StatusRequest,
        node: &VerifiedNodeRecord,
        current: &VerifiedRecord,
        reference: &DeviceRef,
    ) -> Result<FullDataResume, SdkError> {
        request.validate().map_err(|error| crate::custody::pairing::transport::wire(&error))?;
        self.full_selected_db(db, Some(&reference.account_anchor))?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == request.operation_id)
            .ok_or(SdkError::PairingCode("NotFound"))?;
        if live.generation != request.generation {
            return Err(wrong());
        }
        if live.phase != "mutually_confirmed" || db.pairing_head()?.is_some() {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        let role = match live.role.as_str() {
            "initiator" => PairingRole::Initiator,
            "responder" => PairingRole::Responder,
            _ => return Err(wrong()),
        };
        let now = custody::network_now()?;
        let mut stage = db.open_full_transfer_stage(&request.operation_id, role, now)?;
        let record = stage.resume_record()?;
        let context = TranscriptV3::from_wire_bytes(&record.transcript)
            .map_err(|error| crate::custody::pairing::transport::wire(&error))?;
        let invitation = resume_invitation(&live, &context, node)?;
        if record.grant.node_id != node.envelope().body.node_id {
            return Err(wrong());
        }
        stage.observe_full_native_head(current)?;
        verify_full_prepublication_authority(&record.grant, current, now)?;
        let own_key = self.public_keys(reference)?.0;
        let trust = FullResumeTrust::restore_local_stage(record, node, reference, &own_key, now)?;
        let keys = trust.key_owner(None)?;
        let position = stage.forward_resume_position()?;
        if role == PairingRole::Initiator
            && matches!(position, ramflux_storage::FullForwardResumePosition::AwaitingSource)
        {
            return Err(wrong());
        }
        let cancel = stage.io_cancel_handle();
        drop(stage);
        let signer = Arc::new(self.prepare_full_proof_signer_in(
            db,
            &request.operation_id,
            request.generation,
            &trust,
        )?);
        let frontend_generation = crate::custody::pairing::local_credential::load_reservation(
            &self.root,
            &self.account_id,
        )?
        .map(|entry| entry.frontend_generation);
        Ok(FullDataResume {
            live,
            invitation,
            context,
            trust,
            keys,
            signer,
            cancel,
            position,
            frontend_generation,
        })
    }
}
fn resume_invitation(
    live: &LiveRow,
    context: &TranscriptV3,
    node: &VerifiedNodeRecord,
) -> Result<Envelope<Invitation>, SdkError> {
    if live.descriptor.len() > 16_384 {
        return Err(wrong());
    }
    let invitation: Envelope<Invitation> = ramflux_protocol::parse_i_json(&live.descriptor)?;
    crate::custody::pairing::coordinator::verify_invitation(&invitation)?;
    let common = CommonV3::from_full_invitation(
        &invitation.body,
        context.initiator.common.master_public_key.clone(),
    )
    .map_err(|error| crate::custody::pairing::transport::wire(&error))?;
    if common != context.initiator.common
        || invitation.body.node_key != node.envelope().body.node_signing_public_key
        || invitation.body.request_id != live.operation_id
        || invitation.body.invitation_id != live.invitation_id
        || invitation.body.issuer_seq != live.issuer_seq
        || invitation.body.primary_ref != context.initiator.device_ref
    {
        return Err(wrong());
    }
    Ok(invitation)
}
