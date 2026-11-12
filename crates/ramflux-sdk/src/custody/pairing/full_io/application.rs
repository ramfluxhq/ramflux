// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Narrow original-branch data receipt request, never an arbitrary or primary signer.
use super::{FullLocalIoScope, SdkError, wrong};
use crate::custody::pairing::LocalPairingParticipant;
use ramflux_protocol::custody::pairing::full_transfer::DataPacket;
use ramflux_storage::{FullReceiverApplication, FullReceiverBaseCopy, FullTransferStage};

pub(super) enum Action {
    Prepare(Box<FullReceiverBaseCopy>),
    Record {
        copy: Box<FullReceiverBaseCopy>,
        draft: Box<FullApplicationDraft>,
        packet: Box<DataPacket>,
    },
    Source(Box<DataPacket>),
}
pub(super) enum Applied {
    Prepared { copy: Box<FullReceiverBaseCopy>, draft: Box<FullApplicationDraft> },
    Receiver(Box<FullReceiverBaseCopy>),
    Source,
}
/// Opaque proof that the original receiver committed a fully materialized private input.
/// No Debug/serde/clone and no API to request signatures over caller-provided bytes.
pub struct FullApplicationDraft {
    proof: FullReceiverApplication,
    scope: FullLocalIoScope,
}
impl FullApplicationDraft {
    pub(crate) fn sign_with(
        &self,
        participant: &LocalPairingParticipant,
        sign: impl FnOnce(&DataPacket, &str) -> Result<String, SdkError>,
    ) -> Result<DataPacket, SdkError> {
        let _local = self.scope.runtime.local_work()?;
        self.scope.live()?;
        if self.scope.role != ramflux_crypto::custody::pairing::PairingRole::Responder
            || self.scope.destination_key != self.proof.expected_branch_key()
            || participant.account_id != self.scope.account
            || std::fs::canonicalize(&participant.root)? != self.scope.root
            || crate::custody::network_now()? >= self.proof.expires_at()
        {
            return Err(wrong());
        }
        let signature = sign(self.proof.packet(), self.proof.expected_branch_key())?;
        self.scope.live()?;
        Ok(self.proof.signed_packet(signature)?)
    }
}
pub(super) fn apply(
    action: Action,
    scope: &FullLocalIoScope,
    stage: &mut FullTransferStage<'_>,
) -> Result<Applied, SdkError> {
    let now = crate::custody::network_now()?;
    match action {
        Action::Prepare(mut copy) => {
            if scope.role != ramflux_crypto::custody::pairing::PairingRole::Responder {
                return Err(wrong());
            }
            let proof = copy.commit_application(stage, now)?;
            Ok(Applied::Prepared {
                copy,
                draft: Box::new(FullApplicationDraft { proof, scope: scope.clone() }),
            })
        }
        Action::Record { copy, draft, packet } => {
            draft.scope.live()?;
            if scope.role != ramflux_crypto::custody::pairing::PairingRole::Responder
                || draft.scope.root != scope.root
                || draft.scope.operation != scope.operation
                || draft.scope.generation != scope.generation
                || draft.scope.digest != scope.digest
            {
                return Err(wrong());
            }
            copy.record_data_verified(stage, &draft.proof, &packet, now)?;
            Ok(Applied::Receiver(copy))
        }
        Action::Source(packet) => {
            if scope.role != ramflux_crypto::custody::pairing::PairingRole::Initiator {
                return Err(wrong());
            }
            stage.record_source_data_verified(&packet, now)?;
            Ok(Applied::Source)
        }
    }
}
