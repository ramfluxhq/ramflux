// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original-source-only Rebind drafts and independently observed durable head bindings.
use super::{FullLocalAction, FullLocalIoPort, FullLocalIoScope, FullLocalResult, SdkError, wrong};
use crate::custody::pairing::LocalPairingParticipant;
use ed25519_dalek::Signer as _;
use ramflux_crypto::custody::{VerifiedRecord, pairing::PairingRole};
use ramflux_protocol::custody::{DeviceRef, pairing::full_transfer::DataPacket};
pub(super) enum Action {
    Prepare(Box<VerifiedRecord>),
    Retain { current: Box<VerifiedRecord>, packet: Box<DataPacket> },
}
pub(super) enum Applied {
    Prepared(Box<Draft>),
    Retained,
}
pub(crate) struct Draft {
    scope: FullLocalIoScope,
    source: DeviceRef,
    packet: DataPacket,
}
impl Draft {
    pub(crate) fn sign(
        &self,
        participant: &LocalPairingParticipant,
    ) -> Result<DataPacket, SdkError> {
        let _local = self.scope.runtime.local_work()?;
        self.scope.live()?;
        if self.scope.role != PairingRole::Initiator
            || participant.account_id != self.scope.account
            || std::fs::canonicalize(&participant.root)? != self.scope.root
        {
            return Err(wrong());
        }
        let mut packet = self.packet.clone();
        let signature =
            participant.with_full_branch_vault(&self.source, &self.scope.source_key, |branch| {
                Ok(ramflux_protocol::encode_base64url(
                    branch
                        .signing
                        .signing_key
                        .sign(&packet.rebind_signing_bytes().map_err(|error| super::wire(&error))?)
                        .to_bytes(),
                ))
            })?;
        let DataPacket::Rebind { source_signature, .. } = &mut packet else {
            return Err(wrong());
        };
        *source_signature = signature;
        self.scope.live()?;
        Ok(packet)
    }
}
pub(super) fn apply(
    action: Action,
    scope: &FullLocalIoScope,
    stage: &mut ramflux_storage::FullTransferStage<'_>,
) -> Result<Applied, SdkError> {
    let now = crate::custody::network_now()?;
    match action {
        Action::Prepare(current) => {
            if scope.role != PairingRole::Initiator {
                return Err(wrong());
            }
            let packet = stage.prepare_full_rebind(&current, now)?;
            Ok(Applied::Prepared(Box::new(Draft {
                scope: scope.clone(),
                source: stage.resume_record()?.grant.source_ref,
                packet,
            })))
        }
        Action::Retain { current, packet } => {
            stage.retain_full_rebind(&current, &packet, now)?;
            Ok(Applied::Retained)
        }
    }
}
impl FullLocalIoPort {
    pub(crate) fn verify_rebind_hint(&self, packet: &DataPacket) -> Result<String, SdkError> {
        self.scope.live()?;
        let DataPacket::Rebind { manifest_hash, new_base_record_hash, source_signature } = packet
        else {
            return Err(wrong());
        };
        if self.scope.role != PairingRole::Responder
            || manifest_hash != &self.scope.base_manifest_hash
        {
            return Err(wrong());
        }
        ramflux_crypto::verify_canonical_signature(
            &packet.rebind_signing_bytes().map_err(|error| super::wire(&error))?,
            source_signature,
            &self.scope.source_key,
        )?;
        Ok(new_base_record_hash.clone())
    }
    pub(crate) async fn prepare_rebind(
        &mut self,
        current: VerifiedRecord,
    ) -> Result<Box<Draft>, SdkError> {
        let FullLocalResult::Rebind(Applied::Prepared(draft)) =
            self.request(FullLocalAction::Rebind(Action::Prepare(Box::new(current)))).await?
        else {
            return Err(wrong());
        };
        Ok(draft)
    }
    pub(crate) async fn retain_rebind(
        &mut self,
        current: VerifiedRecord,
        packet: DataPacket,
    ) -> Result<(), SdkError> {
        let FullLocalResult::Rebind(Applied::Retained) = self
            .request(FullLocalAction::Rebind(Action::Retain {
                current: Box::new(current),
                packet: Box::new(packet),
            }))
            .await?
        else {
            return Err(wrong());
        };
        Ok(())
    }
    pub(crate) async fn observe_prepublication_binding(
        &mut self,
        current: VerifiedRecord,
    ) -> Result<(String, String), SdkError> {
        let FullLocalResult::NativeObserved { current_hash, bound_hash } =
            self.request(FullLocalAction::ObservePrepublication(Box::new(current))).await?
        else {
            return Err(wrong());
        };
        Ok((current_hash, bound_hash))
    }
}
