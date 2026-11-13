// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded candidate delivery over the already durable duplex epoch.
use super::{PairingActor, SdkError, candidate_assembly::CandidateAssembly};
use crate::custody::pairing::FullPacketEpoch;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{
        DeviceSet, Envelope, Publication, object_hash,
        pairing::{
            PairingWire,
            full_transfer::{DataPacket, FullControlPayload, SecretBase64},
        },
    },
};
use std::collections::VecDeque;
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
pub(super) struct FullManagement {
    packet: FullPacketEpoch,
    candidate: CandidateAssembly,
    outbound: VecDeque<FullControlPayload>,
    role: PairingRole,
    pub(super) source_ready_sent: bool,
}
enum Input {
    Candidate(Box<Envelope<DeviceSet>>),
    Ready(FullControlPayload),
    Completion(FullControlPayload),
}
impl FullManagement {
    pub(super) fn ready_for_tail(&self) -> bool {
        self.outbound.is_empty()
    }
    pub(super) fn into_tail_packet(self) -> Result<FullPacketEpoch, SdkError> {
        if !self.outbound.is_empty() {
            return Err(wrong());
        }
        Ok(self.packet)
    }

    pub(super) fn queue_local_control(
        &mut self,
        payload: FullControlPayload,
    ) -> Result<(), SdkError> {
        payload.require_sender(self.role.as_str()).map_err(|_| wrong())?;
        if self.outbound.len() >= 66 {
            return Err(SdkError::PairingCode("Busy"));
        }
        self.outbound.push_back(payload);
        Ok(())
    }
    fn queue_candidate(
        &mut self,
        invitation: &str,
        transfer: &str,
        publication: &Publication,
    ) -> Result<(), SdkError> {
        if self.role != PairingRole::Responder || !self.outbound.is_empty() {
            return Err(wrong());
        }
        if publication.compacted_ids.is_some() {
            return Err(SdkError::PairingCode("TransferCapacity"));
        }
        let bytes = canonical_json_bytes(&publication.record)?;
        if bytes.is_empty() || bytes.len() > 524_288 {
            return Err(SdkError::PairingCode("TransferCapacity"));
        }
        self.outbound.push_back(FullControlPayload::CandidateReady {
            transfer_id: transfer.into(),
            record_hash: object_hash(&publication.record)?,
            compacted_ids_hash: None,
        });
        let count = u64::try_from(bytes.len().div_ceil(8192)).map_err(|_| wrong())?;
        let total_bytes = u64::try_from(bytes.len()).map_err(|_| wrong())?;
        for (index, part) in bytes.chunks(8192).enumerate() {
            let payload = FullControlPayload::ArtifactChunk {
                object_kind: "candidate".into(),
                object_id: invitation.into(),
                index: u64::try_from(index).map_err(|_| wrong())?,
                count,
                total_bytes,
                bytes: SecretBase64::from_bytes(part),
            };
            payload.validate().map_err(|_| wrong())?;
            self.outbound.push_back(payload);
        }
        Ok(())
    }
    async fn step(
        &mut self,
        relay: &dyn crate::custody::pairing::FullPairingTransport,
        origin: &str,
    ) -> Result<Option<Input>, SdkError> {
        if let Some(payload) = self.outbound.pop_front() {
            let sends_ready = matches!(&payload, FullControlPayload::TransferReadyFull { .. });
            let encrypted = self.packet.seal_packet(&DataPacket::Control { payload })?;
            self.packet.send(relay, origin, encrypted).await?;
            if sends_ready {
                self.source_ready_sent = true;
            }
            return Ok(None);
        }
        let Some(encrypted) = self.packet.poll(relay, origin).await? else {
            return Ok(None);
        };
        let Some(packet) = self.packet.open_packet(&encrypted)? else {
            return Ok(None);
        };
        let DataPacket::Control { payload } = packet else {
            return Err(wrong());
        };
        let sender = if self.role == PairingRole::Initiator { "responder" } else { "initiator" };
        payload.require_sender(sender).map_err(|_| wrong())?;
        match self.role {
            PairingRole::Initiator if matches!(payload, FullControlPayload::Installed { .. }) => {
                Ok(Some(Input::Completion(payload)))
            }
            PairingRole::Responder
                if matches!(
                    payload,
                    FullControlPayload::Published { .. } | FullControlPayload::Completed { .. }
                ) =>
            {
                Ok(Some(Input::Completion(payload)))
            }
            PairingRole::Initiator => self
                .candidate
                .push(&payload)
                .map(|record| record.map(|record| Input::Candidate(Box::new(record)))),
            PairingRole::Responder
                if matches!(payload, FullControlPayload::TransferReadyFull { .. }) =>
            {
                Ok(Some(Input::Ready(payload)))
            }
            PairingRole::Responder => Err(wrong()),
        }
    }
}
impl PairingActor {
    #[cfg(test)]
    pub(crate) fn first_forward_position_for_test(
        &self,
    ) -> Option<crate::custody::pairing::full_epoch::FirstForwardPosition> {
        let full = self.ceremony.as_ref()?.full.as_ref()?;
        if let Some(management) = &full.management {
            return management.packet.first_position_for_test();
        }
        full.bootstrap.as_ref()?.epoch_ready.as_ref()?.first_position_for_test()
    }
    pub(in crate::custody::pairing::coordinator) fn candidate_control_ready(&self) -> bool {
        self.ceremony.as_ref().is_some_and(|c| {
            c.full.as_ref().is_some_and(|full| {
                full.management.as_ref().is_some_and(|management| !management.outbound.is_empty())
            }) || (!super::super::terminal(&c.phase)
                && c.full.as_ref().is_some_and(|full| {
                    full.bootstrap
                        .as_ref()
                        .and_then(|state| state.stream.as_ref())
                        .is_some_and(|stream| stream.complete.is_some())
                        && (c.role == PairingRole::Initiator || full.candidate.is_some())
                }))
        })
    }
    /// Advance one encrypted candidate-control packet after durable forward and reverse DV.
    /// No account writer, stage, key or authority crosses this relay wait. Public candidate
    /// inspection on A grants no approval and independently queries its current native head.
    /// # Errors
    /// Refuses incomplete data, another peer/phase, malformed candidate, expiry or stopped scope.
    pub fn poll_full_management_control(
        &mut self,
    ) -> impl std::future::Future<Output = Result<bool, SdkError>> + Send + '_ {
        Box::pin(self.poll_full_management_owned())
    }
    async fn poll_full_management_owned(&mut self) -> Result<bool, SdkError> {
        self.require_open()?;
        self.full_runtime.require_live()?;
        if self.ceremony.as_ref().is_some_and(|c| c.role == PairingRole::Initiator) {
            let participant = self.participant.as_ref().ok_or_else(wrong)?;
            if participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?.is_some() {
                return Err(SdkError::PairingCode("Busy"));
            }
        }
        self.start_full_candidate_control()?;
        let relay = self.transport.full_transport().ok_or_else(wrong)?;
        let (origin, mut management) = self.with_ceremony_mut(|c| {
            let management =
                c.full.as_mut().and_then(|full| full.management.take()).ok_or_else(wrong)?;
            Ok((c.origin.clone(), management))
        })?;
        let result = management.step(relay.as_ref(), &origin).await;
        self.full_runtime.require_live()?;
        let candidate = result?; // A transport/codec failure drops and wipes this epoch.
        self.with_ceremony_mut(|c| {
            c.full.as_mut().ok_or_else(wrong)?.management = Some(management);
            Ok(())
        })?;
        match candidate {
            Some(Input::Candidate(record)) => {
                self.inspect_full_source_candidate(Publication {
                    record: *record,
                    compacted_ids: None,
                })
                .await?;
                if self.full_source_approval_scope().is_ok() {
                    self.queue_original_source_approval().await?;
                }
                Ok(true)
            }
            Some(Input::Ready(payload)) => {
                self.queue_destination_ready(payload)?;
                Ok(true)
            }
            Some(Input::Completion(payload)) => {
                Box::pin(self.accept_full_completion_control(payload)).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
    pub(super) fn queue_source_ready(&mut self) -> Result<(), SdkError> {
        self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or_else(wrong)?;
            let Some(management) = &mut full.management else {
                return Ok(());
            };
            if c.role != PairingRole::Initiator || management.outbound.len() >= 66 {
                return Err(wrong());
            }
            let approved = full.affirmed.as_ref().ok_or_else(wrong)?;
            let payload = FullControlPayload::TransferReadyFull {
                transfer_id: c.invitation.transfer_id.clone().ok_or_else(wrong)?,
                record_hash: object_hash(&approved.observation.candidate.record)?,
                compacted_ids_hash: None,
                preservation: Box::new(approved.preservation.clone()),
            };
            payload.validate().map_err(|_| wrong())?;
            management.outbound.push_back(payload);
            Ok(())
        })
    }
    fn queue_destination_ready(&mut self, payload: FullControlPayload) -> Result<(), SdkError> {
        let FullControlPayload::TransferReadyFull {
            transfer_id,
            record_hash,
            compacted_ids_hash,
            preservation,
        } = payload
        else {
            return Err(wrong());
        };
        self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or_else(wrong)?;
            let candidate = full.candidate.as_ref().ok_or_else(wrong)?;
            if c.role != PairingRole::Responder
                || c.phase != "prepared"
                || full.pending_ready.is_some()
                || full.ready_retained
                || c.invitation.transfer_id.as_deref() != Some(transfer_id.as_str())
                || object_hash(&candidate.publication().record)? != record_hash
                || compacted_ids_hash.is_some()
            {
                return Err(wrong());
            }
            full.pending_ready =
                Some(Box::new(crate::custody::pairing::participant::FullDestinationReady {
                    operation: c.operation_id.clone(),
                    generation: c.generation,
                    th: c.displayed_th.ok_or_else(wrong)?,
                    previous: candidate.previous().clone(),
                    candidate: candidate.publication().record.clone(),
                    preservation: *preservation,
                }));
            Ok(())
        })
    }
    pub(super) fn finish_destination_ready(
        &mut self,
        db: &ramflux_storage::AccountDb,
    ) -> Result<(), SdkError> {
        let ready = self.with_ceremony_mut(|c| {
            c.full.as_mut().and_then(|full| full.pending_ready.take()).ok_or_else(wrong)
        })?;
        let participant = self.participant.clone().ok_or_else(wrong)?;
        let runtime = self.full_runtime.clone();
        let _local = runtime.local_work()?;
        participant.retain_destination_preservation_in(db, &ready)?;
        runtime.require_live()?;
        self.with_ceremony_mut(|c| {
            super::super::check_generation(c, &ready.operation, ready.generation)?;
            c.full.as_mut().ok_or_else(wrong)?.ready_retained = true;
            Ok(())
        })
    }
    fn start_full_candidate_control(&mut self) -> Result<(), SdkError> {
        self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or_else(wrong)?;
            if full.management.is_some() {
                return Ok(());
            }
            let state = full.bootstrap.as_mut().ok_or_else(wrong)?;
            if state.stream.as_ref().is_none_or(|stream| stream.complete.is_none()) {
                return Err(wrong());
            }
            if c.role == PairingRole::Responder && full.candidate.is_none() {
                return Err(wrong());
            }
            let packet = state.epoch_ready.take().ok_or_else(wrong)?;
            let invitation = c.invitation.invitation_id.clone();
            let transfer = c.invitation.transfer_id.clone().ok_or_else(wrong)?;
            let mut management = Box::new(FullManagement {
                packet,
                candidate: CandidateAssembly::new(invitation.clone(), transfer.clone()),
                outbound: VecDeque::new(),
                role: c.role,
                source_ready_sent: false,
            });
            if let Some(candidate) = &full.candidate {
                management.queue_candidate(&invitation, &transfer, candidate.publication())?;
            }
            full.management = Some(management);
            Ok(())
        })
    }
}
