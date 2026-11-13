// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned prepublication data exchange with ordinary-owner local requests.
//! Durable duplex opens controls; linked reverse and publication remain separate gates.
use super::cancel::FullRuntimeCancel;
use crate::{
    SdkError,
    custody::pairing::{
        FullLocalIoPort, FullLocalIoService, FullPacketEpoch, FullPairingTransport,
        FullTransferLocalIo, LocalPairingParticipant, PairingActor,
    },
};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::SourceManifest;
use std::sync::Arc;
use tokio::task::JoinHandle;

mod work;

pub(super) struct FullStreamFinished {
    pub(super) packet: FullPacketEpoch,
    pub(super) manifest: SourceManifest,
    pub(super) receiver: Option<Box<ramflux_storage::FullReceiverBaseCopy>>,
}
pub(super) struct FullStreamState {
    service: Option<FullLocalIoService>,
    pub(super) job: Option<FullStreamJob>,
    pub(super) complete: Option<SourceManifest>,
    failure: Option<&'static str>,
    pub(super) receiver: Option<Box<ramflux_storage::FullReceiverBaseCopy>>,
    pub(super) progress: Arc<std::sync::Mutex<super::status::FullProgress>>,
}
pub(in crate::custody::pairing::coordinator) struct FullStreamJob(
    Option<JoinHandle<Result<FullStreamFinished, SdkError>>>,
);
impl Drop for FullStreamJob {
    fn drop(&mut self) {
        if let Some(job) = &self.0 {
            job.abort();
        }
    }
}
impl FullStreamJob {
    pub(in crate::custody::pairing::coordinator) async fn abort_and_drain(mut self) {
        if let Some(job) = self.0.take() {
            job.abort();
            let _ = job.await;
        }
    }
}
impl FullStreamState {
    pub(super) async fn advance(&mut self) -> Result<Option<FullPacketEpoch>, SdkError> {
        if let Some(code) = self.failure {
            return Err(SdkError::PairingCode(code));
        }
        if self.complete.is_some() {
            return Ok(None);
        }
        if self.job.as_ref().and_then(|job| job.0.as_ref()).is_some_and(JoinHandle::is_finished) {
            let mut job = self.job.take().ok_or_else(wrong)?;
            let outcome = job.0.take().ok_or_else(wrong)?.await;
            self.service.take();
            let result = outcome
                .map_err(|_| SdkError::PairingCode("Retired"))
                .and_then(std::convert::identity);
            let FullStreamFinished { packet, manifest, receiver } = match result {
                Ok(finished) => finished,
                Err(error) => {
                    self.failure = Some(PairingActor::background_error_code(&error));
                    return Err(error);
                }
            };
            self.receiver = receiver;
            self.complete = Some(manifest);
            return Ok(Some(packet));
        }
        Ok(None)
    }
}
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
struct FullStreamWork {
    role: PairingRole,
    forward_started: bool,
    pending_rebind: Option<ramflux_protocol::custody::pairing::full_transfer::DataPacket>,
    packet: FullPacketEpoch,
    progress: Arc<std::sync::Mutex<super::status::FullProgress>>,
    io: FullLocalIoPort,
    participant: Arc<LocalPairingParticipant>,
    runtime: Arc<FullRuntimeCancel>,
    relay: Arc<dyn FullPairingTransport>,
    origin: String,
    anchor: String,
    linked_target: bool,
    new_target: Option<(String, ramflux_protocol::custody::DeviceRef)>,
}
impl PairingActor {
    /// New B has no ordinary account session yet. Its coordinator owns the actual
    /// staged writer and services one short local request between relay polls.
    pub(in crate::custody::pairing::coordinator) fn service_staged_full_target(
        &mut self,
    ) -> Result<(), SdkError> {
        if self.local_writer.is_some() {
            return Ok(());
        }
        if !self.ceremony.as_ref().is_some_and(|c| {
            c.role == PairingRole::Responder
                && c.full.as_ref().is_some_and(|full| full.common.recipient_mode == "new")
        }) {
            return Ok(());
        }
        let participant = self.participant.clone().ok_or_else(wrong)?;
        let slot = participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        if let Some(db) = slot.as_ref() {
            self.service_full_transfer(db)?;
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn full_base_stream_started_for_test(&self) -> bool {
        self.ceremony
            .as_ref()
            .and_then(|c| c.full.as_ref())
            .and_then(|full| full.bootstrap.as_ref())
            .is_some_and(|state| state.stream.is_some())
    }
    #[cfg(test)]
    pub(crate) async fn settle_full_local_jobs_for_test(&self) {
        self.full_runtime.settle_local_jobs().await;
    }
    /// Service at most one local request against the ordinary owner's actual writer.
    /// Call between async operations; no DB or stage key enters the background job.
    /// The new-recipient driver applies base, neutral reverse and signed catch-up deltas.
    /// Original endpoints commit semantic DV before the local durable duplex control gate.
    /// # Errors
    /// Refuses retired/foreign writers, unsupported linked targets or failed local I/O.
    pub fn service_full_transfer(
        &mut self,
        db: &ramflux_storage::AccountDb,
    ) -> Result<bool, SdkError> {
        self.full_runtime.require_live()?;
        if self
            .ceremony
            .as_ref()
            .and_then(|c| c.full.as_ref())
            .is_some_and(|full| full.pending_ready.is_some())
        {
            self.finish_destination_ready(db)?;
            return Ok(true);
        }
        if self
            .ceremony
            .as_ref()
            .and_then(|c| c.full.as_ref())
            .is_some_and(|full| full.pending_affirmation.is_some())
        {
            self.finish_full_source_affirmation(db)?;
            return Ok(true);
        }
        let Some(full) = self.ceremony.as_ref().and_then(|c| c.full.as_ref()) else {
            return Ok(false);
        };
        let Some(state) = &full.bootstrap else { return Ok(false) };
        if state.stream.is_none() && state.epoch_ready.is_some() {
            let io = self.full_transfer_local_io(db)?;
            self.start_full_base_stream(io)?;
        }
        let stream = self
            .ceremony
            .as_mut()
            .and_then(|c| c.full.as_mut())
            .and_then(|full| full.bootstrap.as_mut())
            .and_then(|state| state.stream.as_mut());
        let Some(request) = stream
            .and_then(|stream| stream.service.as_mut())
            .and_then(FullLocalIoService::try_receive)
        else {
            return Ok(false);
        };
        request.apply(db)?;
        Ok(true)
    }
    fn start_full_base_stream(&mut self, io: FullTransferLocalIo) -> Result<(), SdkError> {
        let participant = self.participant.clone().ok_or_else(wrong)?;
        let relay = self.transport.full_transport().ok_or_else(wrong)?;
        let c = self.ceremony.as_mut().ok_or_else(wrong)?;
        let full = c.full.as_mut().ok_or_else(wrong)?;
        let anchor = full.common.account_anchor.clone();
        let linked_target = full.common.recipient_mode == "existing";
        let state = full.bootstrap.as_mut().ok_or_else(wrong)?;
        let role = c.role;
        let manifest = state.source_manifest.clone();
        if role == PairingRole::Initiator && manifest.is_none() {
            return Err(wrong());
        }
        let new_target = if role == PairingRole::Responder && !linked_target {
            let record = state.trust.as_ref().ok_or_else(wrong)?.local_stage_record()?;
            Some((c.operation_id.clone(), record.grant.destination_ref))
        } else {
            None
        };
        let packet = state.epoch_ready.take().ok_or_else(wrong)?;
        let (io, service) = io.into_port();
        let runtime = self.full_runtime.clone();
        let progress = Arc::new(std::sync::Mutex::new(
            manifest.as_ref().map_or(Ok(super::status::FullProgress::default()), |manifest| {
                super::status::FullProgress::observed(manifest, 0)
            })?,
        ));
        let work = FullStreamWork {
            role,
            forward_started: false,
            pending_rebind: None,
            progress: progress.clone(),
            packet,
            io,
            participant,
            runtime: runtime.clone(),
            relay,
            origin: c.origin.clone(),
            anchor,
            new_target,
            linked_target,
        };
        let job = tokio::spawn(async move {
            match role {
                PairingRole::Initiator => Box::pin(work.source(manifest.ok_or_else(wrong)?)).await,
                PairingRole::Responder => Box::pin(work.destination()).await,
            }
        });
        let _ = runtime.register_job(job.abort_handle());
        state.stream = Some(FullStreamState {
            progress,
            service: Some(service),
            job: Some(FullStreamJob(Some(job))),
            complete: None,
            receiver: None,
            failure: None,
        });
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn hold_receiver_application_for_test(
        &mut self,
        db: &ramflux_storage::AccountDb,
    ) -> Result<Option<crate::custody::pairing::FullLocalIoLoan>, SdkError> {
        if !self.full_base_stream_started_for_test() {
            self.service_full_transfer(db)?;
        }
        let Some(loan) = self
            .ceremony
            .as_mut()
            .and_then(|c| c.full.as_mut())
            .and_then(|full| full.bootstrap.as_mut())
            .and_then(|state| state.stream.as_mut())
            .and_then(|stream| stream.service.as_mut())
            .and_then(FullLocalIoService::try_receive)
        else {
            return Ok(None);
        };
        if loan.is_receiver_application() {
            Ok(Some(loan))
        } else {
            loan.apply(db)?;
            Ok(None)
        }
    }
    #[cfg(test)]
    pub(crate) fn full_receiver_base_projected_for_test(&self) -> bool {
        self.ceremony
            .as_ref()
            .and_then(|c| c.full.as_ref())
            .and_then(|full| full.bootstrap.as_ref())
            .and_then(|state| state.stream.as_ref())
            .and_then(|stream| stream.receiver.as_ref())
            .is_some_and(|copy| copy.projected_input().is_some() && copy.union_encoding().is_some())
    }
    #[cfg(test)]
    pub(crate) fn full_base_disk_complete_for_test(&self) -> bool {
        self.ceremony
            .as_ref()
            .and_then(|c| c.full.as_ref())
            .and_then(|full| full.bootstrap.as_ref())
            .and_then(|state| state.stream.as_ref())
            .is_some_and(|stream| stream.complete.is_some())
    }
}
