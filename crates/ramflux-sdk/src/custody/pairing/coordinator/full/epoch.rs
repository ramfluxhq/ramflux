// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned A3/control/Ready job: no database, writer or authority loan crosses a relay wait.
use super::cancel::FullRuntimeCancel;
use crate::custody::pairing::FullPairingTransport;
use crate::{
    SdkError,
    custody::pairing::{FullPacketEpoch, participant::FullProofSigner},
};
use ramflux_crypto::custody::pairing::{FullResumeKeyOwner, FullResumeTrust, PairingRole};
use std::sync::Arc;
use tokio::{
    task::JoinHandle,
    time::{Duration, timeout},
};

struct FullEpochFinished {
    trust: FullResumeTrust,
    keys: FullResumeKeyOwner,
    packet: Result<FullPacketEpoch, SdkError>,
}
pub(super) struct FullEpochJob(Option<JoinHandle<FullEpochFinished>>);
impl Drop for FullEpochJob {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
impl FullEpochJob {
    fn finished(&self) -> bool {
        self.0.as_ref().is_some_and(JoinHandle::is_finished)
    }
    async fn finish(mut self) -> Result<FullEpochFinished, SdkError> {
        self.0
            .take()
            .ok_or(SdkError::PairingCode("WrongContext"))?
            .await
            .map_err(|_| SdkError::PairingCode("Retired"))
    }
}
struct FullEpochWork {
    signer: FullProofSigner,
    cancelled: ramflux_storage::FullStageIoCancel,
    trust: FullResumeTrust,
    keys: FullResumeKeyOwner,
}
fn start(
    relay: Arc<dyn FullPairingTransport>,
    origin: String,
    stop: Arc<FullRuntimeCancel>,
    work: FullEpochWork,
) -> Result<FullEpochJob, SdkError> {
    let FullEpochWork { signer, cancelled, trust, mut keys } = work;
    stop.require_live()?;
    let owner = stop.clone();
    let task = tokio::spawn(async move {
        let packet = timeout(Duration::from_secs(10), async {
            stop.require_live()?;
            let signing_stop = stop.clone();
            let signing_cancel = cancelled.clone();
            let epoch = relay
                .negotiate_full_epoch(&origin, &trust, &mut keys, move |request| {
                    signing_stop.require_live()?;
                    if signing_cancel.is_cancelled() {
                        return Err(SdkError::PairingCode("Retired"));
                    }
                    let signature = signer.sign(request)?;
                    if signing_cancel.is_cancelled() {
                        return Err(SdkError::PairingCode("Retired"));
                    }
                    signing_stop.require_live()?;
                    Ok(signature)
                })
                .await?;
            stop.require_live()?;
            if cancelled.is_cancelled() {
                return Err(SdkError::PairingCode("Retired"));
            }
            let role = trust.local_stage_record()?.role;
            let packet = match role {
                PairingRole::Initiator => {
                    let (mut packet, control) = epoch.source_control()?;
                    packet.send_control(relay.as_ref(), &origin, control).await?;
                    loop {
                        stop.require_live()?;
                        if cancelled.is_cancelled() {
                            return Err(SdkError::PairingCode("Retired"));
                        }
                        if let Some(ready) = packet.poll(relay.as_ref(), &origin).await? {
                            stop.require_live()?;
                            if cancelled.is_cancelled() {
                                return Err(SdkError::PairingCode("Retired"));
                            }
                            packet.accept_ready(&ready)?;
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    packet
                }
                PairingRole::Responder => {
                    let control = loop {
                        stop.require_live()?;
                        if cancelled.is_cancelled() {
                            return Err(SdkError::PairingCode("Retired"));
                        }
                        if let Some(control) =
                            epoch.poll_destination_control(relay.as_ref(), &origin).await?
                        {
                            break control;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    };
                    stop.require_live()?;
                    let mut packet = epoch.destination_control(&control)?;
                    let ready = packet.seal_ready()?;
                    packet.send(relay.as_ref(), &origin, ready).await?;
                    packet
                }
            };
            stop.require_live()?;
            // Keep the key owner so any reconnect consumes a fresh half, never the SAS half.
            Ok(packet)
        })
        .await
        .unwrap_or_else(|_| Err(SdkError::PairingCode("ResumeRequired")));
        FullEpochFinished { trust, keys, packet }
    });
    owner.register_job(task.abort_handle())?;
    Ok(FullEpochJob(Some(task)))
}
impl crate::custody::pairing::PairingActor {
    #[cfg(test)]
    pub(crate) fn full_epoch_ready_for_test(&self) -> bool {
        self.ceremony
            .as_ref()
            .and_then(|c| c.full.as_ref())
            .and_then(|full| full.bootstrap.as_ref())
            .is_some_and(|state| state.epoch_ready.is_some())
    }
    /// True once the data lease owner has replaced the short SAS relay pump.
    pub(in crate::custody::pairing::coordinator) async fn advance_full_epoch(
        &mut self,
    ) -> Result<bool, SdkError> {
        self.full_runtime.require_live()?;
        let Some(c) = &mut self.ceremony else { return Ok(false) };
        if !c.outbound.is_empty() {
            return Ok(false);
        }
        let Some(state) = c.full.as_mut().and_then(|full| full.bootstrap.as_mut()) else {
            return Ok(false);
        };
        if state.epoch_ready.is_some() {
            return Ok(true);
        }
        if state.epoch_job.as_ref().is_some_and(FullEpochJob::finished) {
            let job = state.epoch_job.take().ok_or(SdkError::PairingCode("WrongContext"))?;
            let finished = job.finish().await?;
            state.trust = Some(finished.trust);
            state.keys = Some(finished.keys);
            state.epoch_ready = Some(finished.packet?);
            self.full_runtime.require_live()?;
            return Ok(true);
        }
        if state.epoch_job.is_some() {
            return Ok(true);
        }
        if state.trust.is_none() {
            return Ok(false);
        }
        let relay =
            self.transport.full_transport().ok_or(SdkError::PairingCode("UpdateRequired"))?;
        let participant =
            self.participant.clone().ok_or(SdkError::PairingCode("UpdateRequired"))?;
        let trust = state.trust.take().ok_or(SdkError::PairingCode("WrongContext"))?;
        let keys = state.keys.take().ok_or(SdkError::PairingCode("WrongContext"))?;
        let operation = c.operation_id.clone();
        let generation = c.generation;
        let cancelled = state.cancel.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let (trust, keys, signer) = tokio::task::spawn_blocking(move || {
            let signer = participant.prepare_full_proof_signer(&operation, generation, &trust);
            (trust, keys, signer)
        })
        .await
        .map_err(|_| SdkError::PairingCode("VaultUnavailable"))?;
        state.trust = Some(trust);
        state.keys = Some(keys);
        let signer = signer?;
        let trust = state.trust.take().ok_or(SdkError::PairingCode("WrongContext"))?;
        let keys = state.keys.take().ok_or(SdkError::PairingCode("WrongContext"))?;
        state.epoch_job = Some(start(
            relay,
            c.origin.clone(),
            self.full_runtime.clone(),
            FullEpochWork { signer, cancelled, trust, keys },
        )?);
        Ok(true)
    }
}
