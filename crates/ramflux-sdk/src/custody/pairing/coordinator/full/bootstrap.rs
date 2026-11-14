// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same actor's post-confirmation DATA-ONLY bootstrap; no candidate/publication signer.
use super::super::{
    PairingActor, PairingRole, RelayFrame, SasHold, SdkError, decode_base64url, encode_base64url,
};
use crate::custody::pairing::{FullBootstrap, FullBootstrapFrame, LocalPairingParticipant};
use ramflux_crypto::custody::pairing::{FullResumeKeyOwner, FullResumeTrust};
use ramflux_protocol::custody::pairing::full_transfer::{
    SourceManifest,
    lease::{BranchKeys, DataGrant},
};
use ramflux_storage::FullStageIoCancel;
use std::sync::Arc;

pub(super) struct BootstrapState {
    owner: Option<FullBootstrap>,
    awaiting_lease: bool,
    pub(super) source_manifest: Option<SourceManifest>,
    pub(super) idle_manifest: Option<SourceManifest>,
    pub(super) source_idle: bool,
    pub(super) trust: Option<FullResumeTrust>,
    pub(super) keys: Option<FullResumeKeyOwner>,
    pub(super) signer: Option<Arc<crate::custody::pairing::participant::FullProofSigner>>,
    pub(super) cancel: Option<FullStageIoCancel>,
    pub(super) epoch_job: Option<super::epoch::FullEpochJob>,
    pub(super) epoch_ready: Option<crate::custody::pairing::FullPacketEpoch>,
    pub(super) stream: Option<super::stream::FullStreamState>,
}
impl BootstrapState {
    pub(super) fn restored(
        trust: FullResumeTrust,
        keys: FullResumeKeyOwner,
        signer: Arc<crate::custody::pairing::participant::FullProofSigner>,
        cancel: FullStageIoCancel,
        position: ramflux_storage::FullForwardResumePosition,
    ) -> Self {
        let (source_manifest, idle_manifest, source_idle) = match position {
            ramflux_storage::FullForwardResumePosition::Streaming { manifest, last_verified } => {
                (Some(*manifest), last_verified.map(|manifest| *manifest), false)
            }
            ramflux_storage::FullForwardResumePosition::Idle { manifest } => {
                (Some((*manifest).clone()), Some(*manifest), true)
            }
            ramflux_storage::FullForwardResumePosition::AwaitingSource => (None, None, false),
        };
        Self {
            owner: None,
            awaiting_lease: false,
            source_manifest,
            idle_manifest,
            source_idle,
            trust: Some(trust),
            keys: Some(keys),
            signer: Some(signer),
            cancel: Some(cancel),
            epoch_job: None,
            epoch_ready: None,
            stream: None,
        }
    }
}
impl Drop for BootstrapState {
    fn drop(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        self.epoch_job.take();
    }
}
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
fn note_bootstrap_failure(phase: &'static str, error: &SdkError) {
    #[cfg(test)]
    eprintln!("test: full bootstrap {phase}: {error}");
    tracing::debug!(
        phase,
        error_code = PairingActor::background_error_code(error),
        "full data bootstrap refused"
    );
}
async fn local<T: std::marker::Send + 'static>(
    runtime: Arc<super::cancel::FullRuntimeCancel>,
    work: impl FnOnce() -> Result<T, SdkError> + std::marker::Send + 'static,
) -> Result<T, SdkError> {
    runtime
        .clone()
        .run_blocking(move || {
            let _local = runtime.local_work()?;
            let result = work()?;
            runtime.require_live()?;
            Ok(result)
        })
        .await
}
impl PairingActor {
    fn queue_full_bootstrap(&mut self, frame: FullBootstrapFrame) -> Result<(), SdkError> {
        self.with_ceremony_mut(|c| {
            c.outbound.push_back(RelayFrame::Channel {
                counter: frame.counter,
                ciphertext: encode_base64url(frame.ciphertext),
            });
            Ok(())
        })
    }
    async fn initialize_full_bootstrap(
        &mut self,
        participant: Arc<LocalPairingParticipant>,
    ) -> Result<(), SdkError> {
        let (role, channel, context, node, prepared) = self.with_ceremony_mut(|c| {
            if !c.local_confirmed || !c.peer_mac_ok || c.phase != "mutually_confirmed" {
                return Err(wrong());
            }
            let full = c.full.as_mut().ok_or_else(wrong)?;
            let context = full.transcript.clone().ok_or_else(wrong)?;
            let node = full.node.clone().ok_or(SdkError::PairingCode("UpdateRequired"))?;
            let SasHold::Established(channel) = std::mem::replace(&mut c.sas, SasHold::None) else {
                return Err(wrong());
            };
            Ok((c.role, *channel, context, node, full.prepared.take()))
        })?;
        let now = crate::custody::network_now()?;
        let writer = self.local_writer.clone();
        let (state, prepared, frames) = local(self.full_runtime.clone(), move || {
            let node_id = node.envelope().body.node_id.clone();
            let mut owner = FullBootstrap::new(role, channel, context.clone(), node, now)
                .inspect_err(|error| note_bootstrap_failure("confirmed channel", error))?;
            let mut frames = Vec::new();
            let mut source_manifest = None;
            if role == PairingRole::Initiator {
                let prepared = prepared.as_ref().ok_or_else(wrong)?;
                let (manifest, start) = owner
                    .prepare_source_start(prepared, now, |request| match &writer {
                        Some(writer) => writer.sign_manifest(&participant, request),
                        None => participant.sign_full_source_manifest(request),
                    })
                    .inspect_err(|error| note_bootstrap_failure("source manifest", error))?;
                let grant = DataGrant {
                    schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
                    version: 1,
                    transfer_id: start.transfer_id.clone(),
                    node_id,
                    source_ref: context.initiator.device_ref.clone(),
                    destination_ref: context.responder.device_ref.clone(),
                    branch_keys: BranchKeys {
                        source: context.initiator.branch_key.clone(),
                        destination: context.responder.branch_key.clone(),
                    },
                    opaque_commitment: start.opaque_commitment.clone(),
                    expires_at: now.checked_add(604_800).ok_or_else(wrong)?,
                };
                frames.extend(
                    owner
                        .begin_source(start, &grant, now, |request| match &writer {
                            Some(writer) => writer.sign_grant(&participant, request),
                            None => participant.sign_full_grant(request),
                        })
                        .inspect_err(|error| note_bootstrap_failure("source grant", error))?,
                );
                source_manifest = Some(manifest);
            }
            Ok((
                BootstrapState {
                    owner: Some(owner),
                    awaiting_lease: false,
                    source_manifest,
                    idle_manifest: None,
                    source_idle: false,
                    trust: None,
                    keys: None,
                    signer: None,
                    cancel: None,
                    epoch_job: None,
                    epoch_ready: None,
                    stream: None,
                },
                prepared,
                frames,
            ))
        })
        .await?;
        self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or_else(wrong)?;
            full.prepared = prepared;
            full.bootstrap = Some(state);
            Ok(())
        })?;
        for frame in frames {
            self.queue_full_bootstrap(frame)?;
        }
        Ok(())
    }
    /// Finish the encrypted local record and real journal link before fresh A3 traffic.
    async fn retain_bootstrap_trust(
        &mut self,
        trust: FullResumeTrust,
        participant: Arc<LocalPairingParticipant>,
    ) -> Result<(), SdkError> {
        let (operation, generation, base, prepared, manifest) = self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or_else(wrong)?;
            let state = full.bootstrap.as_ref().ok_or_else(wrong)?;
            Ok((
                c.operation_id.clone(),
                c.generation,
                full.sas_base.clone().ok_or_else(wrong)?,
                full.prepared.take(),
                state.source_manifest.clone(),
            ))
        })?;
        let owner = participant.clone();
        let work = move |db: &ramflux_storage::AccountDb| {
            let source = match (&prepared, &manifest) {
                (Some(prepared), Some(manifest)) => Some((prepared, manifest)),
                (None, None) => None,
                _ => return Err(wrong()),
            };
            let cancel = participant.retain_full_data_stage_in(
                db,
                (&operation, generation),
                &trust,
                &base,
                source,
            )?;
            let signer = Arc::new(
                participant.prepare_full_proof_signer_in(db, &operation, generation, &trust)?,
            );
            Ok((trust, cancel, signer))
        };
        let (trust, cancel, signer) = if let Some(writer) = &self.local_writer {
            writer.request(work).await?
        } else {
            local(self.full_runtime.clone(), move || {
                let slot = owner.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
                work(slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?)
            })
            .await?
        };
        self.full_runtime.register_stage(cancel.clone())?;
        self.with_ceremony_mut(|c| {
            c.expires_at = trust.lease_expires_at();
            let full = c.full.as_mut().ok_or_else(wrong)?;
            let keys = trust.key_owner(Some(full.hpke.take().ok_or_else(wrong)?))?;
            let state = full.bootstrap.as_mut().ok_or_else(wrong)?;
            state.owner = None;
            state.awaiting_lease = false;
            state.trust = Some(trust);
            state.keys = Some(keys);
            state.signer = Some(signer);
            state.cancel = Some(cancel);
            Ok(())
        })
    }
    pub(in crate::custody::pairing::coordinator) async fn advance_full_bootstrap(
        &mut self,
    ) -> Result<(), SdkError> {
        self.full_runtime.require_live()?;
        let participant =
            self.participant.clone().ok_or(SdkError::PairingCode("UpdateRequired"))?;
        let initialize = self.with_ceremony(|c| {
            Ok(c.phase == "mutually_confirmed"
                && c.full.as_ref().is_some_and(|full| full.bootstrap.is_none()))
        })?;
        if initialize {
            self.initialize_full_bootstrap(participant.clone())
                .await
                .inspect_err(|error| note_bootstrap_failure("local initialization", error))?;
        }
        while let Some((counter, ciphertext)) =
            self.ceremony.as_mut().and_then(|c| c.channels.pop_front())
        {
            let frame = FullBootstrapFrame {
                counter,
                ciphertext: decode_base64url(&ciphertext).map_err(|_| wrong())?,
            };
            let (role, mut owner, awaiting) = self.with_ceremony_mut(|c| {
                let state =
                    c.full.as_mut().and_then(|full| full.bootstrap.as_mut()).ok_or_else(wrong)?;
                Ok((c.role, state.owner.take().ok_or_else(wrong)?, state.awaiting_lease))
            })?;
            let now = crate::custody::network_now()?;
            if role == PairingRole::Responder && awaiting {
                let (_, trust) = owner.accept_destination_lease(&frame, now)?;
                self.retain_bootstrap_trust(trust, participant.clone())
                    .await
                    .inspect_err(|error| note_bootstrap_failure("durable trust", error))?;
                continue;
            }
            let signer = participant.clone();
            let writer = self.local_writer.clone();
            let (mut owner, reply) = local(self.full_runtime.clone(), move || {
                let reply = owner
                    .receive(&frame, now, |request| match &writer {
                        Some(writer) => writer.sign_grant(&signer, request),
                        None => signer.sign_full_grant(request),
                    })
                    .inspect_err(|error| note_bootstrap_failure("peer control", error))?;
                Ok((owner, reply))
            })
            .await?;
            if role == PairingRole::Initiator {
                let native = self.native.clone().ok_or_else(wrong)?;
                let (frame, _, trust) = owner
                    .issue_source_lease(native.as_ref(), now)
                    .await
                    .inspect_err(|error| note_bootstrap_failure("native lease", error))?;
                self.retain_bootstrap_trust(trust, participant.clone())
                    .await
                    .inspect_err(|error| note_bootstrap_failure("durable trust", error))?;
                self.queue_full_bootstrap(frame)?;
            } else {
                self.with_ceremony_mut(|c| {
                    let state = c
                        .full
                        .as_mut()
                        .and_then(|full| full.bootstrap.as_mut())
                        .ok_or_else(wrong)?;
                    state.awaiting_lease = reply.is_some();
                    state.owner = Some(owner);
                    Ok(())
                })?;
                if let Some(reply) = reply {
                    self.queue_full_bootstrap(reply)?;
                }
            }
        }
        Ok(())
    }
}
