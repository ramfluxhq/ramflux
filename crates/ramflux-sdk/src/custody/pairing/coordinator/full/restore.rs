// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reconnect reconstructs data-only trust; every human/publication approval stays absent.
use super::{FullCeremony, PairingActor, PairingRole, SdkError, bootstrap::BootstrapState};
use crate::custody::pairing::coordinator::CeremonyOpen;
use ramflux_protocol::custody::pairing::local_dto::{LocalResult, StatusRequest};
use zeroize::Zeroize as _;
impl PairingActor {
    /// Reopen one exact locally unlocked full-data stage with fresh two-branch proof/HPKE.
    /// This does not restore SAS confirmations, management approval, tokens or counters.
    /// # Errors
    /// Refuses foreign/stale stage/node/branch, terminal data, expiry or possible publication.
    pub async fn resume_full_data(
        &mut self,
        request: &StatusRequest,
    ) -> Result<LocalResult, SdkError> {
        ramflux_protocol::custody::pairing::PairingWire::validate(request)
            .map_err(|error| super::wire(&error))?;
        self.require_open()?;
        self.full_runtime.require_live()?;
        self.require_data_resume_scope(request)?;
        self.retire_data_attempt().await;
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let node = if let Some(node) = &self.full_node {
            node.clone()
        } else {
            self.native.as_ref().ok_or(SdkError::PairingCode("UpdateRequired"))?.full_node().await?
        };
        let local = participant.clone();
        let anchor = self.identity.local_ref.account_anchor.clone();
        let operation = request.operation_id.clone();
        let reference = self.identity.local_ref.clone();
        let target = reference.clone();
        let current = self
            .full_runtime
            .clone()
            .run_blocking(move || {
                local.full_native_stream_head(&anchor, Some((&operation, &target)))
            })
            .await?;
        let owned = request.clone();
        let pinned_node = node.clone();
        let action = move |db: &ramflux_storage::AccountDb| {
            participant.restore_full_data_in(db, &owned, &pinned_node, &current, &reference)
        };
        let snapshot = if let Some(writer) = &self.local_writer {
            writer.request(action).await?
        } else {
            let participant =
                self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
            let runtime = self.full_runtime.clone();
            self.full_runtime
                .clone()
                .run_blocking(move || {
                    let _local = runtime.local_work()?;
                    let slot = participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
                    action(slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?)
                })
                .await?
        };
        self.accept_data_resume(snapshot, node)?;
        self.transfer_status(request).await
    }
    pub(in crate::custody::pairing::coordinator) fn schedule_full_data_retry(
        &mut self,
        error: &SdkError,
    ) {
        let transient = matches!(
            error,
            SdkError::PairingCode("ResumeRequired" | "Busy")
                | SdkError::NodeTimeout { .. }
                | SdkError::NodeUnreachable { .. }
                | SdkError::GatewayWriterBusy
        ) || matches!(error, SdkError::Io(error) if matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe));
        let Some(ceremony) = &mut self.ceremony else { return };
        let Some(full) = &mut ceremony.full else { return };
        if !transient
            || ceremony.phase != "mutually_confirmed"
            || full.candidate.is_some()
            || full.publication.is_publishing()
        {
            full.data_retry_at = None;
            return;
        }
        if full.bootstrap.is_some() || full.data_retry_at.is_some() {
            full.data_retry_at.get_or_insert_with(|| {
                tokio::time::Instant::now() + std::time::Duration::from_secs(10)
            });
        }
    }
    pub(in crate::custody::pairing::coordinator) async fn retry_full_data_if_due(
        &mut self,
    ) -> Result<bool, SdkError> {
        let Some(ceremony) = &self.ceremony else { return Ok(false) };
        let Some(deadline) = ceremony.full.as_ref().and_then(|full| full.data_retry_at) else {
            return Ok(false);
        };
        if tokio::time::Instant::now() < deadline {
            return Ok(true);
        }
        let request = StatusRequest {
            schema: "ramflux.pairing.StatusRequest.v2".into(),
            version: 2,
            operation_id: ceremony.operation_id.clone(),
            generation: ceremony.generation,
        };
        if let Err(error) = Box::pin(self.resume_full_data(&request)).await {
            // Retaining the minimal ceremony scope allows another bounded attempt after
            // a native observation failure; no SAS/HPKE/approval survives retirement.
            if let Some(full) = self.ceremony.as_mut().and_then(|ceremony| ceremony.full.as_mut()) {
                full.data_retry_at =
                    Some(tokio::time::Instant::now() + std::time::Duration::from_secs(10));
            }
            self.note_background_error(&error);
            return Err(error);
        }
        Ok(true)
    }
    fn accept_data_resume(
        &mut self,
        snapshot: crate::custody::pairing::participant::FullDataResume,
        node: ramflux_crypto::custody::VerifiedNodeRecord,
    ) -> Result<(), SdkError> {
        self.full_runtime.register_stage(snapshot.cancel.clone())?;
        let role = if snapshot.live.role == "initiator" {
            PairingRole::Initiator
        } else {
            PairingRole::Responder
        };
        let common = snapshot.context.initiator.common.clone();
        let legacy = snapshot
            .invitation
            .body
            .project_common(common.master_public_key.clone())
            .map_err(|error| super::wire(&error))?;
        let th = snapshot.trust.local_stage_record()?.th;
        let expires = snapshot.trust.lease_expires_at();
        let own = if role == PairingRole::Initiator {
            &snapshot.context.initiator
        } else {
            &snapshot.context.responder
        };
        let mut ceremony = Self::open_ceremony(CeremonyOpen {
            operation_id: snapshot.live.operation_id,
            generation: snapshot.live.generation,
            role,
            origin: snapshot.invitation.body.public_origin.clone(),
            invitation: snapshot.invitation.body.clone(),
            token: zeroize::Zeroizing::new(String::new()),
            display_name: own.display_name.clone(),
            common: Some(legacy),
            verified_invite: Some(snapshot.invitation),
        });
        ceremony.phase =
            if snapshot.candidate.is_some() { "prepared" } else { "mutually_confirmed" }.into();
        ceremony.expires_at = expires;
        ceremony.displayed_th = Some(th);
        let peer = if role == PairingRole::Initiator {
            &snapshot.context.responder
        } else {
            &snapshot.context.initiator
        };
        ceremony.peer_ref = Some(peer.device_ref.clone());
        ceremony.peer_name = Some(peer.display_name.clone());
        let mut full = FullCeremony::new(common, None);
        if let Some(candidate) = &snapshot.candidate {
            ceremony.displayed_proposal =
                Some(ramflux_protocol::custody::object_hash(&candidate.publication().record)?);
        }
        full.candidate = snapshot.candidate;
        full.node = Some(node.clone());
        full.transcript = Some(snapshot.context);
        full.bootstrap = Some(BootstrapState::restored(
            snapshot.trust,
            snapshot.keys,
            snapshot.signer,
            snapshot.cancel,
            snapshot.position,
        ));
        ceremony.full = Some(full);
        self.actor_generation = ceremony.generation;
        if let Some(generation) = snapshot.frontend_generation {
            self.frontend_generation = generation;
        }
        self.full_node = Some(node);
        self.ceremony = Some(ceremony);
        Ok(())
    }
    fn require_data_resume_scope(&self, request: &StatusRequest) -> Result<(), SdkError> {
        if let Some(ceremony) = &self.ceremony {
            if ceremony.operation_id != request.operation_id
                || ceremony.generation != request.generation
            {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            if ceremony
                .full
                .as_ref()
                .is_none_or(|full| full.candidate.is_some() || full.publication.is_publishing())
                || ceremony.phase != "mutually_confirmed"
            {
                return Err(SdkError::PairingCode("PublicationPending"));
            }
        }
        Ok(())
    }
    async fn retire_data_attempt(&mut self) {
        if let Some(full) = self.ceremony.as_mut().and_then(|ceremony| ceremony.full.as_mut()) {
            if let Some(job) = full.take_stream_job() {
                job.abort_and_drain().await;
            }
            if let Some(job) = full.take_epoch_job() {
                job.abort_and_drain().await;
            }
        }
        if let Some(ceremony) = &mut self.ceremony {
            match &mut ceremony.sas {
                super::SasHold::Pending(sas) => sas.cleanup(),
                super::SasHold::Established(sas) => sas.cleanup(),
                super::SasHold::None => {}
            }
            ceremony.sas = super::SasHold::None;
            ceremony.token.zeroize();
            ceremony.emoji = None;
            ceremony.local_confirmed = false;
            ceremony.peer_mac_ok = false;
            ceremony.outbound.clear();
            if let Some(full) = &mut ceremony.full {
                full.bootstrap.take();
                full.management.take();
                full.hpke.take();
            }
        }
        self.full_runtime.drain_local_jobs().await;
    }
}
