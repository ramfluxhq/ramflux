// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reconnect reconstructs data-only trust; every human/publication approval stays absent.
use super::{FullCeremony, PairingActor, PairingRole, SdkError, bootstrap::BootstrapState};
use crate::custody::pairing::coordinator::CeremonyOpen;
use ramflux_protocol::custody::pairing::local_dto::{LocalResult, StatusRequest};
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
        ceremony.phase = "mutually_confirmed".into();
        ceremony.expires_at = expires;
        ceremony.displayed_th = Some(th);
        let mut full = FullCeremony::new(common, None);
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
        self.ceremony.take();
        self.full_runtime.drain_local_jobs().await;
    }
}
