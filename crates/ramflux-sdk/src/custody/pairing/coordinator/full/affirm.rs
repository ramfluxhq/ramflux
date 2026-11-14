// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One attended, candidate-bound source approval; never reconstruct the old SAS flags.
use super::{PairingActor, SdkError};
use crate::custody::pairing::{FullSourceCandidateObservation, FullSourceSubmission};
use ramflux_protocol::custody::{
    Envelope, Publication, object_hash,
    pairing::{
        PairingWire,
        full_transfer::PreservationFull,
        local_dto::{Cancel, LocalResult, TransferAffirm},
    },
};

pub(super) struct AffirmedCandidate {
    pub(super) observation: FullSourceCandidateObservation,
    pub(super) preservation: Envelope<PreservationFull>,
}
impl PairingActor {
    /// Inspect a public candidate after frontend handback. This verifies the exact native
    /// base, preserving device set and original B SAS keys, and grants no signing approval.
    /// # Errors
    /// Refuses a borrowed writer, stale/foreign candidate, incomplete data or consumed approval.
    pub async fn inspect_full_source_candidate(
        &mut self,
        candidate: Publication,
    ) -> Result<LocalResult, SdkError> {
        self.require_open()?;
        self.full_runtime.require_live()?;
        let scope = self.full_source_data_scope()?;
        self.with_ceremony(|c| {
            if c.full.as_ref().is_none_or(|full| full.affirmation_used) {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            Ok(())
        })?;
        let observation = self.observe_source_candidate(candidate, scope.clone()).await?;
        let observation = self.validate_source_observation(observation).await?;
        let hash = object_hash(&observation.candidate.record)?;
        let destination =
            observation.candidate.record.body.master_certificate.body.primary_device_ref.clone();
        self.full_runtime.require_live()?;
        if self.full_source_data_scope()? != scope {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or(SdkError::PairingCode("WrongContext"))?;
            if full.affirmation_used {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            full.source_candidate = Some(Box::new(observation));
            c.displayed_proposal = Some(hash);
            c.peer_ref = Some(destination);
            c.emoji = None;
            c.phase = "proposal_pending".into();
            Ok(())
        })?;
        self.status_update()
    }
    /// Consume one explicit local approval for the exact inspected source candidate.
    /// The fresh native query runs off-loan; the original owner's local service releases
    /// its preservation signature. The old SAS flags stay unchanged.
    /// # Errors
    /// Refuses B, stale operation/generation/TH/hash, replay or failed data/native/key checks.
    pub async fn affirm_full_transfer(
        &mut self,
        request: &TransferAffirm,
    ) -> Result<LocalResult, SdkError> {
        request.validate().map_err(|error| super::wire(&error))?;
        self.require_open()?;
        self.full_runtime.require_live()?;
        let scope = self.full_source_data_scope()?;
        self.with_ceremony(|c| {
            super::super::check_generation(c, &request.operation_id, request.generation)?;
            if request.transcript_hash != ramflux_protocol::encode_base64url(scope.2) {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            let full = c.full.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?;
            let candidate =
                full.source_candidate.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?;
            if full.affirmation_used
                || candidate.scope != scope
                || object_hash(&candidate.candidate.record)? != request.new_record_hash
            {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            Ok(())
        })?;
        if !request.approved {
            return self
                .cancel(&Cancel {
                    schema: "ramflux.pairing.Cancel.v2".into(),
                    version: 2,
                    operation_id: request.operation_id.clone(),
                    generation: request.generation,
                })
                .await;
        }
        self.queue_source_approval(scope, false).await
    }
    pub(super) async fn queue_original_source_approval(&mut self) -> Result<(), SdkError> {
        let scope = self.full_source_approval_scope()?;
        self.queue_source_approval(scope, true).await?;
        Ok(())
    }
    async fn queue_source_approval(
        &mut self,
        scope: (String, u64, [u8; 32]),
        original_sas: bool,
    ) -> Result<LocalResult, SdkError> {
        let participant = self.participant.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?;
        if participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?.is_some() {
            return Err(SdkError::PairingCode("Busy"));
        }
        let observation = self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or(SdkError::PairingCode("WrongContext"))?;
            if full.affirmation_used {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            full.affirmation_used = true;
            full.source_candidate.take().ok_or(SdkError::PairingCode("WrongContext"))
        })?;
        // Native freshness is obtained after the attended gesture, with no original
        // writer loan. The account owner's local service performs the signing step.
        let observation =
            self.observe_source_candidate(observation.candidate, scope.clone()).await?;
        let observation = self.validate_source_observation(observation).await?;
        self.full_runtime.require_live()?;
        let current_scope = if original_sas {
            self.full_source_approval_scope()?
        } else {
            self.full_source_data_scope()?
        };
        if current_scope != scope {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        self.with_ceremony_mut(|c| {
            c.full.as_mut().ok_or(SdkError::PairingCode("WrongContext"))?.pending_affirmation =
                Some(Box::new(observation));
            Ok(())
        })?;
        self.status_update()
    }
    async fn validate_source_observation(
        &self,
        observation: FullSourceCandidateObservation,
    ) -> Result<FullSourceCandidateObservation, SdkError> {
        let context = self.with_ceremony(|c| {
            c.full
                .as_ref()
                .and_then(|full| full.transcript.clone())
                .ok_or(SdkError::PairingCode("WrongContext"))
        })?;
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let runtime = self.full_runtime.clone();
        self.full_runtime
            .clone()
            .run_blocking(move || {
                let _local = runtime.local_work()?;
                participant.validate_candidate_for_affirmation(&observation, &context)?;
                runtime.require_live()?;
                Ok(observation)
            })
            .await
    }
    /// Complete only the queued attended source request under the original writer's
    /// short local loan. This method performs no relay/native I/O and retains no key.
    /// # Errors
    /// Refuses another writer, lost stage/native context, replay or a stopped account.
    pub fn finish_full_source_affirmation(
        &mut self,
        db: &ramflux_storage::AccountDb,
    ) -> Result<LocalResult, SdkError> {
        self.require_open()?;
        self.full_runtime.require_live()?;
        let scope = self.full_source_data_scope()?;
        let observation = self.with_ceremony_mut(|c| {
            c.full
                .as_mut()
                .and_then(|full| full.pending_affirmation.take())
                .ok_or(SdkError::PairingCode("WrongContext"))
        })?;
        if observation.scope != scope {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let runtime = self.full_runtime.clone();
        let _local = runtime.local_work()?;
        let preservation = participant.preserve_full_candidate_in(db, &observation)?;
        runtime.require_live()?;
        self.with_ceremony_mut(|c| {
            c.full.as_mut().ok_or(SdkError::PairingCode("WrongContext"))?.affirmed =
                Some(Box::new(AffirmedCandidate { observation: *observation, preservation }));
            c.phase = "prepared".into();
            Ok(())
        })?;
        self.queue_source_ready()?;
        self.status_update()
    }
    /// The public artifact for the original source's encrypted management-control sender.
    /// # Errors
    /// Refuses absent, consumed or retired attended approval.
    pub fn affirmed_full_source_preservation(
        &self,
    ) -> Result<&Envelope<PreservationFull>, SdkError> {
        self.require_open()?;
        self.full_runtime.require_live()?;
        self.ceremony
            .as_ref()
            .and_then(|c| c.full.as_ref())
            .and_then(|f| f.affirmed.as_ref())
            .map(|approved| &approved.preservation)
            .ok_or(SdkError::PairingCode("WrongContext"))
    }
    /// Consume the same actor's approved candidate after its matching management handshake.
    /// A missing/corrupt retained signature refuses; this path cannot mint another signature.
    /// # Errors
    /// Refuses replay, changed scope, lock or missing retained data/approval.
    pub async fn prepare_affirmed_source_submission(
        &mut self,
    ) -> Result<FullSourceSubmission, SdkError> {
        self.require_open()?;
        self.full_runtime.require_live()?;
        let scope = self.full_source_data_scope()?;
        let (approved, cancelled) = self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or(SdkError::PairingCode("WrongContext"))?;
            let cancelled = full
                .bootstrap
                .as_ref()
                .and_then(|s| s.cancel.clone())
                .ok_or(SdkError::PairingCode("WrongContext"))?;
            let approved = full.affirmed.take().ok_or(SdkError::PairingCode("WrongContext"))?;
            if approved.observation.scope != scope {
                return Err(SdkError::PairingCode("WrongContext"));
            }
            Ok((approved, cancelled))
        })?;
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let runtime = self.full_runtime.clone();
        if let Some(writer) = &self.local_writer {
            return writer
                .request(move |db| {
                    participant.prepare_affirmed_source_submission_in(
                        db,
                        (scope, approved.observation),
                        runtime,
                        cancelled,
                        &approved.preservation,
                    )
                })
                .await;
        }
        self.full_runtime
            .clone()
            .run_blocking(move || {
                let _local = runtime.local_work()?;
                participant.prepare_full_source_submission(
                    scope,
                    approved.observation,
                    runtime.clone(),
                    cancelled,
                    Some(approved.preservation),
                )
            })
            .await
    }
}
