// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restart creates a fresh data-only tail epoch only from authenticated local pending state.
use super::{PairingActor, PairingRole, Phase, SdkError, TailIo, TailJob, wrong};
use ramflux_protocol::custody::pairing::{
    PairingWire as _,
    local_dto::{FullStatus, FullTailStatus, LocalResult, Outcome, StatusRequest},
};
impl TailJob {
    pub(in crate::custody::pairing::coordinator) fn result(
        &self,
        request: &StatusRequest,
    ) -> Result<LocalResult, SdkError> {
        if request.generation != self.status.generation
            || request.operation_id != self.status.operation_id
        {
            return Err(wrong());
        }
        let mut value = self.status.clone();
        value.result = self.error;
        value.tail_status = if self.abandoned {
            FullTailStatus::Abandoned
        } else if self.merged() {
            FullTailStatus::Merged
        } else {
            FullTailStatus::Pending
        };
        if let Some(progress) = self.completed_progress() {
            value.bytes_total.0 = progress.total;
            value.bytes_durable.0 = progress.durable;
            value.cut.0 = progress.cut;
        }
        local_result(value)
    }
}
pub(super) fn local_result(mut value: FullStatus) -> Result<LocalResult, SdkError> {
    if value.tail_status == FullTailStatus::Pending
        && crate::custody::network_now()? >= value.lease_expires_at
    {
        value.result =
            Some(ramflux_protocol::custody::pairing::full_transfer::FullError::LeaseExpired);
    }
    value.validate().map_err(|_| wrong())?;
    Ok(LocalResult {
        schema: "ramflux.pairing.LocalResult.v2".into(),
        version: 2,
        outcome: Outcome::FullStatus { value: Box::new(value) },
    })
}
impl PairingActor {
    pub(in crate::custody::pairing::coordinator) async fn resume_full_tail(
        &mut self,
        request: &StatusRequest,
    ) -> Result<Option<LocalResult>, SdkError> {
        self.require_open()?;
        request.validate().map_err(|_| wrong())?;
        if let Some(result) = self.existing_tail_or_retry(request).await? {
            return Ok(Some(result));
        }
        let Some((scope, role, unlock)) = self.retained_tail_snapshot(request).await? else {
            return Ok(None);
        };
        let participant = self.participant.clone().ok_or_else(wrong)?;
        let anchor = scope.grant.source_ref.account_anchor.clone();
        let current = self.observe_tail_native(request, &anchor, role, unlock).await?;
        let result = if scope.merged || scope.abandoned {
            None
        } else {
            super::super::installed_status::installed_authority_result(
                &scope.grant,
                &current,
                crate::custody::network_now()?,
                scope.lease_expires_at,
            )
        };
        let mut status = super::super::installed_status::installed_progress(
            request,
            scope.lease_expires_at,
            scope.bytes_total,
            scope.cut,
            result,
            if scope.abandoned {
                FullTailStatus::Abandoned
            } else if scope.merged {
                FullTailStatus::Merged
            } else {
                FullTailStatus::Pending
            },
        );
        status.role = role.as_str().into();
        if (role == PairingRole::Initiator
            && result
                == Some(ramflux_protocol::custody::pairing::full_transfer::FullError::LeaseExpired))
            || scope.merged
            || scope.abandoned
        {
            self.reclaim_retained_completion(
                request,
                role == PairingRole::Initiator && !scope.merged && !scope.abandoned,
            )
            .await;
        }
        if scope.merged || scope.abandoned || result.is_some() || self.local_writer.is_none() {
            self.recovered_tail_status = Some(status.clone());
            return local_result(status).map(Some);
        }
        let node = match &self.full_node {
            Some(node) => node.clone(),
            None => {
                self.native
                    .as_ref()
                    .ok_or(SdkError::PairingCode("UpdateRequired"))?
                    .full_node()
                    .await?
            }
        };
        let owned = request.clone();
        let resume = self
            .installation_loan(move |db| {
                participant.restore_full_tail_in(db, &owned, &node, &current)
            })
            .await?;
        self.start_resumed_tail(request, status.clone(), anchor, resume)?;
        self.recovered_tail_status = None;
        local_result(status).map(Some)
    }
    async fn observe_tail_native(
        &self,
        request: &StatusRequest,
        anchor: &str,
        role: PairingRole,
        unlock: ramflux_storage::FullLocalUnlockGuard,
    ) -> Result<ramflux_crypto::custody::VerifiedRecord, SdkError> {
        let local = self.participant.clone().ok_or_else(wrong)?;
        let query_anchor = anchor.to_owned();
        let current = self
            .full_runtime
            .clone()
            .run_blocking(move || {
                unlock.require_unlocked()?;
                let current = local.full_native_head(&query_anchor)?;
                unlock.require_unlocked()?;
                Ok(current)
            })
            .await?;
        let owned = request.clone();
        let observed = current.clone();
        self.installation_loan(move |db| {
            let now = crate::custody::network_now()?;
            match role {
                PairingRole::Initiator => db.observe_full_source_tail_native_head(
                    &owned.operation_id,
                    owned.generation,
                    &observed,
                    now,
                )?,
                PairingRole::Responder => db.observe_full_installed_tail_native_head(
                    &owned.operation_id,
                    owned.generation,
                    &observed,
                    now,
                )?,
            }
            Ok(())
        })
        .await?;
        Ok(current)
    }
    async fn reclaim_retained_completion(&self, request: &StatusRequest, expire_source: bool) {
        self.full_runtime.drain_local_jobs().await;
        self.full_runtime.drain_local_work();
        let owned = request.clone();
        let result = self
            .installation_loan(move |db| {
                let now = crate::custody::network_now()?;
                if expire_source {
                    db.expire_full_source_tail(&owned.operation_id, owned.generation, now)?;
                }
                db.reclaim_full_tail_stage(&owned.operation_id, owned.generation, now)?;
                Ok(())
            })
            .await;
        if let Err(error) = result {
            tracing::debug!(
                error_code = Self::background_error_code(&error),
                "terminal tail stage cleanup deferred"
            );
        }
    }
    async fn existing_tail_or_retry(
        &mut self,
        request: &StatusRequest,
    ) -> Result<Option<LocalResult>, SdkError> {
        if let Some(job) = self.tail_jobs.get(&request.operation_id) {
            if job.error.is_none() {
                return job.result(request).map(Some);
            }
            if job.io.generation != request.generation {
                return Err(wrong());
            }
        }
        if self.tail_jobs.get(&request.operation_id).is_some_and(|job| job.error.is_some())
            && let Some(mut job) = self.tail_jobs.remove(&request.operation_id)
            && let Some(epoch) = job.epoch.take()
        {
            epoch.abort_and_drain().await;
        }
        Ok(None)
    }
    pub(super) async fn retained_tail_snapshot(
        &self,
        request: &StatusRequest,
    ) -> Result<
        Option<(
            ramflux_storage::FullInstalledTailScope,
            PairingRole,
            ramflux_storage::FullLocalUnlockGuard,
        )>,
        SdkError,
    > {
        let participant = self.participant.clone().ok_or_else(wrong)?;
        let owned = request.clone();
        let has_writer = self.local_writer.is_some();
        self.installation_loan(move |db| {
            if db.pairing_head()?.is_some() {
                return Ok(None);
            }
            let now = crate::custody::network_now()?;
            if let Some(scope) =
                db.full_installed_source_tail_scope(&owned.operation_id, owned.generation, now)?
            {
                return Ok(Some((scope, PairingRole::Initiator, db.full_local_unlock_guard()?)));
            }
            let recipient = db
                .pairing_live_rows()?
                .into_iter()
                .any(|row| row.operation_id == owned.operation_id && row.role == "responder");
            if !recipient || !has_writer {
                return Ok(None);
            }
            let Some(adoption) =
                db.pairing_adoption()?.filter(|row| row.full_generation_nonce.is_some())
            else {
                return Ok(None);
            };
            let Some(install) = crate::custody::pairing::install_store::read_installed(
                &participant.root,
                &participant.account_id,
            )?
            else {
                return Ok(None);
            };
            let native =
                crate::custody::load_data_account(&participant.root, &participant.account_id, now)?;
            crate::custody::pairing::full_generation::require_completed_full_generation(
                &participant.root,
                &native,
                &install,
                &adoption,
            )?;
            let scope =
                db.full_installed_recipient_tail_scope(&owned.operation_id, owned.generation, now)?;
            Ok(Some((scope, PairingRole::Responder, db.full_local_unlock_guard()?)))
        })
        .await
    }
    fn start_resumed_tail(
        &mut self,
        request: &StatusRequest,
        status: FullStatus,
        anchor: String,
        resume: crate::custody::pairing::participant::FullTailResume,
    ) -> Result<(), SdkError> {
        if self.tail_jobs.len() >= 3 {
            return Err(SdkError::PairingCode("TransferCapacity"));
        }
        self.full_runtime.register_tail_stage(resume.cancelled.clone())?;
        let role = resume.trust.local_stage_record()?.role;
        let io = TailIo {
            participant: self.participant.clone().ok_or_else(wrong)?,
            writer: self.local_writer.clone().ok_or_else(wrong)?,
            runtime: self.full_runtime.clone(),
            operation: request.operation_id.clone(),
            generation: request.generation,
            anchor,
            cancelled: resume.cancelled.clone(),
        };
        let relay = self.transport.full_transport().ok_or_else(wrong)?;
        let origin = resume.origin.clone();
        let epoch = super::super::epoch::start_tail(
            relay.clone(),
            origin.clone(),
            self.full_runtime.clone(),
            resume,
        )?;
        self.tail_jobs.insert(
            request.operation_id.clone(),
            TailJob {
                packet: None,
                epoch: Some(epoch),
                io,
                relay,
                origin,
                phase: if role == PairingRole::Initiator {
                    Phase::Prepare
                } else {
                    Phase::Manifest
                },
                manifest: None,
                #[cfg(test)]
                manifest_override: None,
                assembler:
                    ramflux_protocol::custody::pairing::full_transfer::ManifestAssembler::default(),
                cached_reply: None,
                cleanup_pending: false,
                expired: false,
                cached_request: None,
                dv_retry_at: None,
                status,
                next: 0,
                abandoned: false,
                error: None,
            },
        );
        Ok(())
    }
    pub(in crate::custody::pairing::coordinator) fn recovered_tail_result(
        &self,
        request: &StatusRequest,
    ) -> Result<Option<LocalResult>, SdkError> {
        let Some(status) = &self.recovered_tail_status else {
            return Ok(None);
        };
        if status.operation_id != request.operation_id || status.generation != request.generation {
            return Err(wrong());
        }
        local_result(status.clone()).map(Some)
    }
}
