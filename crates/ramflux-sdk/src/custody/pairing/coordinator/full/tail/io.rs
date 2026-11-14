// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh native query followed by one bounded actual frontend-writer loan.
use super::{SdkError, wrong};
use crate::custody::pairing::coordinator::{FullRuntimeCancel, local_writer::LocalWriterPort};
use crate::custody::pairing::{FullTailContext, LocalPairingParticipant};
use ramflux_storage::{AccountDb, FullStageIoCancel, FullTailEndpoint};
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct TailIo {
    pub(super) participant: Arc<LocalPairingParticipant>,
    pub(super) writer: LocalWriterPort,
    pub(super) runtime: Arc<FullRuntimeCancel>,
    pub(super) operation: String,
    pub(super) generation: u64,
    pub(super) anchor: String,
    pub(super) cancelled: FullStageIoCancel,
}
impl TailIo {
    pub(super) async fn request<R: Send + 'static>(
        &self,
        action: impl FnOnce(
            &LocalPairingParticipant,
            &AccountDb,
            &FullTailContext<'_>,
            &FullStageIoCancel,
        ) -> Result<R, SdkError>
        + Send
        + 'static,
    ) -> Result<R, SdkError> {
        self.runtime.require_live()?;
        if self.cancelled.is_cancelled() {
            return Err(wrong());
        }
        let participant = self.participant.clone();
        let anchor = self.anchor.clone();
        let current = self
            .runtime
            .clone()
            .run_blocking(move || participant.full_native_head(&anchor))
            .await?;
        let io = self.clone();
        self.writer
            .request(move |db| {
                let now = crate::custody::network_now()?;
                let context = FullTailContext {
                    operation: &io.operation,
                    generation: io.generation,
                    current: &current,
                    now,
                };
                io.participant.full_selected_db(db, Some(&io.anchor))?;
                let mut endpoint =
                    db.open_full_tail_endpoint(&io.operation, io.generation, &current, now)?;
                endpoint.bind_local_io_cancellation(&io.cancelled)?;
                drop(endpoint);
                let output = action(&io.participant, db, &context, &io.cancelled)?;
                io.runtime.require_live()?;
                if io.cancelled.is_cancelled() {
                    return Err(wrong());
                }
                Ok(output)
            })
            .await
    }
    pub(super) async fn endpoint<R: Send + 'static>(
        &self,
        action: impl FnOnce(FullTailEndpoint<'_>, u64) -> Result<R, SdkError> + Send + 'static,
    ) -> Result<R, SdkError> {
        self.request(move |_, db, context, cancelled| {
            let mut endpoint = db.open_full_tail_endpoint(
                context.operation,
                context.generation,
                context.current,
                context.now,
            )?;
            endpoint.bind_local_io_cancellation(cancelled)?;
            action(endpoint, context.now)
        })
        .await
    }
    pub(super) async fn fresh(&self) -> Result<(), SdkError> {
        self.endpoint(|_, _| Ok(())).await
    }
    pub(super) async fn cached_admission(&self) -> Result<(), SdkError> {
        self.runtime.require_live()?;
        let local = self.participant.clone();
        let anchor = self.anchor.clone();
        let current =
            self.runtime.clone().run_blocking(move || local.full_native_head(&anchor)).await?;
        let operation = self.operation.clone();
        let generation = self.generation;
        self.writer
            .request(move |db| {
                Ok(db.admit_cached_full_tail_reply(
                    &operation,
                    generation,
                    &current,
                    crate::custody::network_now()?,
                )?)
            })
            .await
    }
    pub(super) async fn expire_source(&self) -> Result<(), SdkError> {
        self.cancelled.cancel();
        self.runtime.drain_local_jobs().await;
        self.runtime.drain_local_work();
        let operation = self.operation.clone();
        let generation = self.generation;
        self.writer
            .request(move |db| {
                let now = crate::custody::network_now()?;
                db.expire_full_source_tail(&operation, generation, now)?;
                db.reclaim_full_tail_stage(&operation, generation, now)?;
                Ok(())
            })
            .await
    }
    pub(super) async fn reclaim(&self) -> Result<(), SdkError> {
        self.cancelled.cancel();
        self.runtime.drain_local_jobs().await;
        self.runtime.drain_local_work();
        let operation = self.operation.clone();
        let generation = self.generation;
        self.writer
            .request(move |db| {
                db.reclaim_full_tail_stage(&operation, generation, crate::custody::network_now()?)?;
                Ok(())
            })
            .await
    }
    pub(super) async fn source_manifest(
        &self,
    ) -> Result<ramflux_protocol::custody::pairing::full_transfer::SourceManifest, SdkError> {
        let work =
            self.endpoint(|endpoint, now| Ok(endpoint.into_source_encoding_work(now)?)).await?;
        let runtime = self.runtime.clone();
        let draft = self
            .runtime
            .clone()
            .run_blocking(move || {
                let _local = runtime.local_work()?;
                Ok(work.encode()?)
            })
            .await?;
        self.request(move |participant, db, context, _| {
            participant.sign_and_retain_full_tail_manifest(db, context, &draft)
        })
        .await
    }
    pub(super) async fn validate(&self, hash: String) -> Result<(), SdkError> {
        let work = self
            .endpoint(move |endpoint, now| Ok(endpoint.into_validation_work(&hash, now)?))
            .await?;
        let runtime = self.runtime.clone();
        let proof = self
            .runtime
            .clone()
            .run_blocking(move || {
                let _local = runtime.local_work()?;
                Ok(work.validate()?)
            })
            .await?;
        self.endpoint(move |endpoint, now| Ok(endpoint.accept_validated_input(&proof, now)?)).await
    }
}
