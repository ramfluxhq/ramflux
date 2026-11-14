// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Data-only post-G3 tail jobs, owned by the root independently of later ceremonies.
use super::{PairingActor, PairingRole, SdkError};
use crate::custody::pairing::{FullPacketEpoch, FullPairingTransport};
use ramflux_protocol::custody::pairing::full_transfer::{
    DataPacket, ManifestAssembler, SourceManifest, manifest_hash,
};
use std::sync::Arc;
mod abandon;
#[cfg(test)]
mod hostile_fixture;
mod io;
mod receive;
mod resume;
mod send;
use io::TailIo;
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
fn hash(manifest: &SourceManifest) -> Result<String, SdkError> {
    manifest_hash(manifest).map(ramflux_protocol::encode_base64url).map_err(|_| wrong())
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Prepare,
    SendManifest,
    SourceReceipt,
    SourceChunk,
    SourceDv,
    Manifest,
    Chunk,
    Validate,
    Apply,
    Commit,
    Finished,
}
pub(in crate::custody::pairing::coordinator) struct TailJob {
    packet: Option<FullPacketEpoch>,
    pub(in crate::custody::pairing::coordinator) epoch: Option<super::epoch::FullEpochJob>,
    io: TailIo,
    relay: Arc<dyn FullPairingTransport>,
    origin: String,
    phase: Phase,
    manifest: Option<SourceManifest>,
    #[cfg(test)]
    manifest_override: Option<hostile_fixture::ManifestOverride>,
    assembler: ManifestAssembler,
    cached_reply: Option<ramflux_protocol::custody::pairing::full_transfer::relay::EncryptedPacket>,
    cleanup_pending: bool,
    expired: bool,
    cached_request:
        Option<ramflux_protocol::custody::pairing::full_transfer::relay::EncryptedPacket>,
    dv_retry_at: Option<tokio::time::Instant>,
    status: ramflux_protocol::custody::pairing::local_dto::FullStatus,
    next: u64,
    abandoned: bool,
    pub(super) error: Option<ramflux_protocol::custody::pairing::full_transfer::FullError>,
}
impl Drop for TailJob {
    fn drop(&mut self) {
        self.io.cancelled.cancel();
    }
}
impl TailJob {
    pub(in crate::custody::pairing::coordinator) fn generation(&self) -> u64 {
        self.io.generation
    }
    pub(super) fn merged(&self) -> bool {
        self.phase == Phase::Finished
    }
    pub(super) fn abandoned(&self) -> bool {
        self.abandoned
    }
    pub(super) fn completed_progress(&self) -> Option<super::status::FullProgress> {
        if !self.merged() {
            return None;
        }
        let manifest = self.manifest.as_ref()?;
        super::status::FullProgress::observed(manifest, manifest.manifest.chunk_count.0).ok()
    }
    async fn advance(&mut self) -> Result<(), SdkError> {
        if self.epoch.as_ref().is_some_and(|epoch| !epoch.finished()) {
            return Ok(());
        }
        if let Some(epoch) = self.epoch.take() {
            self.packet = Some(epoch.packet().await?);
            self.io.fresh().await?;
        }
        match self.phase {
            Phase::Prepare => {
                let manifest = self.io.source_manifest().await?;
                #[cfg(test)]
                let manifest = match self.manifest_override.take() {
                    Some(replace) => replace(manifest)?,
                    None => manifest,
                };
                self.manifest = Some(manifest);
                self.phase = Phase::SendManifest;
            }
            Phase::SendManifest => self.send_manifest().await?,
            Phase::SourceReceipt => self.source_receipt().await?,
            Phase::SourceChunk => self.source_chunk().await?,
            Phase::SourceDv => self.source_dv().await?,
            Phase::Manifest => self.receive_manifest().await?,
            Phase::Chunk => self.receive_chunk().await?,
            Phase::Validate => {
                let hash = hash(self.manifest.as_ref().ok_or_else(wrong)?)?;
                self.io.validate(hash).await?;
                self.phase = Phase::Apply;
            }
            Phase::Apply => {
                let hash = hash(self.manifest.as_ref().ok_or_else(wrong)?)?;
                if self
                    .io
                    .endpoint(move |endpoint, now| {
                        Ok(endpoint.apply_recipient_batch(&hash, 32, now)?)
                    })
                    .await?
                {
                    self.phase = Phase::Commit;
                }
            }
            Phase::Commit => self.commit().await?,
            Phase::Finished => {}
        }
        Ok(())
    }
    async fn poll(&mut self) -> Result<Option<DataPacket>, SdkError> {
        self.io.fresh().await?;
        let packet = self.packet.as_mut().ok_or_else(wrong)?;
        let Some(encrypted) = packet.poll(self.relay.as_ref(), &self.origin).await? else {
            return Ok(None);
        };
        self.io.runtime.require_live()?;
        packet.open_packet(&encrypted)
    }
    fn finish(&mut self) {
        self.phase = Phase::Finished;
        self.packet = None;
        self.cached_request = None;
        self.dv_retry_at = None;
        self.io.cancelled.cancel();
    }
}
impl PairingActor {
    pub(in crate::custody::pairing::coordinator) async fn advance_full_tails(
        &mut self,
    ) -> Result<(), SdkError> {
        self.start_completed_tail().await?;
        for job in self.tail_jobs.values_mut() {
            if !job.merged()
                && !job.abandoned
                && !job.expired
                && job.status.role == "initiator"
                && crate::custody::network_now()? >= job.status.lease_expires_at
            {
                job.expired = true;
                job.error = Some(
                    ramflux_protocol::custody::pairing::full_transfer::FullError::LeaseExpired,
                );
                job.packet = None;
                job.cached_request = None;
                job.io.cancelled.cancel();
                job.cleanup_pending = true;
            }
            if job.cleanup_pending {
                let result =
                    if job.expired { job.io.expire_source().await } else { job.io.reclaim().await };
                if result.is_ok() {
                    job.cleanup_pending = false;
                }
            }
            if job.merged() && job.packet.is_some() && job.cached_retry().await.is_err() {
                job.packet = None;
                job.cached_reply = None;
            }
            if !job.merged()
                && !job.abandoned
                && job.error.is_none()
                && let Err(error) = job.advance().await
            {
                tracing::debug!(phase = ?job.phase, role = job.status.role.as_str(), code = Self::background_error_code(&error), "full tail phase refused");
                #[cfg(test)]
                eprintln!("test: full tail {:?} {} refused: {error}", job.phase, job.status.role);
                job.error = Some(ramflux_protocol::custody::pairing::full_transfer::FullError::from_code(
                    Self::background_error_code(&error)
                ).unwrap_or(ramflux_protocol::custody::pairing::full_transfer::FullError::ResumeRequired));
                // A failed network epoch is never retried with advanced counters. The
                // durable tail remains pending for a fresh epoch or explicit abandonment.
                job.packet = None;
            }
        }
        Ok(())
    }
    async fn start_completed_tail(&mut self) -> Result<(), SdkError> {
        let Some(c) = self.ceremony.as_ref().filter(|c| c.phase == "completed" && c.full.is_some())
        else {
            return Ok(());
        };
        if self.tail_jobs.contains_key(&c.operation_id) || self.local_writer.is_none() {
            return Ok(());
        }
        if !c.full.as_ref().and_then(|f| f.management.as_ref()).is_some_and(|m| m.ready_for_tail())
        {
            return Ok(());
        }
        if self.tail_jobs.len() >= 3 {
            let completed =
                self.tail_jobs.iter().find(|(_, job)| job.merged()).map(|(op, _)| op.clone());
            if let Some(op) = completed {
                self.tail_jobs.remove(&op);
            } else {
                return Err(SdkError::PairingCode("TransferCapacity"));
            }
        }
        let status = self.current_full_status()?.ok_or_else(wrong)?;
        let c = self.ceremony.as_ref().ok_or_else(wrong)?;
        let operation = c.operation_id.clone();
        let generation = c.generation;
        let role = c.role;
        let writer = self.local_writer.clone().ok_or_else(wrong)?;
        let participant = self.participant.clone().ok_or_else(wrong)?;
        let anchor = self.identity.local_ref.account_anchor.clone();
        let owner = participant.clone();
        let native_anchor = anchor.clone();
        let current = self
            .full_runtime
            .clone()
            .run_blocking(move || owner.full_native_head(&native_anchor))
            .await?;
        let op = operation.clone();
        let cancelled = writer
            .request(move |db| {
                let endpoint = db.open_full_tail_endpoint(
                    &op,
                    generation,
                    &current,
                    crate::custody::network_now()?,
                )?;
                Ok(endpoint.io_cancel_handle())
            })
            .await?;
        self.full_runtime.register_tail_stage(cancelled.clone())?;
        let c = self.ceremony.as_mut().ok_or_else(wrong)?;
        let full = c.full.as_mut().ok_or_else(wrong)?;
        let management = full.management.take().ok_or_else(wrong)?;
        let packet = management.into_tail_packet()?;
        // Release completed prepublication decrypt-only workers before terminal GC.
        full.bootstrap.take();
        full.hpke.take();
        full.prepared.take();
        self.tail_jobs.insert(
            operation.clone(),
            TailJob {
                packet: Some(packet),
                epoch: None,
                io: TailIo {
                    participant,
                    writer,
                    runtime: self.full_runtime.clone(),
                    operation,
                    generation,
                    anchor,
                    cancelled,
                },
                relay: self.transport.full_transport().ok_or_else(wrong)?,
                origin: c.origin.clone(),
                phase: if role == PairingRole::Initiator {
                    Phase::Prepare
                } else {
                    Phase::Manifest
                },
                manifest: None,
                #[cfg(test)]
                manifest_override: None,
                assembler: ManifestAssembler::default(),
                cached_reply: None,
                cleanup_pending: false,
                expired: false,
                cached_request: None,
                dv_retry_at: None,
                status,
                next: 0,
                error: None,
                abandoned: false,
            },
        );
        Ok(())
    }
}
