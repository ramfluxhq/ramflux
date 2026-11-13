// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native full publication, J6 and source retirement, with actual frontend loans kept short.
use super::{PairingActor, SdkError};
use crate::custody::pairing::{FullSourcePublished, FullSourceSubmission, Installation};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::{object_hash, pairing::full_transfer::FullControlPayload};

#[derive(Default)]
pub(super) struct FullPublication {
    submission: Option<FullSourceSubmission>,
    published: Option<FullSourcePublished>,
    pub(super) source_j6: bool,
    source_tail_durable: bool,
    pub(super) source_retired: bool,
    pub(super) announced: bool,
    pub(super) destination_requested: bool,
    pub(super) destination_installed: bool,
}
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
impl PairingActor {
    /// Complete the original source's submitted intent after its ready artifact was sent.
    /// This never recreates a consumed user approval or authorizes another candidate.
    /// # Errors
    /// Refuses a missing frontend owner, dead unlock, incomplete duplex/ready or changed native head.
    pub async fn advance_full_source_publication(&mut self) -> Result<bool, SdkError> {
        self.require_open()?;
        self.full_runtime.require_live()?;
        let Some(writer) = self.local_writer.clone() else { return Ok(false) };
        let ready = self.with_ceremony(|c| {
            Ok(c.role == PairingRole::Initiator
                && c.full.as_ref().is_some_and(|full| {
                    !full.publication.announced
                        && full
                            .management
                            .as_ref()
                            .is_some_and(|management| management.source_ready_sent)
                }))
        })?;
        if !ready {
            return Ok(false);
        }
        let prepared = self.with_ceremony(|c| {
            Ok(c.full.as_ref().ok_or_else(wrong)?.publication.submission.is_some())
        })?;
        if !prepared {
            let submission = self.prepare_affirmed_source_submission().await?;
            self.with_ceremony_mut(|c| {
                c.full.as_mut().ok_or_else(wrong)?.publication.submission = Some(submission);
                Ok(())
            })?;
        }
        let observed = self.with_ceremony(|c| {
            Ok(c.full.as_ref().ok_or_else(wrong)?.publication.published.is_some())
        })?;
        if !observed {
            let submission = self.with_ceremony(|c| {
                c.full
                    .as_ref()
                    .and_then(|full| full.publication.submission.clone())
                    .ok_or_else(wrong)
            })?;
            let published =
                self.full_runtime.clone().run_blocking(move || submission.submit()).await?;
            self.with_ceremony_mut(|c| {
                c.full.as_mut().ok_or_else(wrong)?.publication.published = Some(published);
                Ok(())
            })?;
        }
        Box::pin(self.commit_full_source_publication(&writer)).await?;
        Ok(true)
    }

    async fn commit_full_source_publication(
        &mut self,
        writer: &super::super::local_writer::LocalWriterPort,
    ) -> Result<(), SdkError> {
        let (published, operation, acknowledged) = self.with_ceremony(|c| {
            let state = &c.full.as_ref().ok_or_else(wrong)?.publication;
            Ok((
                state.published.clone().ok_or_else(wrong)?,
                c.operation_id.clone(),
                state.source_j6,
            ))
        })?;
        let participant = self.participant.clone().ok_or_else(wrong)?;
        if !acknowledged {
            let receipt = published.clone();
            let operation = operation.clone();
            let work = writer
                .request(move |db| {
                    let now = crate::custody::network_now()?;
                    let cut = receipt.acknowledge(db, now)?;
                    let stage =
                        db.open_full_transfer_stage(&operation, PairingRole::Initiator, now)?;
                    Ok(cut.into_private_work(stage)?)
                })
                .await?;
            self.with_ceremony_mut(|c| {
                c.full.as_mut().ok_or_else(wrong)?.publication.source_j6 = true;
                Ok(())
            })?;
            self.full_runtime.clone().run_blocking(move || Ok(work.copy()?)).await?;
            self.with_ceremony_mut(|c| {
                c.full.as_mut().ok_or_else(wrong)?.publication.source_tail_durable = true;
                Ok(())
            })?;
        }
        let root = participant.root.clone();
        let vault = participant.vault.clone();
        let receipt = published.clone();
        let cleanup = writer
            .request(move |db| {
                let now = crate::custody::network_now()?;
                let stage = db.open_full_transfer_stage(&operation, PairingRole::Initiator, now)?;
                stage.finish_source_tail_capture()?;
                drop(stage);
                receipt.retire_source(&Installation { root: &root, db, vault: vault.as_ref(), now })
            })
            .await?;
        self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or_else(wrong)?;
            full.publication.source_retired = true;
            let record = &published.authority().publication.record;
            let hash = object_hash(record)?;
            full.management.as_mut().ok_or_else(wrong)?.queue_local_control(
                FullControlPayload::Published {
                    operation_id: c.operation_id.clone(),
                    record_hash: hash.clone(),
                    device_set_epoch: record.body.device_set_epoch,
                    recipient_ref: record.body.master_certificate.body.primary_device_ref.clone(),
                },
            )?;
            full.publication.announced = true;
            c.record_hash = Some(hash);
            c.record_epoch = Some(record.body.device_set_epoch);
            c.phase = "acknowledged".into();
            c.cleanup = match cleanup {
                crate::custody::pairing::FullSourceRetirementOutcome::Complete => "done",
                crate::custody::pairing::FullSourceRetirementOutcome::CleanupPending => {
                    "cleanup_pending"
                }
            }
            .into();
            Ok(())
        })?;
        self.identity.is_primary = false;
        self.identity.base_record_hash = object_hash(&published.authority().publication.record)?;
        self.identity.base_epoch = published.authority().publication.record.body.device_set_epoch;
        Ok(())
    }
}
