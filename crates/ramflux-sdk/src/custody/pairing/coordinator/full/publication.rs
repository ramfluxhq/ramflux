// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native full publication, J6 and source retirement, with actual frontend loans kept short.
use super::{PairingActor, SdkError};
use crate::custody::pairing::{FullSourcePublished, FullSourceSubmission, Installation};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::{object_hash, pairing::full_transfer::FullControlPayload};

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SourcePhase {
    #[default]
    Idle,
    Submitted,
    Observed,
    Acknowledged,
    Retired,
    Announced,
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum DestinationPhase {
    #[default]
    Idle,
    Requested,
    Installed,
}
#[derive(Default)]
pub(super) struct FullPublication {
    submission: Option<FullSourceSubmission>,
    published: Option<Box<FullSourcePublished>>,
    pub(super) source: SourcePhase,
    pub(super) destination: DestinationPhase,
    pub(super) source_tail_durable: bool,
    pub(super) destination_retry_at: Option<tokio::time::Instant>,
}
impl FullPublication {
    pub(super) fn source_acknowledged(&self) -> bool {
        self.source >= SourcePhase::Acknowledged
    }
    pub(super) fn source_retired(&self) -> bool {
        self.source >= SourcePhase::Retired
    }
    pub(super) fn announced(&self) -> bool {
        self.source == SourcePhase::Announced
    }
    pub(super) fn destination_requested(&self) -> bool {
        self.destination == DestinationPhase::Requested
    }
    pub(super) fn destination_installed(&self) -> bool {
        self.destination == DestinationPhase::Installed
    }
    pub(super) fn is_publishing(&self) -> bool {
        self.source != SourcePhase::Idle
    }
    pub(super) fn tail_pending(&self) -> bool {
        self.source_acknowledged() || self.destination_installed()
    }
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
                    !full.publication.announced()
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
                let state = &mut c.full.as_mut().ok_or_else(wrong)?.publication;
                state.submission = Some(submission);
                state.source = SourcePhase::Submitted;
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
                let state = &mut c.full.as_mut().ok_or_else(wrong)?.publication;
                state.published = Some(Box::new(published));
                state.source = SourcePhase::Observed;
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
                state.source_acknowledged(),
            ))
        })?;
        let participant = self.participant.clone().ok_or_else(wrong)?;
        if !acknowledged {
            Box::pin(self.acknowledge_full_source(writer, &published, &operation)).await?;
        }
        let root = participant.root.clone();
        let vault = participant.vault.clone();
        let receipt = published.clone();
        let cleanup = writer
            .request(move |db| {
                let now = crate::custody::network_now()?;
                receipt.retire_source(&Installation { root: &root, db, vault: vault.as_ref(), now })
            })
            .await?;
        self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or_else(wrong)?;
            full.publication.source = SourcePhase::Retired;
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
            full.publication.source = SourcePhase::Announced;
            c.record_hash = Some(hash);
            c.record_epoch = Some(record.body.device_set_epoch);
            c.phase = "acknowledged".into();
            c.cleanup = match cleanup {
                crate::custody::pairing::FullSourceRetirementOutcome::Complete => "done",
                crate::custody::pairing::FullSourceRetirementOutcome::CleanupPending => "pending",
            }
            .into();
            Ok(())
        })?;
        self.identity.is_primary = false;
        self.identity.base_record_hash = object_hash(&published.authority().publication.record)?;
        self.identity.base_epoch = published.authority().publication.record.body.device_set_epoch;
        Ok(())
    }
    async fn acknowledge_full_source(
        &mut self,
        writer: &super::super::local_writer::LocalWriterPort,
        published: &FullSourcePublished,
        operation: &str,
    ) -> Result<(), SdkError> {
        let receipt = published.clone();
        let expected = object_hash(&published.authority().publication.record)?;
        let operation_id = operation.to_owned();
        let cut = writer
            .request(move |db| {
                let now = crate::custody::network_now()?;
                if let Some(head) = db.pairing_head()?
                    && head.state == "acknowledged"
                {
                    if head.operation_id != operation_id || head.candidate_hash != expected {
                        return Err(wrong());
                    }
                    db.full_source_retirement_owner(&operation_id, &expected, now)?;
                    return Ok(None);
                }
                Ok(Some(receipt.acknowledge(db, now)?))
            })
            .await?;
        self.with_ceremony_mut(|c| {
            c.full.as_mut().ok_or_else(wrong)?.publication.source = SourcePhase::Acknowledged;
            Ok(())
        })?;
        let copy_result = if let Some(cut) = cut {
            let operation = operation.to_owned();
            match writer
                .request(move |db| {
                    let stage = db.open_full_transfer_stage(
                        &operation,
                        PairingRole::Initiator,
                        crate::custody::network_now()?,
                    )?;
                    Ok(cut.into_private_work(stage)?)
                })
                .await
            {
                Ok(work) => self.full_runtime.clone().run_blocking(move || Ok(work.copy()?)).await,
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        let durable = match copy_result {
            Ok(()) => {
                let operation = operation.to_owned();
                writer
                    .request(move |db| {
                        let stage = db.open_full_transfer_stage(
                            &operation,
                            PairingRole::Initiator,
                            crate::custody::network_now()?,
                        )?;
                        Ok(stage.finish_source_tail_capture()?)
                    })
                    .await
            }
            Err(error) => Err(error),
        };
        match durable {
            Ok(()) => self.with_ceremony_mut(|c| {
                c.full.as_mut().ok_or_else(wrong)?.publication.source_tail_durable = true;
                Ok(())
            })?,
            Err(error) => {
                // The native role is already durable. Keep an explicit pending tail;
                // a failed local copy cannot block source convergence or undo authority.
                self.note_background_error(&error);
            }
        }
        self.full_runtime.require_live()
    }
}
