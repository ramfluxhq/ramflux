// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Peer completion controls name exact local work; native and local generation owners authorize effects.
use super::{PairingActor, SdkError, publication::DestinationPhase};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::{object_hash, pairing::full_transfer::FullControlPayload};
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}
impl PairingActor {
    pub(in crate::custody::pairing::coordinator) fn full_staged_recipient_installed(&self) -> bool {
        self.recovered_installation.is_some()
            || self.ceremony.as_ref().is_some_and(|c| {
                c.role == PairingRole::Responder
                    && matches!(c.phase.as_str(), "locally_installed" | "completed")
                    && c.full.as_ref().is_some_and(|full| {
                        full.common.recipient_mode == "new"
                            && full.publication.destination_installed()
                    })
            })
    }

    pub(super) async fn accept_full_completion_control(
        &mut self,
        payload: FullControlPayload,
    ) -> Result<(), SdkError> {
        match payload {
            FullControlPayload::Published {
                operation_id,
                record_hash,
                device_set_epoch,
                recipient_ref,
            } => {
                self.with_ceremony_mut(|c| {
                    let full = c.full.as_mut().ok_or_else(wrong)?;
                    let candidate = full.candidate.as_ref().ok_or_else(wrong)?.publication();
                    if c.role != PairingRole::Responder
                        || c.phase != "prepared"
                        || !full.ready_retained
                        || operation_id != c.operation_id
                        || object_hash(&candidate.record)? != record_hash
                        || candidate.record.body.device_set_epoch != device_set_epoch
                        || candidate.record.body.master_certificate.body.primary_device_ref
                            != recipient_ref
                    {
                        return Err(wrong());
                    }
                    full.publication.destination = DestinationPhase::Requested;
                    Ok(())
                })?;
                Box::pin(self.advance_full_destination_installation()).await?;
            }
            FullControlPayload::Installed { operation_id, record_hash, recipient_ref } => {
                self.with_ceremony_mut(|c| {
                    let full = c.full.as_mut().ok_or_else(wrong)?;
                    let context = full.transcript.as_ref().ok_or_else(wrong)?;
                    if c.role != PairingRole::Initiator
                        || c.phase != "acknowledged"
                        || !full.publication.source_acknowledged()
                        || !full.publication.source_retired()
                        || operation_id != c.operation_id
                        || c.record_hash.as_deref() != Some(record_hash.as_str())
                        || context.responder.device_ref != recipient_ref
                    {
                        return Err(wrong());
                    }
                    full.management.as_mut().ok_or_else(wrong)?.queue_local_control(
                        FullControlPayload::Completed {
                            operation_id,
                            record_hash,
                            cleanup: if c.cleanup == "done" { "done" } else { "pending" }.into(),
                        },
                    )?;
                    c.phase = "completed".into();
                    Ok(())
                })?;
            }
            FullControlPayload::Completed { operation_id, record_hash, .. } => {
                self.with_ceremony_mut(|c| {
                    let full = c.full.as_ref().ok_or_else(wrong)?;
                    if c.role != PairingRole::Responder
                        || c.phase != "locally_installed"
                        || !full.publication.destination_installed()
                        || operation_id != c.operation_id
                        || c.record_hash.as_deref() != Some(record_hash.as_str())
                    {
                        return Err(wrong());
                    }
                    c.phase = "completed".into();
                    c.cleanup = "done".into();
                    Ok(())
                })?;
            }
            _ => return Err(wrong()),
        }
        Ok(())
    }
    pub(in crate::custody::pairing::coordinator) async fn advance_full_destination_installation(
        &mut self,
    ) -> Result<bool, SdkError> {
        let pending = self.with_ceremony(|c| {
            Ok(c.role == PairingRole::Responder
                && c.full.as_ref().is_some_and(|full| {
                    full.publication.destination_requested()
                        && !full.publication.destination_installed()
                        && full
                            .publication
                            .destination_retry_at
                            .is_none_or(|deadline| tokio::time::Instant::now() >= deadline)
                }))
        })?;
        if !pending {
            return Ok(false);
        }
        let participant = self.participant.clone().ok_or_else(wrong)?;
        let install = self.with_ceremony(|c| {
            let full = c.full.as_ref().ok_or_else(wrong)?;
            Ok(full.candidate.as_ref().ok_or_else(wrong)?.install().clone())
        })?;
        let outcome = if install.recipient_mode == "existing" {
            Box::pin(self.install_linked_full_generation(install)).await
        } else {
            let cancellation = self.full_runtime.stage_owner()?;
            self.full_runtime
                .clone()
                .run_blocking(move || {
                    participant.install_new_full_generation(&install, &cancellation)
                })
                .await
        };
        let authority = match outcome {
            Ok(authority) => authority,
            Err(error) => {
                if super::installation::install_busy(&error) {
                    self.with_ceremony_mut(|c| {
                        c.full.as_mut().ok_or_else(wrong)?.publication.destination_retry_at =
                            Some(tokio::time::Instant::now() + std::time::Duration::from_secs(30));
                        Ok(())
                    })?;
                }
                return Err(error);
            }
        };
        self.with_ceremony_mut(|c| {
            let full = c.full.as_mut().ok_or_else(wrong)?;
            let candidate = full.candidate.as_ref().ok_or_else(wrong)?.publication();
            let hash = object_hash(&authority.publication.record)?;
            if object_hash(&candidate.record)? != hash {
                return Err(wrong());
            }
            full.publication.destination = DestinationPhase::Installed;
            full.publication.destination_retry_at = None;
            if let Some(stream) = full.bootstrap.as_mut().and_then(|state| state.stream.as_mut()) {
                stream.receiver.take();
            }
            full.management.as_mut().ok_or_else(wrong)?.queue_local_control(
                FullControlPayload::Installed {
                    operation_id: c.operation_id.clone(),
                    record_hash: hash.clone(),
                    recipient_ref: authority
                        .publication
                        .record
                        .body
                        .master_certificate
                        .body
                        .primary_device_ref
                        .clone(),
                },
            )?;
            c.record_hash = Some(hash);
            c.record_epoch = Some(authority.publication.record.body.device_set_epoch);
            c.phase = "locally_installed".into();
            Ok(())
        })?;
        self.identity.is_primary = true;
        self.identity.local_ref =
            authority.publication.record.body.master_certificate.body.primary_device_ref.clone();
        self.identity.base_record_hash = object_hash(&authority.publication.record)?;
        self.identity.base_epoch = authority.publication.record.body.device_set_epoch;
        self.identity.master_public_key = Some(
            authority.publication.record.body.master_certificate.body.master_public_key.clone(),
        );
        Ok(true)
    }
}
