// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Confirmed-channel enrollment; all frontends call the parent coordinator.

use super::{
    Arc, Close, DeviceRef, PairingActor, PairingRole, PairingWire, RelayFrame, SasHold, SdkError,
    Zeroize, decode_base64url, encode_base64url, verify_canonical_signature, wire,
};
use crate::custody::pairing::{LocalPairingParticipant, ParticipantContext};
use ramflux_protocol::custody::object_hash;
use ramflux_protocol::custody::pairing::channel::{Channel, ChannelContext, Payload};

impl PairingActor {
    pub(super) async fn refresh_generation(&mut self) -> Result<(), SdkError> {
        if let Some(participant) = self.participant.clone() {
            let runtime = self.full_runtime.clone();
            if let Some(writer) = &self.local_writer {
                let generation =
                    writer.request(move |db| participant.next_generation_in(db)).await?;
                self.actor_generation = self.actor_generation.max(generation);
                return Ok(());
            }
            self.actor_generation = self.actor_generation.max(
                block(self.full_runtime.clone(), move || {
                    let _local = runtime.local_work()?;
                    let generation = participant.next_generation()?;
                    runtime.require_live()?;
                    Ok(generation)
                })
                .await?,
            );
        }
        Ok(())
    }

    pub(super) async fn record_local_invitation(
        &self,
        invitation: ramflux_protocol::custody::Envelope<
            ramflux_protocol::custody::pairing::native::Invitation,
        >,
        generation: u64,
    ) -> Result<(), SdkError> {
        let Some(participant) = self.participant.clone() else {
            return Ok(());
        };
        if let Some(writer) = &self.local_writer {
            return writer
                .request(move |db| participant.record_invitation_in(db, &invitation, generation))
                .await;
        }
        let runtime = self.full_runtime.clone();
        block(self.full_runtime.clone(), move || {
            let _local = runtime.local_work()?;
            participant.record_invitation(&invitation, generation)
        })
        .await
    }
    pub(super) async fn load_public_keys(
        &self,
        reference: DeviceRef,
    ) -> Result<Option<(String, String)>, SdkError> {
        let Some(participant) = self.participant.clone() else { return Ok(None) };
        let runtime = self.full_runtime.clone();
        Ok(Some(
            block(self.full_runtime.clone(), move || {
                let _local = runtime.local_work()?;
                let keys = participant.public_keys(&reference)?;
                runtime.require_live()?;
                Ok(keys)
            })
            .await?,
        ))
    }

    fn participant_context(&self) -> Result<ParticipantContext, SdkError> {
        self.with_ceremony(|c| {
            Ok(ParticipantContext {
                invitation: c
                    .verified_invite
                    .clone()
                    .ok_or(SdkError::PairingCode("WrongContext"))?,
                transcript: c.transcript.clone().ok_or(SdkError::PairingCode("WrongContext"))?,
                transcript_hash: encode_base64url(
                    c.displayed_th.ok_or(SdkError::PairingCode("WrongContext"))?,
                ),
                generation: c.generation,
            })
        })
    }

    fn queue_channel(&mut self, payload: Payload) -> Result<(), SdkError> {
        self.with_ceremony_mut(|c| {
            let channel = Channel {
                schema: "ramflux.pairing.Channel.v2".into(),
                version: 2,
                invitation_id: c.invitation.invitation_id.clone(),
                transcript_hash: encode_base64url(
                    c.displayed_th.ok_or(SdkError::PairingCode("WrongContext"))?,
                ),
                payload,
            };
            let bytes = channel.to_wire_bytes().map_err(|error| wire(&error))?;
            let SasHold::Established(sas) = &mut c.sas else {
                return Err(SdkError::PairingCode("WrongContext"));
            };
            let (counter, ciphertext) = sas.seal(&bytes)?;
            c.outbound.push_back(RelayFrame::Channel {
                counter,
                ciphertext: encode_base64url(ciphertext),
            });
            Ok(())
        })
    }

    pub(super) async fn advance_workflow(&mut self) -> Result<(), SdkError> {
        if self.ceremony.as_ref().is_some_and(|c| c.full.is_some()) {
            return self.advance_full_bootstrap().await;
        }
        let Some(participant) = self.participant.clone() else {
            if self.ceremony.as_ref().is_some_and(|c| !c.channels.is_empty()) {
                return Err(SdkError::PairingCode("UpdateRequired"));
            }
            return Ok(());
        };
        while let Some((counter, ciphertext)) =
            self.ceremony.as_mut().and_then(|c| c.channels.pop_front())
        {
            let channel = self.with_ceremony_mut(|c| {
                let SasHold::Established(sas) = &mut c.sas else {
                    return Err(SdkError::PairingCode("WrongContext"));
                };
                let plaintext = sas.open(
                    counter,
                    &decode_base64url(&ciphertext)
                        .map_err(|_| SdkError::PairingCode("InvalidInput"))?,
                )?;
                Channel::from_wire_bytes(&plaintext).map_err(|error| wire(&error))
            })?;
            self.validate_received_channel(&channel)?;
            self.apply_channel(participant.clone(), channel).await?;
        }
        if self.ceremony.as_ref().is_some_and(|c| {
            c.role == PairingRole::Responder
                && c.phase == "mutually_confirmed"
                && c.enrollment.is_none()
        }) {
            let context = self.participant_context()?;
            let proposal =
                block(self.full_runtime.clone(), move || participant.proposal(&context)).await?;
            self.with_ceremony_mut(|c| {
                c.displayed_proposal = Some(object_hash(&proposal)?);
                c.enrollment = Some(proposal.clone());
                c.phase = "proposal_pending".into();
                c.emoji = None;
                Ok(())
            })?;
            self.queue_channel(Payload::Enrollment { proposal })?;
        }
        Ok(())
    }

    fn validate_received_channel(&self, channel: &Channel) -> Result<(), SdkError> {
        self.with_ceremony(|c| {
            let context = self.participant_context()?;
            let sender = if c.role == PairingRole::Initiator { "responder" } else { "initiator" };
            let (phase, hash, epoch) = match &channel.payload {
                Payload::Published { record_hash, device_set_epoch, .. }
                    if c.phase == "prepared" =>
                {
                    ("acknowledged", Some(record_hash.as_str()), Some(*device_set_epoch))
                }
                Payload::Installed { .. } if c.phase == "acknowledged" => {
                    ("locally_installed", c.record_hash.as_deref(), c.record_epoch)
                }
                Payload::Completed { .. } if c.phase == "locally_installed" => {
                    ("completed", c.record_hash.as_deref(), c.record_epoch)
                }
                _ => (c.phase.as_str(), c.record_hash.as_deref(), c.record_epoch),
            };
            channel
                .validate_context(&ChannelContext {
                    transcript: &context.transcript,
                    transcript_hash: &context.transcript_hash,
                    sender,
                    phase,
                    operation_id: &c.operation_id,
                    proposal_hash: c.displayed_proposal.as_deref(),
                    record_hash: hash,
                    record_epoch: epoch,
                    compacted_ids_hash: None,
                })
                .map_err(|error| wire(&error))
        })
    }

    async fn apply_channel(
        &mut self,
        participant: Arc<LocalPairingParticipant>,
        channel: Channel,
    ) -> Result<(), SdkError> {
        match channel.payload {
            Payload::Enrollment { proposal } => {
                let body = &proposal.body;
                verify_canonical_signature(
                    &ramflux_protocol::custody::signing_bytes(&body.schema, body)?,
                    &proposal.signature,
                    &body.branch_signing_key,
                )
                .map_err(|_| SdkError::PairingCode("WrongContext"))?;
                let context = self.participant_context()?;
                let saved = proposal.clone();
                block(self.full_runtime.clone(), move || {
                    participant.save_context(&context, &saved)
                })
                .await?;
                self.with_ceremony_mut(|c| {
                    c.displayed_proposal = Some(object_hash(&proposal)?);
                    c.enrollment = Some(proposal);
                    c.phase = "proposal_pending".into();
                    c.emoji = None;
                    Ok(())
                })?;
            }
            Payload::Approval { approved, .. } => {
                if approved {
                    self.with_ceremony_mut(|c| {
                        c.phase = "prepared".into();
                        c.emoji = None;
                        Ok(())
                    })?;
                } else {
                    self.fail("rejected", "Retired").await?;
                }
            }
            Payload::Published { operation_id, record_hash, device_set_epoch, recipient_ref } => {
                let context = self.participant_context()?;
                let hash = record_hash.clone();
                block(self.full_runtime.clone(), move || {
                    participant.install_enrollment(&context, &hash, device_set_epoch)
                })
                .await?;
                self.with_ceremony_mut(|c| {
                    c.phase = "locally_installed".into();
                    c.record_hash = Some(record_hash.clone());
                    c.record_epoch = Some(device_set_epoch);
                    Ok(())
                })?;
                self.queue_channel(Payload::Installed {
                    operation_id,
                    record_hash,
                    recipient_ref,
                })?;
            }
            Payload::Installed { operation_id, record_hash, .. } => {
                let op = operation_id.clone();
                let hash = record_hash.clone();
                block(self.full_runtime.clone(), move || participant.finish_install(&op, &hash))
                    .await?;
                self.queue_channel(Payload::Completed {
                    operation_id,
                    record_hash,
                    cleanup: "done".into(),
                })?;
                self.with_ceremony_mut(|c| {
                    c.phase = "completed".into();
                    c.cleanup = "done".into();
                    Ok(())
                })?;
            }
            Payload::Completed { operation_id, record_hash, .. } => {
                block(self.full_runtime.clone(), move || {
                    participant.finish_install(&operation_id, &record_hash)
                })
                .await?;
                self.with_ceremony_mut(|c| {
                    c.phase = "completed".into();
                    c.cleanup = "done".into();
                    Ok(())
                })?;
            }
            Payload::Abort { .. } => {
                self.fail("cancelled", "Retired").await?;
            }
            _ => return Err(SdkError::PairingCode("WrongContext")),
        }
        Ok(())
    }

    pub(super) async fn publish_workflow(&mut self) -> Result<(), SdkError> {
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let context = self.participant_context()?;
        let proposal = self
            .with_ceremony(|c| c.enrollment.clone().ok_or(SdkError::PairingCode("WrongContext")))?;
        self.queue_channel(Payload::Approval {
            proposal_hash: object_hash(&proposal)?,
            base_record_hash: context.invitation.body.base_record_hash.clone(),
            base_epoch: context.invitation.body.base_epoch,
            approved: true,
        })?;
        self.flush_send().await?;
        let recipient_ref = context.transcript.responder.device_ref.clone();
        let published = block(self.full_runtime.clone(), move || {
            participant.publish_enrollment(&context, &proposal)
        })
        .await?;
        self.identity.base_record_hash.clone_from(&published.record_hash);
        self.identity.base_epoch = published.epoch;
        self.with_ceremony_mut(|c| {
            c.phase = "acknowledged".into();
            c.record_hash = Some(published.record_hash.clone());
            c.record_epoch = Some(published.epoch);
            Ok(())
        })?;
        let operation_id = self.with_ceremony(|c| Ok(c.operation_id.clone()))?;
        self.queue_channel(Payload::Published {
            operation_id,
            record_hash: published.record_hash,
            device_set_epoch: published.epoch,
            recipient_ref,
        })
    }

    pub(super) async fn close_completed_relay(&mut self) {
        let close = self
            .ceremony
            .as_ref()
            .filter(|c| {
                c.phase == "completed"
                    && c.role == PairingRole::Responder
                    && c.outbound.is_empty()
                    && !c.token.is_empty()
            })
            .map(|c| {
                (
                    c.origin.clone(),
                    Close {
                        schema: "ramflux.pairing.Close.v2".into(),
                        version: 2,
                        invitation_id: c.invitation.invitation_id.clone(),
                        issuer_seq: c.issuer_seq,
                        role: "responder".into(),
                        token: c.token.as_str().into(),
                        reason: "done".into(),
                    },
                )
            });
        if let Some((origin, close)) = close {
            let _ = self.transport.close(origin, close).await;
        }
    }

    pub(super) fn clear_completed_secrets(&mut self) {
        if let Some(c) =
            self.ceremony.as_mut().filter(|c| c.phase == "completed" && c.outbound.is_empty())
        {
            c.token.zeroize();
            c.sas = SasHold::None;
            c.channels.clear();
            if let Some(native) = &self.native {
                native.close();
            }
        }
    }
}

async fn block<T: std::marker::Send + 'static>(
    runtime: Arc<super::FullRuntimeCancel>,
    work: impl FnOnce() -> Result<T, SdkError> + std::marker::Send + 'static,
) -> Result<T, SdkError> {
    runtime.run_blocking(work).await
}
