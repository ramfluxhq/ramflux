// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Author-signed full-state proofs for bounded recovery and own-device bootstrap.
use super::{Carrier, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{A2uiConversationCommand, A2uiConversationEvent, SurfaceState};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotProof {
    pub wire_base64: String,
    pub checkpoint_base64: String,
    pub author_device_id: String,
}
impl SnapshotProof {
    pub(super) fn new(state: &SurfaceState, author_device_id: &str) -> Result<Self, SdkError> {
        let content = state.content().ok_or_else(|| invalid("snapshot content absent"))?;
        let conversation =
            state.conversation_id().ok_or_else(|| invalid("snapshot conversation absent"))?;
        let wire = ramflux_protocol::encode_a2ui_conversation_event(
            conversation,
            state.version(),
            &A2uiConversationCommand::CreateSurface(content.clone()),
        )?;
        Ok(Self {
            wire_base64: ramflux_protocol::encode_base64url(wire),
            checkpoint_base64: ramflux_protocol::encode_base64url(
                state.checkpoint_bytes().map_err(|_| invalid("snapshot checkpoint failed"))?,
            ),
            author_device_id: author_device_id.into(),
        })
    }
    pub(super) fn restore(
        &self,
        carrier: &Carrier,
        previous: &SurfaceState,
        version: u64,
    ) -> Result<SurfaceState, SdkError> {
        let wire = ramflux_protocol::decode_base64url(&self.wire_base64)
            .map_err(|_| invalid("invalid snapshot wire encoding"))?;
        let event = A2uiConversationEvent::from_wire_bytes(&wire)?;
        if event.conversation_id() != carrier.conversation_id
            || super::command_id(event.command()) != carrier.surface_id
            || event.version() != version
            || self.author_device_id.is_empty()
            || self.author_device_id.len() > 256
        {
            return Err(invalid("snapshot proof binding mismatch"));
        }
        let checkpoint = ramflux_protocol::decode_base64url(&self.checkpoint_base64)
            .map_err(|_| invalid("invalid snapshot checkpoint encoding"))?;
        previous
            .resynchronize(&event, &checkpoint)
            .map_err(|_| invalid("invalid snapshot proof state"))
    }
}
impl RamfluxClient {
    pub(crate) fn attach_surface_snapshot(&self, carrier: &mut Carrier) -> Result<(), SdkError> {
        let super::Payload::Event(event) = carrier.payload()? else {
            return Ok(());
        };
        if carrier.sender_principal_id != carrier.author_principal_id {
            return Ok(());
        }
        let previous = self.surface_state_scoped(
            &carrier.conversation_id,
            &carrier.author_principal_id,
            &carrier.surface_id,
        )?;
        let state = previous.as_ref().map_or_else(SurfaceState::default, |(_, s)| s.clone());
        if let Ok(next) = state.apply(&event) {
            let author_device =
                previous.as_ref().map_or(carrier.sender_device_id.as_str(), |(record, _)| {
                    record.author_device_id.as_str()
                });
            carrier.snapshot = Some(SnapshotProof::new(&next, author_device)?);
        }
        Ok(())
    }
    pub(super) fn surface_is_out_of_sync(&self, reference: &str) -> Result<bool, SdkError> {
        Ok(self.account_db()?.load_actor_state::<u64>(&key("out_of_sync", reference))?.is_some())
    }
    pub(super) fn surface_snapshot_floor(&self, reference: &str) -> Result<u64, SdkError> {
        Ok(self.account_db()?.load_actor_state(&key("snapshot_floor", reference))?.unwrap_or(0))
    }
    pub(super) fn restore_surface_proof(
        &self,
        carrier: &Carrier,
        previous: &SurfaceState,
        version: u64,
    ) -> Result<Option<SurfaceState>, SdkError> {
        let Some(proof) = &carrier.snapshot else {
            return Ok(None);
        };
        let next = proof.restore(carrier, previous, version)?;
        if let Some((record, _)) = self.surface_state_ref(&carrier.surface_reference()?)? {
            if record.author_device_id != proof.author_device_id {
                return Err(invalid("snapshot executor changed"));
            }
        } else if proof.author_device_id != carrier.sender_device_id {
            let owner = self
                .account_db()?
                .client_record("device", &proof.author_device_id)?
                .ok_or_else(|| invalid("snapshot executor has no verified device record"))?;
            if owner["principal_id"] != carrier.author_principal_id {
                return Err(invalid("snapshot executor principal mismatch"));
            }
        }
        Ok(Some(next))
    }
}
