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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wire_base64: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub checkpoint_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
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
            surface_hash: state.hash().map(str::to_owned),
            metadata: None,
            wire_base64: ramflux_protocol::encode_base64url(wire),
            checkpoint_base64: ramflux_protocol::encode_base64url(
                state.checkpoint_bytes().map_err(|_| invalid("snapshot checkpoint failed"))?,
            ),
            author_device_id: author_device_id.into(),
        })
    }
    pub(super) fn delta(state: &SurfaceState, author: &str) -> Self {
        Self {
            wire_base64: String::new(),
            checkpoint_base64: String::new(),
            surface_hash: state.hash().map(str::to_owned),
            metadata: None,
            author_device_id: author.into(),
        }
    }
    pub(super) fn compact(state: &SurfaceState, author: &str) -> Result<Self, SdkError> {
        Ok(Self {
            metadata: Some(serde_json::from_slice(
                &state
                    .resync_metadata_bytes()
                    .map_err(|_| invalid("resync metadata encoding failed"))?,
            )?),
            ..Self::delta(state, author)
        })
    }
    pub(crate) fn is_full(&self) -> bool {
        self.metadata.is_some() || !self.checkpoint_base64.is_empty()
    }
    pub(super) fn matches_hash(&self, state: &SurfaceState) -> bool {
        self.surface_hash.as_deref().is_some_and(|hash| state.hash() == Some(hash))
    }
    pub(super) fn restore(
        &self,
        carrier: &Carrier,
        previous: &SurfaceState,
        version: u64,
    ) -> Result<SurfaceState, SdkError> {
        let wire_base64 =
            if self.metadata.is_some() { &carrier.wire_base64 } else { &self.wire_base64 };
        let wire = ramflux_protocol::decode_base64url(wire_base64)
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
        if let Some(metadata) = &self.metadata {
            let state = previous
                .resynchronize_compact(&event, &serde_json::to_vec(metadata)?)
                .map_err(|_| invalid("invalid compact resync state"))?;
            if !self.matches_hash(&state) {
                return Err(invalid("resync result hash mismatch"));
            }
            return Ok(state);
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
            carrier.snapshot = Some(SnapshotProof::delta(&next, author_device));
        }
        Ok(())
    }
    pub(crate) fn prepare_surface_resync(
        &self,
        reference: &str,
        message_id: &str,
    ) -> Result<Carrier, SdkError> {
        let (record, state) = self
            .surface_state_ref(reference)?
            .ok_or_else(|| crate::SurfaceRefusalCode::NotFound.error("resync surface absent"))?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if local.principal_id != record.author_principal_id {
            return Err(crate::SurfaceRefusalCode::NotAuthor
                .error("only the author may resynchronize a surface"));
        }
        let wire = ramflux_protocol::encode_a2ui_conversation_event(
            &record.conversation_id,
            state.version(),
            &A2uiConversationCommand::CreateSurface(
                state.content().ok_or_else(|| invalid("resync content absent"))?.clone(),
            ),
        )?;
        let candidate = Carrier {
            schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
            content_type: "surface".into(),
            posted_at: record.created_at,
            updated_at: record.updated_at,
            payload_kind: super::PayloadKind::Event,
            conversation_id: record.conversation_id,
            surface_id: record.surface_id,
            message_id: message_id.into(),
            sender_principal_id: local.principal_id.clone(),
            sender_device_id: local.device_id.clone(),
            author_principal_id: record.author_principal_id,
            wire_base64: ramflux_protocol::encode_base64url(wire),
            signature: String::new(),
            snapshot: Some(SnapshotProof::compact(&state, &record.author_device_id)?),
        };
        let (key, _) = super::authored::authored_key(&candidate)?;
        if let Some(row) = self.account_db()?.load_actor_state::<serde_json::Value>(&key)? {
            let retained: Carrier =
                serde_json::from_value(row.get("carrier").cloned().unwrap_or(row))?;
            if retained.sender_device_id != local.device_id
                || !retained.snapshot.as_ref().is_some_and(SnapshotProof::is_full)
            {
                return Err(invalid("resync message id is already used"));
            }
            return Ok(retained);
        }
        self.sign_surface_carrier(candidate)
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
            let owner =
                self.surface_signer_record(&carrier.author_principal_id, &proof.author_device_id)?;
            if owner["principal_id"] != carrier.author_principal_id {
                return Err(invalid("snapshot executor principal mismatch"));
            }
        }
        Ok(Some(next))
    }
}
