// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Author-signed v3 resync proofs; stateless admission is separate from stored-state replacement.
use super::{Carrier, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{SurfaceEvent, SurfaceState};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotProof {
    pub wire_base64: String,
    pub author_device_id: String,
}
impl SnapshotProof {
    pub(super) fn new(state: &SurfaceState, author: &str) -> Result<Self, SdkError> {
        Ok(Self {
            wire_base64: ramflux_protocol::encode_base64url(state.resync_frame()?.wire_bytes()?),
            author_device_id: author.into(),
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
        let event = SurfaceEvent::from_wire_bytes(&wire)?;
        if !event.is_resync()
            || event.conversation_id() != carrier.conversation_id
            || event.surface_id() != carrier.surface_id
            || event.version() != version
            || self.author_device_id.is_empty()
            || self.author_device_id.len() > 256
        {
            return Err(invalid("snapshot proof binding mismatch"));
        }
        // Empty-context proof checks never grant authority or discard known state.
        SurfaceState::validate_proof(&event)?;
        previous.apply(&event).map_err(Into::into)
    }
}
impl RamfluxClient {
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
            wire_base64: ramflux_protocol::encode_base64url(state.resync_frame()?.wire_bytes()?),
            signature: String::new(),
            snapshot: None,
        };
        let (key, _) = super::authored::authored_key(&candidate)?;
        if let Some(row) = self.account_db()?.load_actor_state::<serde_json::Value>(&key)? {
            let retained: Carrier =
                serde_json::from_value(row.get("carrier").cloned().unwrap_or(row))?;
            if retained.sender_device_id != local.device_id
                || !matches!(retained.payload()?,super::Payload::Event(event) if event.is_resync())
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
        if let Some((record, _)) = self.surface_state_ref(&carrier.surface_reference()?)? {
            if record.author_device_id != proof.author_device_id {
                return Err(invalid("snapshot executor changed"));
            }
        }
        if proof.author_device_id != carrier.sender_device_id {
            let owner =
                self.surface_signer_record(&carrier.author_principal_id, &proof.author_device_id)?;
            if owner.get("principal_id").and_then(serde_json::Value::as_str)
                != Some(carrier.author_principal_id.as_str())
            {
                return Err(invalid("snapshot executor principal mismatch"));
            }
        }
        Ok(Some(proof.restore(carrier, previous, version)?))
    }
}
