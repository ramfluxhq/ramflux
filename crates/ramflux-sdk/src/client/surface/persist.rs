// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One atomic writer for current surface state and retained signed history.
use super::{Carrier, StoredSurface, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::SurfaceState;
use serde_json::json;
impl RamfluxClient {
    pub(super) fn persist_surface_state(
        &self,
        carrier: &Carrier,
        state: &SurfaceState,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let reference = carrier.surface_reference()?;
        let previous = self.surface_state_ref(&reference)?;
        let created_at = previous.as_ref().and_then(|(r, _)| r.created_at).or(carrier.posted_at);
        let updated_at =
            carrier.updated_at.or_else(|| previous.as_ref().and_then(|(r, _)| r.updated_at));
        let author_device = previous.map_or_else(
            || {
                carrier.snapshot.as_ref().map_or_else(
                    || carrier.sender_device_id.clone(),
                    |proof| proof.author_device_id.clone(),
                )
            },
            |(record, _)| record.author_device_id,
        );
        if db
            .load_actor_state::<u64>(&key("out_of_sync", &reference))?
            .is_some_and(|missing| state.version() >= missing)
        {
            db.delete_surface_state(&key("out_of_sync", &reference))?;
        }
        let record = StoredSurface {
            created_at,
            updated_at,
            surface_id: carrier.surface_id.clone(),
            conversation_id: carrier.conversation_id.clone(),
            author_principal_id: carrier.author_principal_id.clone(),
            author_device_id: author_device.clone(),
            checkpoint_base64: ramflux_protocol::encode_base64url(
                state.checkpoint_bytes().map_err(|_| invalid("surface checkpoint failed"))?,
            ),
        };
        db.persist_actor_state(&key("state", &reference), &record)?;
        let prefix = key("history", &reference) + "/";
        let history = format!("{prefix}{:020}", state.version());
        db.persist_actor_state(&history,&json!({"version":state.version(),"surface_hash":state.hash(),"carrier":carrier,"message_id":carrier.message_id}))?;
        db.prune_surface_records(&prefix, 256, 4 * 1024 * 1024, &history)?;
        let executor = self.device_branch.as_ref().is_some_and(|local| {
            local.principal_id == carrier.author_principal_id && local.device_id == author_device
        });
        db.persist_client_record("surface",&reference,&json!({"created_at":created_at,"posted_at":created_at,"updated_at":updated_at,"streams":state.stream_states(),"id":reference,"surface_ref":reference,"surface_id":carrier.surface_id,"conversation_id":carrier.conversation_id,"author_principal_id":carrier.author_principal_id,"author_device_id":author_device,"executor_device_id":author_device,"is_action_executor":executor,"out_of_sync":self.surface_is_out_of_sync(&reference)?,"version":state.version(),"surface_hash":state.hash(),"closed":state.is_closed(),"fallback_text":state.content().ok_or_else(||invalid("surface content absent"))?.fallback_text,"renderer_error":null}))?;
        Ok(())
    }
    pub(super) fn bootstrap_owned_surface(&self, carrier: &Carrier) -> Result<(), SdkError> {
        let Some(proof) = carrier.snapshot.as_ref().filter(|proof| proof.is_full()) else {
            return Ok(());
        };
        let version = match carrier.payload()? {
            super::Payload::Event(event) => event.version(),
            super::Payload::ActionReceipt { action, .. } => action.version(),
            super::Payload::Action(_) => return Ok(()),
        };
        let previous = self
            .surface_state_ref(&carrier.surface_reference()?)?
            .map_or_else(SurfaceState::default, |(_, s)| s);
        if previous.version() >= version {
            return Ok(());
        }
        let state = self
            .restore_surface_proof(carrier, &previous, version)?
            .ok_or_else(|| invalid("own-device full-state proof missing"))?;
        if proof.author_device_id.is_empty() {
            return Err(invalid("own-device executor missing"));
        }
        self.account_db()?
            .persist_actor_state(&key("snapshot_floor", &carrier.surface_reference()?), &version)?;
        self.account_db()?
            .delete_surface_state(&key("out_of_sync", &carrier.surface_reference()?))?;
        self.persist_surface_state(carrier, &state)
    }
}
