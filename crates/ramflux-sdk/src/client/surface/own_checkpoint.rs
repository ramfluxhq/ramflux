// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private validated-state replication inside an authenticated same-root history bundle.
//! This is account-owned persistence, never a substitute for peer event authentication.
use super::{StoredSurface, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{A2uiConversationEvent, SurfaceState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OwnedSurfaceCheckpoint {
    pub(super) record: StoredSurface,
    snapshot_wire_base64: String,
    pub(super) version: u64,
    surface_hash: String,
    pub(super) conversation: Value,
    pub(super) group_epoch: Option<u64>,
}
impl RamfluxClient {
    pub(super) fn export_owned_surface_checkpoint(
        &self,
        reference: &str,
    ) -> Result<OwnedSurfaceCheckpoint, SdkError> {
        let (record, state) = self
            .surface_state_ref(reference)?
            .ok_or_else(|| invalid("surface has no validated checkpoint"))?;
        let conversation = self
            .account_db()?
            .client_record("conversation", &record.conversation_id)?
            .ok_or_else(|| invalid("surface conversation missing"))?;
        let epoch = self.account_db()?.load_actor_state::<u64>(&key("group_epoch", reference))?;
        self.check_owned_surface_floor(&conversation, epoch)?;
        let command = ramflux_protocol::A2uiConversationCommand::CreateSurface(
            state.content().ok_or_else(|| invalid("surface content missing"))?.clone(),
        );
        let wire = ramflux_protocol::encode_a2ui_conversation_event(
            &record.conversation_id,
            state.version(),
            &command,
        )?;
        Ok(OwnedSurfaceCheckpoint {
            record,
            snapshot_wire_base64: ramflux_protocol::encode_base64url(wire),
            version: state.version(),
            surface_hash: state.hash().ok_or_else(|| invalid("surface hash missing"))?.into(),
            conversation,
            group_epoch: epoch,
        })
    }
    fn check_owned_surface_floor(
        &self,
        conversation: &Value,
        epoch: Option<u64>,
    ) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if let Some(group) = conversation["group_id"].as_str() {
            let floor = self.account_db()?.group_member_joined_epoch(group, &local.device_id)?;
            if !self.group_state(group)?.roles.contains_key(&local.device_id)
                || floor.is_none_or(|f| epoch.is_none_or(|e| e < f))
            {
                return Err(invalid("surface is below the own-device membership floor"));
            }
        } else if conversation["kind"] != "direct"
            || !conversation["participants"]
                .as_array()
                .is_some_and(|ids| ids.len() == 2 && ids.iter().any(|id| id == &local.principal_id))
        {
            return Err(invalid("owned surface direct context mismatch"));
        }
        Ok(())
    }
    /// Only call after the enclosing own-device history envelope authenticated its same-root source.
    pub(crate) fn import_owned_surface_checkpoints(
        &self,
        checkpoints: &[OwnedSurfaceCheckpoint],
    ) -> Result<(), SdkError> {
        if checkpoints.len() > 64 || serde_json::to_vec(checkpoints)?.len() > 8 * 1024 * 1024 {
            return Err(invalid("owned surface checkpoint budget exceeded"));
        }
        for owned in checkpoints {
            if let Err(error) = self
                .account_db()?
                .surface_transaction(|| self.import_owned_surface_checkpoint(owned))
            {
                let reference = super::scope::surface_reference(
                    &owned.record.conversation_id,
                    &owned.record.author_principal_id,
                    &owned.record.surface_id,
                )?;
                self.account_db()?.persist_actor_state(
                    &key("import_skip", &reference),
                    &json!({"reason":error.to_string(),"version":owned.version}),
                )?;
                self.account_db()?
                    .persist_actor_state(&key("out_of_sync", &reference), &owned.version)?;
                if let Some(mut view) = self.account_db()?.client_record("surface", &reference)? {
                    view["out_of_sync"] = json!(true);
                    self.account_db()?.persist_client_record("surface", &reference, &view)?;
                }
            }
        }
        Ok(())
    }
    fn import_owned_surface_checkpoint(
        &self,
        owned: &OwnedSurfaceCheckpoint,
    ) -> Result<(), SdkError> {
        self.check_owned_surface_floor(&owned.conversation, owned.group_epoch)?;
        let record = &owned.record;
        let reference = super::scope::surface_reference(
            &record.conversation_id,
            &record.author_principal_id,
            &record.surface_id,
        )?;
        let previous = self.surface_state_ref(&reference)?;
        if previous.as_ref().is_some_and(|(old, _)| old.author_device_id != record.author_device_id)
        {
            return Err(SdkError::SurfaceCheckpointMismatch);
        }
        if previous.as_ref().is_some_and(|(_, state)| state.version() > owned.version) {
            return Ok(());
        }
        let wire = ramflux_protocol::decode_base64url(&owned.snapshot_wire_base64)
            .map_err(|_| SdkError::SurfaceCheckpointMismatch)?;
        let event = A2uiConversationEvent::from_wire_bytes(&wire)?;
        let bytes = ramflux_protocol::decode_base64url(&record.checkpoint_base64)
            .map_err(|_| SdkError::SurfaceCheckpointMismatch)?;
        let repeated = previous.as_ref().is_some_and(|(_, state)| state.version() == owned.version);
        let prior = previous.map_or_else(SurfaceState::default, |(_, state)| state);
        let state =
            prior.resynchronize(&event, &bytes).map_err(|_| SdkError::SurfaceCheckpointMismatch)?;
        if state.version() != owned.version
            || state.hash() != Some(owned.surface_hash.as_str())
            || state.conversation_id() != Some(record.conversation_id.as_str())
            || state.content().is_none_or(|content| content.surface_id != record.surface_id)
        {
            return Err(SdkError::SurfaceCheckpointMismatch);
        }
        if repeated {
            return Ok(());
        }
        let db = self.account_db()?;
        if let Some(existing) = db.client_record("conversation", &record.conversation_id)? {
            if existing["kind"] != owned.conversation["kind"]
                || existing["group_id"] != owned.conversation["group_id"]
            {
                return Err(invalid("owned checkpoint conversation conflict"));
            }
        } else {
            db.persist_client_record("conversation", &record.conversation_id, &owned.conversation)?;
        }
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        db.persist_actor_state(&key("state", &reference), record)?;
        db.persist_actor_state(&key("snapshot_floor", &reference), &owned.version)?;
        db.delete_surface_state(&key("out_of_sync", &reference))?;
        db.persist_client_record("surface",&reference,&json!({"id":reference,"surface_ref":reference,"surface_id":record.surface_id,"conversation_id":record.conversation_id,"author_principal_id":record.author_principal_id,"author_device_id":record.author_device_id,"executor_device_id":record.author_device_id,"is_action_executor":record.author_principal_id==local.principal_id && record.author_device_id==local.device_id,"version":state.version(),"surface_hash":state.hash(),"closed":state.is_closed(),"fallback_text":state.content().ok_or_else(||invalid("surface content missing"))?.fallback_text,"out_of_sync":false,"renderer_error":null}))?;
        if let Some(epoch) = owned.group_epoch {
            db.persist_actor_state(&key("group_epoch", &reference), &epoch)?;
        }
        let prefix = key("history", &reference) + "/";
        let history = format!("{prefix}{:020}", state.version());
        db.persist_actor_state(
            &history,
            &json!({"version":state.version(),"surface_hash":state.hash(),"owned_checkpoint":true}),
        )?;
        db.prune_surface_records(&prefix, 256, 4 * 1024 * 1024, &history)?;
        self.drain_surface_pending(&reference)?;
        Ok(())
    }
}
