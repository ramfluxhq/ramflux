// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic projections of opaque verified group state and root-qualified member pins.
use super::AccountDb;
use crate::StorageError;
use ramflux_crypto::{
    GroupStateRelation, VerifiedGroupState, verify_group_state_actor, verify_group_state_snapshot,
};
use ramflux_protocol::group_state::{GroupMemberIdentity, GroupStateActor, GroupStateSnapshot};
use rusqlite::params;
use serde_json::json;

fn state_key(group: &str) -> String {
    format!("group-state/{}", ramflux_protocol::encode_base64url(group))
}
impl AccountDb {
    pub(super) fn ensure_legacy_group_writable(&self, group: &str) -> Result<(), StorageError> {
        if self.is_shared_group(group)? {
            return Err(StorageError::GroupPermissionDenied);
        }
        Ok(())
    }

    /// Load and reverify the persisted authority proof, never a deserialized role claim.
    /// # Errors
    /// Returns storage, serialization or proof verification errors.
    pub fn shared_group_state(
        &self,
        group: &str,
    ) -> Result<Option<VerifiedGroupState>, StorageError> {
        self.load_actor_state::<GroupStateSnapshot>(&state_key(group))?
            .map(verify_group_state_snapshot)
            .transpose()
            .map_err(Into::into)
    }
    /// Commit a full state and all membership, pin and name projections in one transaction.
    /// The caller separately authenticates transport and the local account root.
    /// # Errors
    /// Rejects forks, rollback, mismatched pins, conflicting conversation links and invalid local certificates.
    pub fn commit_shared_group_state(
        &self,
        verified: &VerifiedGroupState,
        local: &GroupStateActor,
    ) -> Result<bool, StorageError> {
        verify_group_state_actor(local)?;
        self.write_transaction(|| {
            let state = verified.view();
            let previous = self.shared_group_state(&state.group_id)?;
            let changed = previous.as_ref().is_none_or(|old| state != old.view());
            if let Some(previous) = previous {
                if verified.snapshot().checkpoint.as_ref().is_some_and(|checkpoint|
                    checkpoint.owner.identity.root_commitment != checkpoint.genesis.actor.identity.root_commitment
                    && checkpoint.authority.as_ref().map_or(0, |authority| authority.epoch)
                        < previous.snapshot().checkpoint.as_ref().and_then(|old| old.authority.as_ref()).map_or(0, |authority| authority.epoch)) {
                    return Err(StorageError::GroupPermissionDenied);
                }
                match verified.relation_to(&previous)? {
                    GroupStateRelation::Ancestor | GroupStateRelation::ExistingPreferred => return Ok(false),
                    GroupStateRelation::Same | GroupStateRelation::Extension | GroupStateRelation::IncomingPreferred => {}
                    GroupStateRelation::Unrelated => return Err(StorageError::GroupPermissionDenied),
                }
            } else if self.group_snapshot_epoch(&state.group_id)?.is_some() {
                // An unsolicited full-state proof cannot take over a legacy group with the same id.
                return Err(StorageError::GroupPermissionDenied);
            }
            let now = self.now_unix();
            let role = state.effective_role(&local.identity.root_commitment, &local.identity.device_id);
            self.connection.execute("INSERT INTO group_projection (group_id,group_epoch,role,max_members,new_member_history,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?6) ON CONFLICT(group_id) DO UPDATE SET group_epoch=excluded.group_epoch,role=excluded.role,max_members=excluded.max_members,new_member_history=excluded.new_member_history,updated_at=excluded.updated_at",params![state.group_id,state.epoch,role.map(ramflux_protocol::SharedGroupRole::as_str),state.max_members,state.new_member_history,now])?;
            self.connection.execute("UPDATE group_member_projection SET active=0,removed_epoch=?2,updated_at=?3 WHERE group_id=?1 AND active=1",params![state.group_id,state.epoch,now])?;
            self.connection.execute("UPDATE shared_group_member_projection SET active=0 WHERE group_id=?1",params![state.group_id])?;
            for member in &state.members {
                self.project_shared_group_member(verified, &member.identity, member.joined_epoch)?;
            }
            if role.is_some() && !state.members.iter().any(|member| {
                member.identity.root_commitment == local.identity.root_commitment
                    && member.identity.device_id == local.identity.device_id
            }) {
                let joined = state.members.iter()
                    .filter(|member| member.identity.root_commitment == local.identity.root_commitment)
                    .map(|member| member.joined_epoch).min().ok_or(StorageError::GroupPermissionDenied)?;
                self.project_shared_group_member(verified, &local.identity, joined)?;
            }
            self.persist_client_record("group-local", &state.group_id, &json!(local.identity))?;
            self.project_shared_group_link(verified)?;
            self.persist_actor_state(&state_key(&state.group_id), verified.snapshot())?;
            self.persist_client_record("group-name", &state.group_id,
                &json!({"name":state.name,"name_epoch":state.name_epoch}))?;
            Ok(changed)
        })
    }
    pub(super) fn project_shared_group_member(
        &self,
        verified: &VerifiedGroupState,
        identity: &GroupMemberIdentity,
        joined: u64,
    ) -> Result<(), StorageError> {
        let state = verified.view();
        let id =
            verified.member_storage_key(identity)?.ok_or(StorageError::GroupPermissionDenied)?;
        let role = state
            .effective_role(&identity.root_commitment, &identity.device_id)
            .ok_or(StorageError::GroupPermissionDenied)?;
        // This is a group-authorized declaration, not a device-set authentication result.
        // Key consumers must supply a RootQualifiedDeviceRef and verify its current manifest.
        self.connection.execute("INSERT INTO group_member_projection (group_id,member_principal_id,member_id,principal_commitment,role,joined_epoch,active,updated_at) VALUES (?1,?2,?2,?3,?4,?5,1,?6) ON CONFLICT(group_id,member_principal_id) DO UPDATE SET principal_commitment=excluded.principal_commitment,role=excluded.role,joined_epoch=excluded.joined_epoch,active=1,removed_epoch=NULL,updated_at=excluded.updated_at",params![state.group_id,id,identity.root_commitment,role.as_str(),joined,self.now_unix()])?;
        self.connection.execute("INSERT INTO shared_group_member_projection(group_id,root_commitment,device_id,principal_id,declared_signing_key,current_signing_key,target_delivery_id,role,joined_epoch,active) VALUES(?1,?2,?3,?4,?5,?5,?6,?7,?8,1) ON CONFLICT(group_id,root_commitment,device_id) DO UPDATE SET principal_id=excluded.principal_id,current_signing_key=CASE WHEN declared_signing_key=excluded.declared_signing_key THEN current_signing_key ELSE excluded.current_signing_key END,declared_signing_key=excluded.declared_signing_key,target_delivery_id=excluded.target_delivery_id,role=excluded.role,joined_epoch=excluded.joined_epoch,active=1",params![state.group_id,identity.root_commitment,identity.device_id,identity.principal_id,identity.signing_public_key,identity.target_delivery_id,role.as_str(),joined])?;
        Ok(())
    }
    fn project_shared_group_link(&self, verified: &VerifiedGroupState) -> Result<(), StorageError> {
        let state = verified.view();
        let mut conversation = self
            .client_record("conversation", &state.conversation_id)?
            .unwrap_or_else(|| json!({"participants":[],"direct_route":null}));
        if conversation.get("kind").is_some_and(|kind| kind != "group")
            || conversation
                .get("group_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|group| group != state.group_id)
        {
            return Err(StorageError::GroupPermissionDenied);
        }
        conversation["kind"] = json!("group");
        conversation["group_id"] = json!(state.group_id);
        if let Some(name) = &state.name {
            conversation["title"] = json!(name);
        }
        self.persist_client_record("conversation", &state.conversation_id, &conversation)?;
        let mut group = self.client_record("group", &state.group_id)?.unwrap_or_else(|| json!({}));
        let mut links = group["conversation_ids"].as_array().cloned().unwrap_or_default();
        if !links.contains(&json!(state.conversation_id)) {
            links.push(json!(state.conversation_id));
        }
        group["conversation_id"] =
            if links.len() == 1 { json!(state.conversation_id) } else { serde_json::Value::Null };
        group["conversation_ids"] = json!(links);
        self.persist_client_record("group", &state.group_id, &group)?;
        Ok(())
    }
}
