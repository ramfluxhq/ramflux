// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore merge chooses signed group state atomically with its monotonic removal fences.
use super::{backup_database::BackupDatabase, shared_group_removals::Floors};
use crate::StorageError;
use ramflux_crypto::{GroupStateRelation, VerifiedGroupState};
use ramflux_protocol::{GroupMemberIdentity, GroupStateActor, GroupStateSnapshot};
use rusqlite::{OptionalExtension, params};
use serde_json::json;
use std::collections::BTreeMap;

pub(super) struct GroupMerge {
    state: VerifiedGroupState,
    floors: Floors,
    heads: Vec<serde_json::Value>,
}
impl BackupDatabase {
    fn group_backup_value<T: serde::de::DeserializeOwned>(
        &self,
        incoming: bool,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let table =
            if incoming { "incoming.runtime_actor_state" } else { "main.runtime_actor_state" };
        let bytes: Option<Vec<u8>> = self
            .db
            .query_row(
                &format!("SELECT state_json FROM {table} WHERE state_kind=?1"),
                params![key],
                |r| r.get(0),
            )
            .optional()?;
        bytes.map(|b| serde_json::from_slice(&b).map_err(Into::into)).transpose()
    }
    fn backup_shared_states(
        &self,
        incoming: bool,
    ) -> Result<BTreeMap<String, VerifiedGroupState>, StorageError> {
        let table =
            if incoming { "incoming.runtime_actor_state" } else { "main.runtime_actor_state" };
        let mut query=self.db.prepare(&format!("SELECT state_kind,state_json FROM {table} WHERE state_kind LIKE 'group-state/%' AND substr(state_kind,13) NOT LIKE '%/%'"))?;
        let mut states = BTreeMap::new();
        for row in query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))? {
            let (key, bytes) = row?;
            let state = ramflux_crypto::verify_group_state_snapshot(
                GroupStateSnapshot::from_wire_bytes(&bytes)?,
            )?;
            if key
                != format!(
                    "group-state/{}",
                    ramflux_protocol::encode_base64url(&state.view().group_id)
                )
            {
                return Err(StorageError::AuthorizationRejected);
            }
            states.insert(state.view().group_id.clone(), state);
        }
        Ok(states)
    }
    fn backup_group_floors(
        &self,
        incoming: bool,
        state: Option<&VerifiedGroupState>,
        key: &str,
    ) -> Result<Floors, StorageError> {
        if let Some(floors) = self.group_backup_value(incoming, key)? {
            return Ok(floors);
        }
        let mut floors = Floors::default();
        if let Some(state) = state {
            floors.observe(state.view());
            let database = if incoming { "incoming" } else { "main" };
            let mut query = self.db.prepare(&format!("SELECT principal_commitment,max(removed_epoch) FROM {database}.group_member_projection WHERE group_id=?1 AND active=0 AND removed_epoch IS NOT NULL AND member_principal_id LIKE 'root~%' GROUP BY principal_commitment"))?;
            for row in query.query_map(params![state.view().group_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?))
            })? {
                let (root, epoch) = row?;
                if !state.view().members.iter().any(|m| m.identity.root_commitment == root) {
                    floors.remember_root(root, epoch);
                }
            }
        }
        Ok(floors)
    }
    pub(super) fn select_backup_shared_groups(
        &self,
        local: Option<&GroupStateActor>,
    ) -> Result<Vec<GroupMerge>, StorageError> {
        let live = self.backup_shared_states(false)?;
        let incoming = self.backup_shared_states(true)?;
        if live.is_empty() && incoming.is_empty() {
            return Ok(Vec::new());
        }
        ramflux_crypto::verify_group_state_actor(
            local.ok_or(StorageError::AuthorizationRejected)?,
        )?;
        let mut groups = Vec::new();
        for group in live.keys().chain(incoming.keys()).collect::<std::collections::BTreeSet<_>>() {
            let a = live.get(group);
            let b = incoming.get(group);
            let chosen = match (a, b) {
                (Some(a), Some(b)) => {
                    if a.genesis() != b.genesis() {
                        return Err(StorageError::AuthorizationRejected);
                    }
                    match b.relation_to(a) {
                        Ok(
                            GroupStateRelation::Extension | GroupStateRelation::IncomingPreferred,
                        ) => b,
                        Ok(_)
                        | Err(ramflux_crypto::CryptoError::Protocol(
                            ramflux_protocol::ProtocolError::GroupTransferRequiresSync,
                        )) => a,
                        Err(error) => return Err(error.into()),
                    }
                }
                (Some(a), None) => a,
                (None, Some(b)) => b,
                (None, None) => return Err(StorageError::AuthorizationRejected),
            };
            let encoded = ramflux_protocol::encode_base64url(group);
            let floor_key = format!("group-state/removal-floors/{encoded}");
            let mut floors = Floors::default();
            for (source, state) in [(false, a), (true, b)] {
                floors.merge(self.backup_group_floors(source, state, &floor_key)?)?;
            }
            for state in [a, b].into_iter().flatten() {
                floors.observe(state.view());
            }
            floors.merge(Floors::default())?;
            floors.check(chosen.view())?;
            let head_key = format!("group-state/known-heads/{encoded}");
            let mut heads: Vec<serde_json::Value> = Vec::new();
            for source in [false, true] {
                for head in self
                    .group_backup_value::<Vec<serde_json::Value>>(source, &head_key)?
                    .unwrap_or_default()
                {
                    let epoch =
                        head["epoch"].as_u64().ok_or(StorageError::AuthorizationRejected)?;
                    let hash = head["hash"].as_str().ok_or(StorageError::AuthorizationRejected)?;
                    if epoch == 0
                        || epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
                        || ramflux_protocol::decode_base64url(hash)
                            .map_err(|_| StorageError::AuthorizationRejected)?
                            .len()
                            != 32
                    {
                        return Err(StorageError::AuthorizationRejected);
                    }
                    if !heads.contains(&head) {
                        heads.push(head);
                    }
                }
            }
            let current = json!({"epoch":chosen.view().epoch,"hash":chosen.snapshot().state_hash});
            heads.retain(|h| h != &current);
            heads.push(current);
            if heads.len() > 64 {
                heads.drain(..heads.len() - 64);
            }
            groups.push(GroupMerge { state: chosen.clone(), floors, heads });
        }
        Ok(groups)
    }
    pub(super) fn project_backup_shared_groups(
        &self,
        groups: &[GroupMerge],
        local: &GroupStateActor,
    ) -> Result<(), StorageError> {
        for group in groups {
            let state = group.state.view();
            let id = &state.group_id;
            let role =
                state.effective_role(&local.identity.root_commitment, &local.identity.device_id);
            self.db.execute("INSERT INTO group_projection(group_id,group_epoch,role,max_members,new_member_history,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,unixepoch(),unixepoch()) ON CONFLICT(group_id) DO UPDATE SET group_epoch=excluded.group_epoch,role=excluded.role,max_members=excluded.max_members,new_member_history=excluded.new_member_history,updated_at=excluded.updated_at",params![id,state.epoch,role.map(ramflux_protocol::SharedGroupRole::as_str),state.max_members,state.new_member_history])?;
            self.db.execute(
                "UPDATE group_member_projection SET active=0,removed_epoch=?2 WHERE group_id=?1 AND active=1",
                params![id, state.epoch],
            )?;
            self.db.execute(
                "UPDATE shared_group_member_projection SET active=0 WHERE group_id=?1",
                params![id],
            )?;
            for member in &state.members {
                self.project_backup_group_member(
                    &group.state,
                    &member.identity,
                    member.joined_epoch,
                )?;
            }
            if role.is_some()
                && !state.members.iter().any(|m| {
                    m.identity.root_commitment == local.identity.root_commitment
                        && m.identity.device_id == local.identity.device_id
                })
            {
                let joined = state
                    .members
                    .iter()
                    .filter(|m| m.identity.root_commitment == local.identity.root_commitment)
                    .map(|m| m.joined_epoch)
                    .min()
                    .ok_or(StorageError::AuthorizationRejected)?;
                self.project_backup_group_member(&group.state, &local.identity, joined)?;
            }
            let encoded = ramflux_protocol::encode_base64url(id);
            self.put_state(&format!("group-state/{encoded}"), group.state.snapshot())?;
            self.put_state(&format!("group-state/removal-floors/{encoded}"), &group.floors)?;
            self.put_state(&format!("group-state/known-heads/{encoded}"), &group.heads)?;
            self.put_state(&format!("directory/group-local/{id}"), &local.identity)?;
            self.put_state(
                &format!("directory/group-name/{id}"),
                &json!({"name":state.name,"name_epoch":state.name_epoch}),
            )?;
            let key = format!("directory/conversation/{}", state.conversation_id);
            let mut conversation = self
                .group_backup_value::<serde_json::Value>(false, &key)?
                .unwrap_or_else(|| json!({"participants":[],"direct_route":null}));
            if conversation.get("kind").is_some_and(|v| v != "group")
                || conversation
                    .get("group_id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|v| v != id)
            {
                return Err(StorageError::AuthorizationRejected);
            }
            conversation["kind"] = json!("group");
            conversation["group_id"] = json!(id);
            if let Some(name) = &state.name {
                conversation["title"] = json!(name);
            }
            self.put_state(&key, &conversation)?;
            let group_key = format!("directory/group/{id}");
            let mut directory = self
                .group_backup_value::<serde_json::Value>(false, &group_key)?
                .unwrap_or_else(|| json!({}));
            let mut links = directory["conversation_ids"].as_array().cloned().unwrap_or_default();
            if !links.contains(&json!(state.conversation_id)) {
                links.push(json!(state.conversation_id));
            }
            directory["conversation_id"] = if links.len() == 1 {
                json!(state.conversation_id)
            } else {
                serde_json::Value::Null
            };
            directory["conversation_ids"] = json!(links);
            self.put_state(&group_key, &directory)?;
        }
        Ok(())
    }
    fn project_backup_group_member(
        &self,
        verified: &VerifiedGroupState,
        identity: &GroupMemberIdentity,
        joined: u64,
    ) -> Result<(), StorageError> {
        let state = verified.view();
        let key =
            verified.member_storage_key(identity)?.ok_or(StorageError::AuthorizationRejected)?;
        let role = state
            .effective_role(&identity.root_commitment, &identity.device_id)
            .ok_or(StorageError::AuthorizationRejected)?;
        self.db.execute("INSERT INTO group_member_projection(group_id,member_principal_id,member_id,principal_commitment,role,joined_epoch,active,updated_at) VALUES(?1,?2,?2,?3,?4,?5,1,unixepoch()) ON CONFLICT(group_id,member_principal_id) DO UPDATE SET principal_commitment=excluded.principal_commitment,role=excluded.role,joined_epoch=excluded.joined_epoch,active=1,removed_epoch=NULL,updated_at=excluded.updated_at",params![state.group_id,key,identity.root_commitment,role.as_str(),joined])?;
        self.db.execute("INSERT INTO shared_group_member_projection(group_id,root_commitment,device_id,principal_id,declared_signing_key,current_signing_key,target_delivery_id,role,joined_epoch,active) VALUES(?1,?2,?3,?4,?5,?5,?6,?7,?8,1) ON CONFLICT(group_id,root_commitment,device_id) DO UPDATE SET principal_id=excluded.principal_id,current_signing_key=CASE WHEN declared_signing_key=excluded.declared_signing_key THEN current_signing_key ELSE excluded.current_signing_key END,declared_signing_key=excluded.declared_signing_key,target_delivery_id=excluded.target_delivery_id,role=excluded.role,joined_epoch=excluded.joined_epoch,active=1",params![state.group_id,identity.root_commitment,identity.device_id,identity.principal_id,identity.signing_public_key,identity.target_delivery_id,role.as_str(),joined])?;
        Ok(())
    }
}
