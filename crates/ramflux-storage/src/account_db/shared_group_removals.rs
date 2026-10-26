// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiver-owned removal floors survive snapshot pruning and creator branch switches.
use super::AccountDb;
use crate::StorageError;
use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::{GroupStateLimit, ProtocolError, SharedGroupState};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Default, Deserialize, Serialize)]
struct Floors {
    roots: BTreeMap<String, u64>,
    devices: Vec<DeviceFloor>,
}
#[derive(Deserialize, Serialize)]
struct DeviceFloor {
    root: String,
    device: String,
    epoch: u64,
}
fn key(group: &str) -> String {
    format!("group-state/removal-floors/{}", ramflux_protocol::encode_base64url(group))
}
impl AccountDb {
    fn shared_group_removal_floors(&self, group: &str) -> Result<Floors, StorageError> {
        if let Some(floors) = self.load_actor_state(&key(group))? {
            return Ok(floors);
        }
        let mut floors = Floors::default();
        if let Some(previous) = self.shared_group_state(group)? {
            floors.observe(previous.view());
            // Upgrade persisted shared groups, including removals whose wire exclusion expired.
            let mut query = self.connection.prepare("SELECT principal_commitment,max(removed_epoch) FROM group_member_projection WHERE group_id=?1 AND active=0 AND removed_epoch IS NOT NULL AND member_principal_id LIKE 'root~%' GROUP BY principal_commitment")?;
            for row in query.query_map(params![group], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })? {
                let (root, epoch) = row?;
                if !has_root(previous.view(), &root) {
                    floors
                        .roots
                        .entry(root)
                        .and_modify(|old| *old = (*old).max(epoch))
                        .or_insert(epoch);
                }
            }
        }
        Ok(floors)
    }
    /// Check receiver-pinned exclusions before allowing any replacement snapshot.
    /// # Errors
    /// Refuses implicit re-admission, or returns database/decoding failures.
    pub fn validate_shared_group_removal_continuity(
        &self,
        candidate: &VerifiedGroupState,
    ) -> Result<(), StorageError> {
        let floors = self.shared_group_removal_floors(&candidate.view().group_id)?;
        floors.check(candidate.view())
    }
    pub(super) fn record_shared_group_removal_continuity(
        &self,
        candidate: &VerifiedGroupState,
    ) -> Result<(), StorageError> {
        let state = candidate.view();
        let mut floors = self.shared_group_removal_floors(&state.group_id)?;
        floors.check(state)?;
        if let Some(previous) = self.shared_group_state(&state.group_id)? {
            for member in &previous.view().members {
                let root = &member.identity.root_commitment;
                if !has_root(state, root) {
                    let epoch = state
                        .excluded
                        .iter()
                        .filter(|e| e.root_commitment == *root)
                        .map(|e| e.removed_epoch)
                        .max()
                        .unwrap_or(state.epoch);
                    floors
                        .roots
                        .entry(root.clone())
                        .and_modify(|old| *old = (*old).max(epoch))
                        .or_insert(epoch);
                }
            }
        }
        floors.observe(state);
        if floors.roots.len() + floors.devices.len()
            > ramflux_protocol::group_state::MAX_GROUP_STATE_EXCLUSIONS * 2
        {
            return Err(ProtocolError::GroupStateLimit(GroupStateLimit::RemovalFences).into());
        }
        self.persist_actor_state(&key(&state.group_id), &floors)?;
        Ok(())
    }
}
fn has_root(state: &SharedGroupState, root: &str) -> bool {
    state.members.iter().any(|m| m.identity.root_commitment == root)
}
impl Floors {
    fn observe(&mut self, state: &SharedGroupState) {
        for removed in &state.excluded {
            if !has_root(state, &removed.root_commitment) {
                self.roots
                    .entry(removed.root_commitment.clone())
                    .and_modify(|old| *old = (*old).max(removed.removed_epoch))
                    .or_insert(removed.removed_epoch);
            }
            if let Some(old) = self
                .devices
                .iter_mut()
                .find(|old| old.root == removed.root_commitment && old.device == removed.device_id)
            {
                old.epoch = old.epoch.max(removed.removed_epoch);
            } else {
                self.devices.push(DeviceFloor {
                    root: removed.root_commitment.clone(),
                    device: removed.device_id.clone(),
                    epoch: removed.removed_epoch,
                });
            }
        }
    }
    fn check(&self, state: &SharedGroupState) -> Result<(), StorageError> {
        for (root, epoch) in &self.roots {
            if state
                .members
                .iter()
                .any(|m| m.identity.root_commitment == *root && m.joined_epoch <= *epoch)
            {
                return Err(ProtocolError::GroupTransferRequiresSync.into());
            }
        }
        for floor in &self.devices {
            if state.effective_role(&floor.root, &floor.device).is_none() {
                continue;
            }
            let members: Vec<_> =
                state.members.iter().filter(|m| m.identity.root_commitment == floor.root).collect();
            if !members
                .iter()
                .any(|m| m.identity.device_id == floor.device && m.joined_epoch > floor.epoch)
                && !members.iter().all(|m| m.joined_epoch > floor.epoch)
            {
                return Err(ProtocolError::GroupTransferRequiresSync.into());
            }
        }
        Ok(())
    }
}
