// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiver-owned removal floors survive snapshot pruning and creator branch switches.
use super::AccountDb;
use crate::StorageError;
use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::{ProtocolError, SharedGroupState};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Default, Deserialize, Serialize)]
pub(super) struct Floors {
    pub(super) roots: BTreeMap<String, u64>,
    pub(super) devices: Vec<DeviceFloor>,
}
#[derive(Clone, Deserialize, Serialize)]
pub(super) struct DeviceFloor {
    pub(super) root: String,
    pub(super) device: String,
    pub(super) epoch: u64,
}
fn key(group: &str) -> String {
    format!("group-state/removal-floors/{}", ramflux_protocol::encode_base64url(group))
}
impl AccountDb {
    fn shared_group_removal_floors(&self, group: &str) -> Result<Floors, StorageError> {
        let owned_group = group.to_owned();
        if let Some(floors) =
            self.connection.call(move |db| Floors::load_index(db, "main", &owned_group))?
        {
            return Ok(floors);
        }
        if let Some(mut floors) = self.load_actor_state::<Floors>(&key(group))? {
            floors.prune();
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
    fn shared_group_candidate_floors(
        &self,
        state: &SharedGroupState,
    ) -> Result<Floors, StorageError> {
        let group = state.group_id.clone();
        let roots = serde_json::to_string(
            &state
                .members
                .iter()
                .map(|m| &m.identity.root_commitment)
                .collect::<std::collections::BTreeSet<_>>(),
        )?;
        if let Some(floors) = self
            .connection
            .call(move |db| Floors::load_matching_index(db, "main", &group, Some(&roots)))?
        {
            return Ok(floors);
        }
        self.shared_group_removal_floors(&state.group_id)
    }
    /// Reconstruct creator-authorized removals which a replacement branch would lose.
    /// # Errors
    /// Returns database or decoding failures; callers must separately verify creator authority.
    pub fn shared_group_removal_repairs(
        &self,
        candidate: &VerifiedGroupState,
    ) -> Result<Vec<ramflux_protocol::GroupStateChange>, StorageError> {
        let floors = self.shared_group_candidate_floors(candidate.view())?;
        Ok(floors.repairs(candidate.view()))
    }
    /// Check receiver-pinned exclusions before allowing any replacement snapshot.
    /// # Errors
    /// Refuses implicit re-admission, or returns database/decoding failures.
    pub fn validate_shared_group_removal_continuity(
        &self,
        candidate: &VerifiedGroupState,
    ) -> Result<(), StorageError> {
        let floors = self.shared_group_candidate_floors(candidate.view())?;
        floors.check(candidate.view())
    }
    pub(super) fn record_shared_group_removal_continuity(
        &self,
        candidate: &VerifiedGroupState,
    ) -> Result<(), StorageError> {
        let state = candidate.view();
        let mut floors = self.shared_group_removal_floors(&state.group_id)?;
        let previous_floors = floors.clone();
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
        floors.prune();
        // A legacy over-cap store can still rename or update existing fences.
        floors.check_capacity(previous_floors.len())?;
        let group = state.group_id.clone();
        self.connection.call(move |db| floors.store_index_delta(db, &group, &previous_floors))?;
        self.remove_actor_state(&key(&state.group_id))?;
        Ok(())
    }
}
fn has_root(state: &SharedGroupState, root: &str) -> bool {
    state.members.iter().any(|m| m.identity.root_commitment == root)
}
impl Floors {
    pub(super) fn remember_root(&mut self, root: String, epoch: u64) {
        self.roots.entry(root).and_modify(|old| *old = (*old).max(epoch)).or_insert(epoch);
    }
    pub(super) fn merge(&mut self, other: Self) {
        for (root, epoch) in other.roots {
            self.roots.entry(root).and_modify(|old| *old = (*old).max(epoch)).or_insert(epoch);
        }
        for floor in other.devices {
            if let Some(old) = self
                .devices
                .iter_mut()
                .find(|old| old.root == floor.root && old.device == floor.device)
            {
                old.epoch = old.epoch.max(floor.epoch);
            } else {
                self.devices.push(floor);
            }
        }
        self.prune();
    }

    pub(super) fn observe(&mut self, state: &SharedGroupState) {
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
    pub(super) fn check(&self, state: &SharedGroupState) -> Result<(), StorageError> {
        if !self.repairs(state).is_empty() {
            return Err(ProtocolError::GroupTransferRequiresSync.into());
        }
        Ok(())
    }
    fn repairs(&self, state: &SharedGroupState) -> Vec<ramflux_protocol::GroupStateChange> {
        let mut missing = std::collections::BTreeSet::new();
        for (root, epoch) in &self.roots {
            // A root fence can only be superseded by an explicit later re-add.
            if state
                .members
                .iter()
                .any(|m| m.identity.root_commitment == *root && m.joined_epoch <= *epoch)
            {
                for member in state.members.iter().filter(|m| m.identity.root_commitment == *root) {
                    missing.insert((root.clone(), member.identity.device_id.clone()));
                }
            }
        }
        for floor in &self.devices {
            let members: Vec<_> =
                state.members.iter().filter(|m| m.identity.root_commitment == floor.root).collect();
            if state.effective_role(&floor.root, &floor.device).is_some()
                && !members
                    .iter()
                    .any(|m| m.identity.device_id == floor.device && m.joined_epoch > floor.epoch)
                && !members.iter().all(|m| m.joined_epoch > floor.epoch)
            {
                missing.insert((floor.root.clone(), floor.device.clone()));
            }
        }
        missing
            .into_iter()
            .map(|(root_commitment, device_id)| ramflux_protocol::GroupStateChange::Remove {
                root_commitment,
                device_id,
            })
            .collect()
    }
}
