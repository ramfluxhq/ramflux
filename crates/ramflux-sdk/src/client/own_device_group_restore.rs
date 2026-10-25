// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Snapshot epoch admission and fail-closed restoration of independent group items.
use crate::own_device_sync::{SdkOwnDeviceGroupSnapshot, SdkOwnDeviceHistoryBundle};
use crate::prelude::*;
impl RamfluxClient {
    // History read-model eligibility only. This does not select a root or grant key authority.
    pub(super) fn own_history_group_member_name_present(
        &self,
        group: &str,
        name: &str,
    ) -> Result<bool, SdkError> {
        let Some(state) = self.account_db()?.shared_group_state(group)? else {
            return Ok(self.account_db()?.group_member_role_metadata(group, name)?.is_some());
        };
        if state.view().members.iter().any(|member| member.identity.device_id == name) {
            return Ok(true);
        }
        let roots = state
            .view()
            .members
            .iter()
            .map(|member| member.identity.root_commitment.as_str())
            .collect::<BTreeSet<_>>();
        for root in roots {
            if state.view().effective_role(root, name).is_some()
                && self.observed_device_set(root)?.is_some_and(|record| {
                    record.devices.iter().any(|device| {
                        device.device_id == name
                            && device.status == ramflux_protocol::DeviceSetStatus::Active
                    })
                })
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn restore_own_groups(
        &self,
        bundle: &SdkOwnDeviceHistoryBundle,
    ) -> Result<BTreeMap<String, u64>, SdkError> {
        let db = self.account_db()?;
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id;
        let mut newest = BTreeMap::<&str, &SdkOwnDeviceGroupSnapshot>::new();
        for group in &bundle.groups {
            let old = newest.entry(&group.group_id).or_insert(group);
            if old.group_epoch < group.group_epoch {
                *old = group;
            }
        }
        let mut conflicting = BTreeSet::new();
        for group in &bundle.groups {
            if let Some(latest) = newest.get(group.group_id.as_str())
                && latest.group_epoch == group.group_epoch
                && serde_json::to_vec(*latest)? != serde_json::to_vec(group)?
            {
                conflicting.insert(group.group_id.clone());
            }
        }
        let mut floors = BTreeMap::new();
        for group in newest.into_values() {
            if conflicting.contains(&group.group_id) {
                db.record_own_device_restore_skip(
                    &bundle.snapshot_id,
                    &group.group_id,
                    "conflicting_group_snapshot",
                )?;
                continue;
            }
            if let Some(snapshot) = &group.shared_state {
                if let Some(floor) =
                    self.restore_own_shared_group_checked(bundle, group, snapshot)?
                {
                    floors.insert(group.group_id.clone(), floor);
                }
                continue;
            }
            // A legacy own-device item cannot roll back authenticated shared authority.
            if db.shared_group_state(&group.group_id)?.is_some() {
                continue;
            }
            let previous = db.group_snapshot_epoch(&group.group_id)?;
            if previous.is_some_and(|epoch| epoch > group.group_epoch)
                || db.group_snapshot_member_removed(&group.group_id, local)?
            {
                db.record_own_device_restore_skip(
                    &bundle.snapshot_id,
                    &group.group_id,
                    "stale_or_removed_group",
                )?;
                continue;
            }
            if group.local_joined_epoch > group.group_epoch {
                db.record_own_device_restore_skip(
                    &bundle.snapshot_id,
                    &group.group_id,
                    "invalid_join_epoch",
                )?;
                continue;
            }
            let existing =
                if previous.is_some() { Some(self.group_state(&group.group_id)?) } else { None };
            let joined = group
                .local_joined_epoch
                .max(db.group_member_joined_epoch_metadata(&group.group_id, local)?.unwrap_or(0));
            let role = if previous == Some(group.group_epoch) {
                db.group_member_role_metadata(&group.group_id, local)?
                    .unwrap_or_else(|| group.local_role.clone())
            } else {
                group.local_role.clone()
            };
            db.upsert_group_local_membership_snapshot(
                &group.group_id,
                group.group_epoch,
                group.max_members,
                &group.new_member_history,
                local,
                &role,
                joined,
            )?;
            if let Some(state) =
                existing.filter(|_| previous.is_some_and(|epoch| epoch < group.group_epoch))
            {
                for member in state.members.iter().filter(|m| {
                    *m != local && !group.members.iter().any(|row| row.member_id == **m)
                }) {
                    db.retire_group_snapshot_member(&group.group_id, member, group.group_epoch)?;
                }
            }
            self.restore_own_group_members(bundle, group, previous)?;
            for route in &group.routes {
                if db.group_member_role_metadata(&group.group_id, &route.member_id)?.is_some() {
                    self.persist_group_member_route(&group.group_id, route)?;
                }
            }
            floors.insert(
                group.group_id.clone(),
                db.group_member_joined_epoch_metadata(&group.group_id, local)?
                    .unwrap_or(group.local_joined_epoch),
            );
        }
        Ok(floors)
    }
    fn restore_own_shared_group_checked(
        &self,
        bundle: &SdkOwnDeviceHistoryBundle,
        group: &SdkOwnDeviceGroupSnapshot,
        snapshot: &ramflux_protocol::group_state::GroupStateSnapshot,
    ) -> Result<Option<u64>, SdkError> {
        match self.restore_own_shared_group(group, snapshot) {
            Ok(floor) => Ok(floor),
            Err(SdkError::Storage(error))
                if !matches!(error, StorageError::GroupPermissionDenied) =>
            {
                Err(SdkError::Storage(error))
            }
            Err(_) => {
                self.account_db()?.record_own_device_restore_skip(
                    &bundle.snapshot_id,
                    &group.group_id,
                    "invalid_shared_group_snapshot",
                )?;
                Ok(None)
            }
        }
    }
    fn restore_own_shared_group(
        &self,
        group: &SdkOwnDeviceGroupSnapshot,
        snapshot: &ramflux_protocol::group_state::GroupStateSnapshot,
    ) -> Result<Option<u64>, SdkError> {
        let state = ramflux_crypto::verify_group_state_snapshot(snapshot.clone())?;
        if state.view().group_id != group.group_id || state.view().epoch != group.group_epoch {
            return Err(SdkError::InboundRejected("own group state header mismatch".into()));
        }
        let local = self.owned_device_identity()?;
        let db = self.account_db()?;
        if db.group_snapshot_epoch(&group.group_id)?.is_some_and(|epoch| epoch > state.view().epoch)
        {
            return Ok(None);
        }
        let target = db
            .client_record("device", local.storage_key())?
            .and_then(|record| record["target_delivery_id"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "own-device-history".into());
        // The enclosing history is authenticated to this owned account root. A removal fence
        // may be restored without first granting this device the membership it removes.
        db.commit_shared_group_state(&state, &self.owned_group_actor(&target)?)?;
        if state.view().effective_role(local.root_commitment(), local.device_id()).is_none() {
            return Ok(None);
        }
        Ok(db.group_member_joined_epoch(&group.group_id, &local)?)
    }
    fn restore_own_group_members(
        &self,
        bundle: &SdkOwnDeviceHistoryBundle,
        group: &SdkOwnDeviceGroupSnapshot,
        previous: Option<u64>,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for member in &group.members {
            if member.joined_epoch > group.group_epoch
                || db.group_snapshot_member_removed(&group.group_id, &member.member_id)?
            {
                db.record_own_device_restore_skip(
                    &bundle.snapshot_id,
                    &format!("{}:{}", group.group_id, member.member_id),
                    "removed_or_future_member",
                )?;
                continue;
            }
            if previous != Some(group.group_epoch)
                || db.group_member_role_metadata(&group.group_id, &member.member_id)?.is_none()
            {
                db.upsert_group_member_snapshot(
                    &group.group_id,
                    &member.member_id,
                    &member.role,
                    member.joined_epoch.max(
                        db.group_member_joined_epoch_metadata(&group.group_id, &member.member_id)?
                            .unwrap_or(0),
                    ),
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn restore_own_sender_key(
        &self,
        bundle: &SdkOwnDeviceHistoryBundle,
        encoded: &str,
        blocked: &BTreeSet<(String, String)>,
    ) -> Result<bool, SdkError> {
        let parsed = ramflux_protocol::decode_base64url(encoded).ok().and_then(|bytes| {
            serde_json::from_slice::<SdkGroupSenderKeyDistribution>(&bytes)
                .ok()
                .map(|distribution| (bytes, distribution))
        });
        let Some((bytes, distribution)) = parsed else {
            self.account_db()?.record_own_device_restore_skip(
                &bundle.snapshot_id,
                "distribution",
                "invalid_distribution",
            )?;
            return Ok(false);
        };
        let item = format!("{}:{}", distribution.group_id, distribution.sender_id);
        let latest = bundle
            .groups
            .iter()
            .filter(|g| g.group_id == distribution.group_id)
            .max_by_key(|g| g.group_epoch);
        let shared = self.account_db()?.shared_group_state(&distribution.group_id)?;
        let available = if let Some(state) = &shared {
            let own = self.owned_device_identity()?;
            distribution.sender_id == bundle.source_device_id
                && state
                    .view()
                    .effective_role(own.root_commitment(), &distribution.sender_id)
                    .is_some()
                && state.view().effective_role(own.root_commitment(), own.device_id()).is_some()
        } else {
            latest.is_some_and(|g| g.members.iter().any(|m| m.member_id == distribution.sender_id))
                && self
                    .account_db()?
                    .group_member_role_metadata(&distribution.group_id, &distribution.sender_id)?
                    .is_some()
        };
        if !available
            || self.account_db()?.group_snapshot_epoch(&distribution.group_id)?
                != latest.map(|g| g.group_epoch)
            || blocked.contains(&(distribution.group_id.clone(), String::new()))
            || blocked.contains(&(distribution.group_id.clone(), distribution.sender_id.clone()))
        {
            self.account_db()?.record_own_device_restore_skip(
                &bundle.snapshot_id,
                &item,
                "distribution_member_unavailable",
            )?;
            return Ok(false);
        }
        match self.account_db()?.write_transaction(|| {
            if shared.is_some() {
                let source = self.owned_account_device_identity(&distribution.sender_id)?;
                self.require_group_sender_pin(
                    &distribution.group_id,
                    &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id,
                    &source,
                )?;
                let checkpoint = group_sender_key_checkpoint_name(
                    &distribution.group_id,
                    &source,
                    distribution.group_key_epoch,
                    "recv",
                )?;
                if self.projection_checkpoint(&checkpoint)?.is_none() {
                    self.import_group_key_for_identity(&bytes, &source, false)?;
                }
                Ok(distribution.clone())
            } else {
                self.import_group_sender_key_distribution(&bytes)
            }
        }) {
            Ok(_) => Ok(true),
            Err(SdkError::Storage(error))
                if !matches!(error, StorageError::GroupPermissionDenied) =>
            {
                Err(SdkError::Storage(error))
            }
            Err(_) => {
                self.account_db()?.record_own_device_restore_skip(
                    &bundle.snapshot_id,
                    &item,
                    "distribution_rejected",
                )?;
                Ok(false)
            }
        }
    }
}
