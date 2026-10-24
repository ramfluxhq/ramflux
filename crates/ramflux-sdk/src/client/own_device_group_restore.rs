// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Snapshot epoch admission and fail-closed restoration of independent group items.
use crate::own_device_sync::{SdkOwnDeviceGroupSnapshot, SdkOwnDeviceHistoryBundle};
use crate::prelude::*;
impl RamfluxClient {
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
                .max(db.group_member_joined_epoch(&group.group_id, local)?.unwrap_or(0));
            let role = if previous == Some(group.group_epoch) {
                db.group_member_role(&group.group_id, local)?
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
                if db.group_member_role(&group.group_id, &route.member_id)?.is_some() {
                    self.persist_group_member_route(&group.group_id, route)?;
                }
            }
            floors.insert(
                group.group_id.clone(),
                db.group_member_joined_epoch(&group.group_id, local)?
                    .unwrap_or(group.local_joined_epoch),
            );
        }
        Ok(floors)
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
                || db.group_member_role(&group.group_id, &member.member_id)?.is_none()
            {
                db.upsert_group_member_snapshot(
                    &group.group_id,
                    &member.member_id,
                    &member.role,
                    member.joined_epoch.max(
                        db.group_member_joined_epoch(&group.group_id, &member.member_id)?
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
        if latest.is_none_or(|g| !g.members.iter().any(|m| m.member_id == distribution.sender_id))
            || self.account_db()?.group_snapshot_epoch(&distribution.group_id)?
                != latest.map(|g| g.group_epoch)
            || blocked.contains(&(distribution.group_id.clone(), String::new()))
            || blocked.contains(&(distribution.group_id.clone(), distribution.sender_id.clone()))
            || self
                .account_db()?
                .group_member_role(&distribution.group_id, &distribution.sender_id)?
                .is_none()
        {
            self.account_db()?.record_own_device_restore_skip(
                &bundle.snapshot_id,
                &item,
                "distribution_member_unavailable",
            )?;
            return Ok(false);
        }
        match self
            .account_db()?
            .write_transaction(|| self.import_group_sender_key_distribution(&bytes))
        {
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
