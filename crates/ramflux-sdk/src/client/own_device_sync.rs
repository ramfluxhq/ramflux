// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

mod pairing;
impl RamfluxClient {
    pub(crate) fn own_device_group_snapshots(
        &self,
        source_device_id: &str,
    ) -> Result<Vec<SdkOwnDeviceGroupSnapshot>, SdkError> {
        self.groups()?
            .into_iter()
            .filter_map(|group| {
                self.own_device_group_snapshot(&group.group_id, source_device_id).transpose()
            })
            .collect()
    }
    pub(crate) fn own_device_group_snapshot(
        &self,
        id: &str,
        source_device_id: &str,
    ) -> Result<Option<SdkOwnDeviceGroupSnapshot>, SdkError> {
        let source = self.local_device_identity(source_device_id)?;
        if let Some(state) = self.account_db()?.shared_group_state(id)? {
            let Some(role) =
                state.view().effective_role(source.root_commitment(), source.device_id())
            else {
                return Ok(None);
            };
            let joined = self
                .account_db()?
                .group_member_joined_epoch(id, &source)?
                .ok_or(StorageError::GroupPermissionDenied)?;
            return Ok(Some(SdkOwnDeviceGroupSnapshot {
                shared_state: Some(state.snapshot().clone()),
                group_id: id.into(),
                group_epoch: state.view().epoch,
                max_members: state.view().max_members,
                new_member_history: state.view().new_member_history.clone(),
                local_role: role.as_str().into(),
                local_joined_epoch: joined,
                members: state
                    .view()
                    .members
                    .iter()
                    .map(|m| SdkOwnDeviceGroupMemberSnapshot {
                        member_id: m.identity.device_id.clone(),
                        role: m.role.as_str().into(),
                        joined_epoch: m.joined_epoch,
                    })
                    .collect(),
                routes: Vec::new(),
            }));
        }
        let group = self.group_state(id)?;
        let Some(role) = group.roles.get(source.device_id()).cloned() else { return Ok(None) };
        let Some(joined_epoch) =
            self.account_db()?.group_member_joined_epoch_metadata(id, source.device_id())?
        else {
            return Ok(None);
        };
        let mut members = Vec::with_capacity(group.members.len());
        for member in &group.members {
            if let Some(role) = group.roles.get(member).cloned()
                && let Some(joined_epoch) =
                    self.account_db()?.group_member_joined_epoch_metadata(id, member)?
            {
                members.push(SdkOwnDeviceGroupMemberSnapshot {
                    member_id: member.clone(),
                    role,
                    joined_epoch,
                });
            }
        }
        Ok(Some(SdkOwnDeviceGroupSnapshot {
            shared_state: self
                .account_db()?
                .shared_group_state(id)?
                .map(|state| state.snapshot().clone()),
            group_id: id.into(),
            group_epoch: group.group_epoch,
            max_members: group.max_members,
            new_member_history: group.new_member_history,
            local_role: role,
            local_joined_epoch: joined_epoch,
            members,
            routes: self.group_member_routes(id)?,
        }))
    }
}
