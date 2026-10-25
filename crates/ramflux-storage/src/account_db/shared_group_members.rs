// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-qualified access to projected group declarations; no raw device identity constructors.
use super::AccountDb;
use crate::{GroupMemberKeyBinding, StorageError};
use ramflux_crypto::RootQualifiedDeviceRef;
use rusqlite::{OptionalExtension, params};

impl AccountDb {
    pub(super) fn is_shared_group(&self, group: &str) -> Result<bool, StorageError> {
        self.actor_state_exists(&format!(
            "group-state/{}",
            ramflux_protocol::encode_base64url(group)
        ))
    }
    pub(super) fn shared_member_binding(
        &self,
        group: &str,
        device: &RootQualifiedDeviceRef,
    ) -> Result<Option<GroupMemberKeyBinding>, StorageError> {
        Ok(self.connection.query_row("SELECT current_signing_key,principal_id,root_commitment FROM shared_group_member_projection WHERE group_id=?1 AND root_commitment=?2 AND device_id=?3 AND active=1",params![group,device.root_commitment(),device.device_id()],|row|Ok(GroupMemberKeyBinding {signing_public_key:row.get(0)?,principal_id:Some(row.get(1)?),principal_commitment:Some(row.get(2)?)})).optional()?)
    }
    pub(super) fn shared_member_role(
        &self,
        group: &str,
        device: &RootQualifiedDeviceRef,
    ) -> Result<Option<String>, StorageError> {
        Ok(self.connection.query_row("SELECT role FROM shared_group_member_projection WHERE group_id=?1 AND root_commitment=?2 AND device_id=?3 AND active=1",params![group,device.root_commitment(),device.device_id()],|row|row.get(0)).optional()?)
    }
    pub(super) fn shared_member_joined_epoch(
        &self,
        group: &str,
        device: &RootQualifiedDeviceRef,
    ) -> Result<Option<u64>, StorageError> {
        Ok(self.connection.query_row("SELECT joined_epoch FROM shared_group_member_projection WHERE group_id=?1 AND root_commitment=?2 AND device_id=?3 AND active=1",params![group,device.root_commitment(),device.device_id()],|row|row.get(0)).optional()?)
    }
    pub(super) fn check_shared_member_key(
        &self,
        group: &str,
        device: &RootQualifiedDeviceRef,
        principal: Option<&str>,
        key: &str,
    ) -> Result<(), StorageError> {
        let binding = self
            .shared_member_binding(group, device)?
            .ok_or(StorageError::GroupPermissionDenied)?;
        if binding.signing_public_key != key
            || principal.is_some_and(|principal| binding.principal_id.as_deref() != Some(principal))
        {
            return Err(StorageError::GroupPermissionDenied);
        }
        Ok(())
    }
    pub(super) fn shared_member_metadata(
        &self,
        group: &str,
        name: &str,
    ) -> Result<Option<GroupMemberKeyBinding>, StorageError> {
        let mut query=self.connection.prepare("SELECT current_signing_key,principal_id,root_commitment FROM shared_group_member_projection WHERE group_id=?1 AND device_id=?2 AND active=1 LIMIT 2")?;
        let rows = query
            .query_map(params![group, name], |row| {
                Ok(GroupMemberKeyBinding {
                    signing_public_key: row.get(0)?,
                    principal_id: Some(row.get(1)?),
                    principal_commitment: Some(row.get(2)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > 1 {
            return Err(StorageError::AmbiguousDeviceId(name.into()));
        }
        Ok(rows.into_iter().next())
    }
    pub(super) fn shared_member_metadata_role_epoch(
        &self,
        group: &str,
        name: &str,
    ) -> Result<Option<(String, u64)>, StorageError> {
        let mut query=self.connection.prepare("SELECT role,joined_epoch FROM shared_group_member_projection WHERE group_id=?1 AND device_id=?2 AND active=1 LIMIT 2")?;
        let rows = query
            .query_map(params![group, name], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > 1 {
            return Err(StorageError::AmbiguousDeviceId(name.into()));
        }
        Ok(rows.into_iter().next())
    }
}
