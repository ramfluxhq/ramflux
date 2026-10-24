// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resolve group pins by root without changing literal membership slot names.
use super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
impl AccountDb {
    pub(super) fn group_pin_key(
        &self,
        group: &str,
        device: &str,
    ) -> Result<Option<String>, StorageError> {
        if let Some((root, raw)) = ramflux_protocol::parse_qualified_device_id(device)? {
            return Ok(self.connection.query_row("SELECT member_id FROM group_member_device_key WHERE group_id=?1 AND COALESCE(raw_device_id,member_id)=?3 AND principal_commitment=?4 ORDER BY member_id=?2 DESC LIMIT 1",params![group,device,raw,root],|row|row.get(0)).optional()?);
        }
        let mut query=self.connection.prepare("SELECT member_id FROM group_member_device_key WHERE group_id=?1 AND (member_id=?2 OR raw_device_id=?2) AND (principal_commitment IS NOT NULL OR NOT EXISTS(SELECT 1 FROM group_member_device_key bound WHERE bound.group_id=?1 AND COALESCE(bound.raw_device_id,bound.member_id)=?2 AND bound.principal_commitment IS NOT NULL)) LIMIT 2")?;
        let rows = query
            .query_map(params![group, device], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > 1 {
            return Err(StorageError::AmbiguousDeviceId(device.into()));
        }
        Ok(rows.into_iter().next())
    }
    pub(super) fn pin_address_for_write(
        device: &str,
    ) -> Result<(String, String, Option<String>), StorageError> {
        if let Some((root, raw)) = ramflux_protocol::parse_qualified_device_id(device)? {
            return Ok((device.into(), raw, Some(root)));
        }
        Ok((crate::schema_device_namespace::legacy_address(device), device.into(), None))
    }
}
