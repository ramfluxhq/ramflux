// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resolve a membership pin only when its retained root matches an authenticated device.
use super::AccountDb;
use crate::StorageError;
use ramflux_crypto::RootQualifiedDeviceRef;
use rusqlite::{OptionalExtension, params};
impl AccountDb {
    pub(super) fn group_pin_key(
        &self,
        group: &str,
        device: &RootQualifiedDeviceRef,
    ) -> Result<Option<String>, StorageError> {
        // A known-root historical row may still use a literal primary key. NULL-root pins
        // cannot satisfy this lookup and require explicit member re-addition.
        Ok(self.connection.query_row("SELECT member_id FROM group_member_device_key WHERE group_id=?1 AND COALESCE(raw_device_id,member_id)=?3 AND principal_commitment=?4 ORDER BY member_id=?2 DESC LIMIT 1",params![group,device.storage_key(),device.device_id(),device.root_commitment()],|row|row.get(0)).optional()?)
    }
    /// Whether an unbound historical pin prevents this authenticated member's admission.
    /// # Errors
    /// Returns SQL errors. This check can only deny admission, never select a pin or key.
    pub fn group_member_requires_readd(
        &self,
        group: &str,
        device: &RootQualifiedDeviceRef,
    ) -> Result<bool, StorageError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=COALESCE(k.raw_device_id,k.member_id) WHERE k.group_id=?1 AND COALESCE(k.raw_device_id,k.member_id)=?2 AND k.principal_commitment IS NULL AND m.active=1)",params![group,device.device_id()],|row|row.get(0))?)
    }
    pub(super) fn legacy_archive_group_pin(
        &self,
        group: &str,
        name: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS legacy_group_member_device_key AS SELECT * FROM group_member_device_key WHERE 0")?;
        self.connection.execute("INSERT INTO legacy_group_member_device_key SELECT * FROM group_member_device_key WHERE group_id=?1 AND COALESCE(raw_device_id,member_id)=?2 AND principal_commitment IS NULL",params![group,name])?;
        self.connection.execute("DELETE FROM group_member_device_key WHERE group_id=?1 AND COALESCE(raw_device_id,member_id)=?2 AND principal_commitment IS NULL",params![group,name])?;
        Ok(())
    }
    /// Whether a verified roster binds this exact root/device, for retry relationship budgets.
    /// This does not authenticate a signature or substitute for a pinned member key.
    /// # Errors
    /// Returns database errors.
    pub fn has_root_bound_group_membership(
        &self,
        group: &str,
        device: &RootQualifiedDeviceRef,
    ) -> Result<bool, StorageError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM group_member_projection WHERE group_id=?1 AND member_id=?2 AND principal_commitment=?3 AND active=1)",params![group,device.device_id(),device.root_commitment()],|row|row.get(0))?)
    }
    /// Import membership provenance from an authenticated roster, without installing a device key.
    /// # Errors
    /// Rejects an existing slot bound to a different root and returns storage errors.
    pub fn upsert_root_bound_group_member_snapshot(
        &self,
        group: &str,
        device: &RootQualifiedDeviceRef,
        role: &str,
        epoch: u64,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            let conflict:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM group_member_projection WHERE group_id=?1 AND member_id=?2 AND active=1 AND principal_commitment IS NOT NULL AND principal_commitment<>?3)",params![group,device.device_id(),device.root_commitment()],|row|row.get(0))?;
            if conflict { return Err(StorageError::GroupPermissionDenied); }
            self.upsert_group_member_snapshot(group,device.device_id(),role,epoch)?;
            self.connection.execute("UPDATE group_member_projection SET principal_commitment=?3 WHERE group_id=?1 AND member_id=?2",params![group,device.device_id(),device.root_commitment()])?;
            Ok(())
        })
    }
    pub(super) fn archive_removed_group_pin(
        &self,
        group: &str,
        name: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS legacy_group_member_device_key AS SELECT * FROM group_member_device_key WHERE 0")?;
        let predicate = "group_id=?1 AND COALESCE(raw_device_id,member_id)=?2 AND EXISTS(SELECT 1 FROM group_member_projection m WHERE m.group_id=?1 AND m.member_id=?2 AND m.active=0 AND m.principal_commitment=group_member_device_key.principal_commitment)";
        self.connection.execute(&format!("INSERT INTO legacy_group_member_device_key SELECT * FROM group_member_device_key WHERE {predicate}"),params![group,name])?;
        self.connection.execute(
            &format!("DELETE FROM group_member_device_key WHERE {predicate}"),
            params![group, name],
        )?;
        Ok(())
    }
}
