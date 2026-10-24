// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pinned group key observations never rotate keys from directory claims.
use super::*;
impl AccountDb {
    /// Binds a pinned key to its known principal; a different principal cannot claim the device id.
    /// # Errors
    /// Rejects mismatched keys or previously bound identities and returns SQL errors.
    pub fn bind_group_member_key_identity(
        &self,
        group: &str,
        device: &str,
        principal: &str,
        commitment: &str,
        key: &str,
    ) -> Result<(), StorageError> {
        if self.group_member_device_key(group, device)?.as_deref() != Some(key) {
            return Err(StorageError::GroupPermissionDenied);
        }
        let changed=self.connection.execute("UPDATE group_member_device_key SET member_principal_id=?3,principal_commitment=?4 WHERE group_id=?1 AND member_id=?2 AND (member_principal_id IS NULL OR (member_principal_id=?3 AND principal_commitment=?4))",params![group,device,principal,commitment])?;
        if changed == 0 {
            return Err(StorageError::GroupPermissionDenied);
        }
        Ok(())
    }
    pub(super) fn bind_group_key_from_directory(
        &self,
        group: &str,
        device: &str,
        key: &str,
    ) -> Result<(), StorageError> {
        if let Some(record) = self.client_record("device", device)?
            && record["signing_public_key"].as_str() == Some(key)
            && let (Some(principal), Some(commitment)) =
                (record["principal_id"].as_str(), record["principal_commitment"].as_str())
        {
            self.bind_group_member_key_identity(group, device, principal, commitment, key)?;
        }
        Ok(())
    }

    /// Lists pinned group keys for one device, without granting a directory any write authority.
    /// # Errors
    /// Returns SQL errors.
    pub fn pinned_group_device_keys(
        &self,
        device: &str,
    ) -> Result<Vec<(String, String)>, StorageError> {
        let mut query=self.connection.prepare("SELECT k.group_id,k.device_signing_public_key FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=k.member_id WHERE k.member_id=?1 AND m.active=1 ORDER BY k.group_id")?;
        Ok(query
            .query_map(params![device], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
}
