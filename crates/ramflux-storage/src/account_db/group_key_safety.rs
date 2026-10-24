// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pinned group key observations never rotate keys from directory claims.
use super::*;
use rusqlite::OptionalExtension;
impl AccountDb {
    /// Binds a pinned key to its known principal; a different principal cannot claim the device id.
    /// # Errors
    /// Rejects mismatched keys or previously bound identities and returns SQL errors.
    pub fn bind_group_member_key_identity(
        &self,
        group: &str,
        device: &ramflux_crypto::RootQualifiedDeviceRef,
        principal: &str,
        commitment: &str,
        key: &str,
    ) -> Result<(), StorageError> {
        if commitment != device.root_commitment() {
            return Err(StorageError::GroupPermissionDenied);
        }
        let address = device.storage_key();
        let raw = device.device_id();
        if self.group_member_device_key(group, device)?.as_deref() != Some(key) {
            return Err(StorageError::GroupPermissionDenied);
        }
        let Some(stored) = self.group_pin_key(group, device)? else {
            return Err(StorageError::GroupPermissionDenied);
        };
        let device = stored.as_str();
        let changed=self.connection.execute("UPDATE group_member_device_key SET member_principal_id=?3,principal_commitment=?4 WHERE group_id=?1 AND member_id=?2 AND member_principal_id IS NULL AND device_signing_public_key=?5",params![group,device,principal,commitment,key])?;
        if changed == 0 {
            let same:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM group_member_device_key WHERE group_id=?1 AND member_id=?2 AND member_principal_id=?3 AND principal_commitment=?4 AND device_signing_public_key=?5)",params![group,device,principal,commitment,key],|r|r.get(0))?;
            if !same {
                return Err(StorageError::GroupPermissionDenied);
            }
        }
        if device != address {
            self.connection.execute("UPDATE group_member_device_key SET member_id=?3,raw_device_id=?4 WHERE group_id=?1 AND member_id=?2 AND principal_commitment=?5",params![group,device,address,raw,commitment])?;
        }
        Ok(())
    }
    pub(super) fn bind_group_key_from_directory(
        &self,
        group: &str,
        device: &ramflux_crypto::RootQualifiedDeviceRef,
        key: &str,
    ) -> Result<(), StorageError> {
        if let Some(record) = self.client_record("device", device.storage_key())?
            && record["signing_public_key"].as_str() == Some(key)
            && let (Some(principal), Some(commitment)) =
                (record["principal_id"].as_str(), record["principal_commitment"].as_str())
        {
            self.bind_group_member_key_identity(group, device, principal, commitment, key)?;
        }
        Ok(())
    }

    /// Returns an active member's pinned device key and optional legacy identity binding.
    /// # Errors
    /// Returns SQL errors; absent/inactive membership returns None.
    pub fn group_member_key_binding(
        &self,
        group: &str,
        device: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Option<GroupMemberKeyBinding>, StorageError> {
        let Some(device) = self.group_pin_key(group, device)? else { return Ok(None) };
        Ok(self.connection.query_row("SELECT k.device_signing_public_key,k.member_principal_id,k.principal_commitment FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=COALESCE(k.raw_device_id,k.member_id) AND m.principal_commitment=k.principal_commitment WHERE k.group_id=?1 AND k.member_id=?2 AND m.active=1",params![group,device],|r|Ok(GroupMemberKeyBinding{signing_public_key:r.get(0)?,principal_id:r.get(1)?,principal_commitment:r.get(2)?})).optional()?)
    }
    /// Read the pin belonging to a literal active membership slot, without parsing it as an address.
    /// # Errors
    /// Returns SQL errors or rejects ambiguous historical pins.
    pub fn group_member_identity_metadata(
        &self,
        group: &str,
        raw: &str,
    ) -> Result<Option<GroupMemberKeyBinding>, StorageError> {
        // Display/source-discovery metadata only. Callers must authenticate its root-signed
        // device set before constructing an identity reference or using this key.
        let mut query=self.connection.prepare("SELECT k.device_signing_public_key,k.member_principal_id,k.principal_commitment FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=COALESCE(k.raw_device_id,k.member_id) AND m.principal_commitment=k.principal_commitment WHERE k.group_id=?1 AND COALESCE(k.raw_device_id,k.member_id)=?2 AND m.active=1 AND k.principal_commitment IS NOT NULL LIMIT 2")?;
        let rows = query
            .query_map(params![group, raw], |row| {
                Ok(GroupMemberKeyBinding {
                    signing_public_key: row.get(0)?,
                    principal_id: row.get(1)?,
                    principal_commitment: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > 1 {
            return Err(StorageError::AmbiguousDeviceId(raw.into()));
        }
        Ok(rows.into_iter().next())
    }

    /// Rejects a directory claim that conflicts with any existing member pin's identity.
    /// An unbound legacy pin can only acquire an identity through its unchanged key.
    /// # Errors
    /// Returns permission or SQL errors.
    pub fn check_group_device_directory_identity(
        &self,
        device: &ramflux_crypto::RootQualifiedDeviceRef,
        principal: &str,
        commitment: &str,
        key: &str,
    ) -> Result<(), StorageError> {
        let conflicts:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM group_member_device_key WHERE member_id=?1 AND ((member_principal_id IS NOT NULL AND (member_principal_id IS NOT ?2 OR principal_commitment IS NOT ?3)) OR (member_principal_id IS NULL AND device_signing_public_key IS NOT ?4)))",params![device.storage_key(),principal,commitment,key],|r|r.get(0))?;
        if conflicts {
            return Err(StorageError::GroupPermissionDenied);
        }
        Ok(())
    }
    /// Lists pinned group keys for one device, without granting a directory any write authority.
    /// # Errors
    /// Returns SQL errors.
    pub fn pinned_group_device_keys(
        &self,
        device: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Vec<(String, String)>, StorageError> {
        let mut query=self.connection.prepare("SELECT k.group_id,k.device_signing_public_key FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=COALESCE(k.raw_device_id,k.member_id) AND m.principal_commitment=k.principal_commitment WHERE m.active=1 AND COALESCE(k.raw_device_id,k.member_id)=?1 AND k.principal_commitment=?2 ORDER BY k.group_id")?;
        Ok(query
            .query_map(params![device.device_id(), device.root_commitment()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Read-only root provenance for safety notices about a pinned principal label.
    /// # Errors
    /// Returns SQL errors. These rows do not authenticate a manifest or grant membership.
    pub fn pinned_group_root_metadata(
        &self,
        principal: &str,
        name: &str,
    ) -> Result<Vec<String>, StorageError> {
        let mut query = self.connection.prepare("SELECT DISTINCT k.principal_commitment FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=COALESCE(k.raw_device_id,k.member_id) AND m.principal_commitment=k.principal_commitment WHERE m.active=1 AND (k.member_principal_id=?1 OR k.member_principal_id IS NULL) AND COALESCE(k.raw_device_id,k.member_id)=?2 AND k.principal_commitment IS NOT NULL")?;
        Ok(query
            .query_map(params![principal, name], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// An authenticated inviter's pending offer may select trust material to fetch.
    /// This metadata does not authenticate a sender or grant group membership.
    /// # Errors
    /// Returns SQL errors.
    pub fn pending_group_invite_root_metadata(
        &self,
        name: &str,
        root: &str,
        at: i64,
    ) -> Result<bool, StorageError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM root_group_invite_identity r JOIN group_invite_projection i ON i.group_id=r.group_id AND i.invite_id=r.invite_id WHERE r.device_name=?1 AND r.expected_root=?2 AND i.invitee_identity=?1 AND i.state='pending' AND i.expires_at>=?3)",params![name,root,at],|row|row.get(0))?)
    }

    /// Update an existing ownership-bound pin after the caller verifies a newer root-signed set.
    /// # Errors
    /// Rejects ownership/key races and returns SQL failures. This grants no authority to a directory.
    pub fn rotate_root_authorized_group_device_key(
        &self,
        rotation: crate::RootAuthorizedGroupKeyRotation<'_>,
    ) -> Result<(), StorageError> {
        let crate::RootAuthorizedGroupKeyRotation {
            group_id: group,
            device_id: device,
            principal_id: principal,
            principal_commitment: commitment,
            previous_key: old,
            next_key: new,
        } = rotation;
        let Some(device) = self.group_pin_key(group, device)? else {
            return Err(StorageError::GroupPermissionDenied);
        };
        let changed=self.connection.execute("UPDATE group_member_device_key SET device_signing_public_key=?6 WHERE group_id=?1 AND member_id=?2 AND member_principal_id=?3 AND principal_commitment=?4 AND device_signing_public_key=?5",params![group,device,principal,commitment,old,new])?;
        if changed != 1 {
            return Err(StorageError::GroupPermissionDenied);
        }
        Ok(())
    }
}

impl AccountDb {
    /// Whether active local group membership already binds this principal/root/device tuple.
    /// # Errors
    /// Returns SQL errors.
    pub fn has_group_device_relationship(
        &self,
        principal: &str,
        device: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<bool, StorageError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=COALESCE(k.raw_device_id,k.member_id) AND m.principal_commitment=k.principal_commitment WHERE m.active=1 AND COALESCE(k.raw_device_id,k.member_id)=?1 AND k.member_principal_id=?2 AND k.principal_commitment=?3)",params![device.device_id(),principal,device.root_commitment()],|row|row.get(0))?)
    }
}
