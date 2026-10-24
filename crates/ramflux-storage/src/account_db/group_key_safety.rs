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
        device: &str,
        principal: &str,
        commitment: &str,
        key: &str,
    ) -> Result<(), StorageError> {
        let raw = ramflux_protocol::parse_qualified_device_id(device)?
            .map_or_else(|| device.to_owned(), |(_, raw)| raw);
        let address = ramflux_protocol::qualified_device_id(commitment, &raw)?;
        let Some(device) = self.group_pin_key(group, &address)? else {
            return Err(StorageError::GroupPermissionDenied);
        };
        let device = device.as_str();
        if self.group_member_device_key(group, device)?.as_deref() != Some(key) {
            return Err(StorageError::GroupPermissionDenied);
        }
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

    /// Returns an active member's pinned device key and optional legacy identity binding.
    /// # Errors
    /// Returns SQL errors; absent/inactive membership returns None.
    pub fn group_member_key_binding(
        &self,
        group: &str,
        device: &str,
    ) -> Result<Option<GroupMemberKeyBinding>, StorageError> {
        let Some(device) = self.group_pin_key(group, device)? else { return Ok(None) };
        Ok(self.connection.query_row("SELECT k.device_signing_public_key,k.member_principal_id,k.principal_commitment FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=COALESCE(k.raw_device_id,k.member_id) WHERE k.group_id=?1 AND k.member_id=?2 AND m.active=1",params![group,device],|r|Ok(GroupMemberKeyBinding{signing_public_key:r.get(0)?,principal_id:r.get(1)?,principal_commitment:r.get(2)?})).optional()?)
    }
    /// Read the pin belonging to a literal active membership slot, without parsing it as an address.
    /// # Errors
    /// Returns SQL errors or rejects ambiguous historical pins.
    pub fn group_member_key_binding_by_name(
        &self,
        group: &str,
        raw: &str,
    ) -> Result<Option<GroupMemberKeyBinding>, StorageError> {
        let mut query=self.connection.prepare("SELECT k.member_id FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=COALESCE(k.raw_device_id,k.member_id) WHERE k.group_id=?1 AND COALESCE(k.raw_device_id,k.member_id)=?2 AND m.active=1 LIMIT 2")?;
        let keys = query
            .query_map(params![group, raw], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if keys.len() > 1 {
            return Err(StorageError::AmbiguousDeviceId(raw.into()));
        }
        keys.first()
            .map(|key| self.group_member_key_binding(group, key))
            .transpose()
            .map(Option::flatten)
    }
    /// Read a literal member slot's key, independent of any global device-name aliases.
    /// # Errors
    /// Returns SQL/ambiguity errors.
    pub fn group_member_device_key_by_name(
        &self,
        group: &str,
        raw: &str,
    ) -> Result<Option<String>, StorageError> {
        Ok(self
            .group_member_key_binding_by_name(group, raw)?
            .map(|binding| binding.signing_public_key))
    }
    /// Rejects a directory claim that conflicts with any existing member pin's identity.
    /// An unbound legacy pin can only acquire an identity through its unchanged key.
    /// # Errors
    /// Returns permission or SQL errors.
    pub fn check_group_device_directory_identity(
        &self,
        device: &str,
        principal: &str,
        commitment: &str,
        key: &str,
    ) -> Result<(), StorageError> {
        let conflicts:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM group_member_device_key WHERE member_id=?1 AND ((member_principal_id IS NOT NULL AND (member_principal_id IS NOT ?2 OR principal_commitment IS NOT ?3)) OR (member_principal_id IS NULL AND device_signing_public_key IS NOT ?4)))",params![device,principal,commitment,key],|r|r.get(0))?;
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
        device: &str,
    ) -> Result<Vec<(String, String)>, StorageError> {
        let qualified = ramflux_protocol::parse_qualified_device_id(device)?;
        let (root, raw) = qualified
            .as_ref()
            .map_or((None, device), |(root, raw)| (Some(root.as_str()), raw.as_str()));
        let mut query=self.connection.prepare("SELECT k.group_id,k.device_signing_public_key FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=COALESCE(k.raw_device_id,k.member_id) WHERE m.active=1 AND (COALESCE(k.raw_device_id,k.member_id)=?2 AND (?3 IS NULL OR k.principal_commitment=?3 OR k.principal_commitment IS NULL)) AND (?1 IS NOT NULL) ORDER BY k.group_id")?;
        Ok(query
            .query_map(params![device, raw, root], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
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
        root: &str,
        device: &str,
    ) -> Result<bool, StorageError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM group_member_device_key k JOIN group_member_projection m ON m.group_id=k.group_id AND m.member_id=COALESCE(k.raw_device_id,k.member_id) WHERE m.active=1 AND COALESCE(k.raw_device_id,k.member_id)=?1 AND k.member_principal_id=?2 AND k.principal_commitment=?3)",params![device,principal,root],|row|row.get(0))?)
    }
}
