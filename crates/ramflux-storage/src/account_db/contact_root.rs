// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Narrow cache/link maintenance used only after SDK-authorized provisional root replacement.
use super::*;
impl AccountDb {
    /// Removes an obsolete lookup hint only if it still belongs to the replaced root.
    /// # Errors
    /// Returns database errors.
    pub fn remove_device_directory_root(
        &self,
        device: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM device_directory WHERE COALESCE(raw_device_id,device_id)=?1 AND principal_commitment=?2",
            params![device.device_id(), device.root_commitment()],
        )?;
        Ok(())
    }
    /// Updates existing local link aliases without changing relationship authorization state.
    /// # Errors
    /// Returns database errors.
    pub fn replace_contact_link_root(
        &self,
        own_principal: &str,
        own_root: &str,
        old_root: &str,
        new_root: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute("UPDATE friend_link_projection SET requester_id=?4 WHERE requester_id=?3 AND target_id IN (?1,?2)",params![own_principal,own_root,old_root,new_root])?;
        self.connection.execute("UPDATE friend_link_projection SET target_id=?4 WHERE target_id=?3 AND requester_id IN (?1,?2)",params![own_principal,own_root,old_root,new_root])?;
        Ok(())
    }
}
