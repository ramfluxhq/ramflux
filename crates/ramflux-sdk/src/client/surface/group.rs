// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Surface membership follows verified account roots across their authorized devices.
use crate::{RamfluxClient, SdkError};
use ramflux_crypto::RootQualifiedDeviceRef;
impl RamfluxClient {
    pub(crate) fn surface_group_device_allowed(
        &self,
        group: &str,
        device: &RootQualifiedDeviceRef,
    ) -> Result<bool, SdkError> {
        let state = self.group_state(group)?;
        let db = self.account_db()?;
        for member in &state.members {
            let Some(binding) = db.group_member_identity_metadata(group, member)? else { continue };
            if binding.principal_commitment.as_deref() != Some(device.root_commitment()) {
                continue;
            }
            let identity = self.device_identity_for_root(device.root_commitment(), member)?;
            if db.group_member_device_key(group, &identity)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
