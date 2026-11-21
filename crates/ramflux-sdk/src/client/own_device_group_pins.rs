// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable group-member pins carried by authenticated same-root history snapshots.
use crate::own_device_sync::{SdkOwnDeviceGroupMemberPin, SdkOwnDeviceGroupSnapshot};
use crate::prelude::*;
impl RamfluxClient {
    pub(super) fn own_device_group_member_pins(
        &self,
        groups: &[SdkOwnDeviceGroupSnapshot],
    ) -> Result<Vec<SdkOwnDeviceGroupMemberPin>, SdkError> {
        let mut pins = Vec::new();
        for group in groups {
            if group.shared_state.is_some() {
                continue;
            }
            for member in &group.members {
                if let Some(binding) = self
                    .account_db()?
                    .group_member_identity_metadata(&group.group_id, &member.member_id)?
                {
                    pins.push(SdkOwnDeviceGroupMemberPin {
                        group_id: group.group_id.clone(),
                        device_id: member.member_id.clone(),
                        signing_public_key: binding.signing_public_key,
                        principal_id: binding.principal_id,
                        principal_commitment: binding.principal_commitment,
                    });
                }
            }
        }
        Ok(pins)
    }
    pub(crate) fn restore_own_member_pin(
        &self,
        pin: &crate::own_device_sync::SdkOwnDeviceGroupMemberPin,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if pin.principal_id.is_some() != pin.principal_commitment.is_some()
            || ramflux_protocol::decode_base64url(&pin.signing_public_key)
                .map_or(true, |key| key.len() != 32)
        {
            return Err(SdkError::InboundRejected("invalid member pin".into()));
        }
        let reference = self.device_identity_for_root(
            pin.principal_commitment.as_deref().ok_or_else(|| {
                SdkError::InboundPending("unbound snapshot pin requires member re-add".into())
            })?,
            &pin.device_id,
        )?;
        if let Some(old) = db.group_member_key_binding(&pin.group_id, &reference)?
            && (old.signing_public_key != pin.signing_public_key
                || old.principal_id.as_ref().is_some_and(|p| Some(p) != pin.principal_id.as_ref())
                || old
                    .principal_commitment
                    .as_ref()
                    .is_some_and(|p| Some(p) != pin.principal_commitment.as_ref()))
        {
            return Err(SdkError::InboundRejected("member pin conflict".into()));
        }
        db.persist_group_member_device_key(&pin.group_id, &reference, &pin.signing_public_key)?;
        if let (Some(principal), Some(commitment)) = (&pin.principal_id, &pin.principal_commitment)
        {
            db.bind_group_member_key_identity(
                &pin.group_id,
                &reference,
                principal,
                commitment,
                &pin.signing_public_key,
            )?;
        }
        Ok(())
    }
}
