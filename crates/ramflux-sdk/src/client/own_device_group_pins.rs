// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable group-member pins carried by authenticated same-root history snapshots.
use crate::own_device_sync::{
    SdkOwnDeviceGroupMemberPin, SdkOwnDeviceGroupSnapshot, SdkOwnDeviceHistoryBundle,
};
use crate::prelude::*;
impl RamfluxClient {
    pub(super) fn own_device_group_member_pins(
        &self,
        groups: &[SdkOwnDeviceGroupSnapshot],
    ) -> Result<Vec<SdkOwnDeviceGroupMemberPin>, SdkError> {
        let mut pins = Vec::new();
        for group in groups {
            for member in &group.members {
                if let Some(binding) = self
                    .account_db()?
                    .group_member_key_binding(&group.group_id, &member.member_id)?
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
    /// Called only after the same-root source, target, encrypted bundle and group context checks.
    pub(super) fn restore_own_device_group_member_pins(
        &self,
        bundle: &SdkOwnDeviceHistoryBundle,
    ) -> Result<(), SdkError> {
        self.restore_own_group_pins(&bundle.groups, &bundle.group_member_pins)
    }
    pub(crate) fn restore_own_group_pins(
        &self,
        groups: &[SdkOwnDeviceGroupSnapshot],
        pins: &[SdkOwnDeviceGroupMemberPin],
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        // Validate the entire incoming pin set before writing any keys. Existing active pins
        // always win; a sibling device gets its own key rather than replacing the source key.
        let mut seen = BTreeSet::new();
        for pin in pins {
            if !seen.insert((&pin.group_id, &pin.device_id))
                || !groups.iter().any(|group| {
                    group.group_id == pin.group_id
                        && group.members.iter().any(|m| m.member_id == pin.device_id)
                })
                || pin.principal_id.is_some() != pin.principal_commitment.is_some()
            {
                return Err(SdkError::InboundRejected(
                    "own-device group pin context mismatch".into(),
                ));
            }
            let key =
                ramflux_protocol::decode_base64url(&pin.signing_public_key).map_err(|_| {
                    SdkError::InboundRejected("invalid own-device group member key".into())
                })?;
            if key.len() != 32 {
                return Err(SdkError::InboundRejected(
                    "invalid own-device group member key length".into(),
                ));
            }
            if let Some(old) = db.group_member_key_binding(&pin.group_id, &pin.device_id)?
                && (old.signing_public_key != pin.signing_public_key
                    || old
                        .principal_id
                        .as_ref()
                        .is_some_and(|p| Some(p) != pin.principal_id.as_ref())
                    || old
                        .principal_commitment
                        .as_ref()
                        .is_some_and(|p| Some(p) != pin.principal_commitment.as_ref()))
            {
                return Err(SdkError::InboundRejected(
                    "own-device snapshot conflicts with an existing member pin".into(),
                ));
            }
        }
        for pin in pins {
            db.persist_group_member_device_key(
                &pin.group_id,
                &pin.device_id,
                &pin.signing_public_key,
            )?;
            if let (Some(principal), Some(commitment)) =
                (&pin.principal_id, &pin.principal_commitment)
            {
                db.bind_group_member_key_identity(
                    &pin.group_id,
                    &pin.device_id,
                    principal,
                    commitment,
                    &pin.signing_public_key,
                )?;
            }
        }
        for group in groups {
            self.pin_local_group_member(&group.group_id)?;
        }
        Ok(())
    }
}
