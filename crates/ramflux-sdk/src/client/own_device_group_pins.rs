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
    /// Called after authenticated same-root context admission. Rejected pins remain inactive.
    pub(super) fn restore_own_device_group_member_pins(
        &self,
        bundle: &SdkOwnDeviceHistoryBundle,
        floors: &BTreeMap<String, u64>,
    ) -> Result<BTreeSet<(String, String)>, SdkError> {
        let db = self.account_db()?;
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id;
        let mut blocked = BTreeSet::new();
        let mut unique = BTreeMap::new();
        for pin in bundle.group_member_pins.iter().filter(|pin| pin.device_id != *local) {
            let id = (pin.group_id.clone(), pin.device_id.clone());
            let encoded = serde_json::to_vec(pin)?;
            if unique.insert(id.clone(), encoded.clone()).is_some_and(|old| old != encoded) {
                blocked.insert(id);
            }
        }
        let mut seen = BTreeSet::new();
        for pin in bundle.group_member_pins.iter().filter(|pin| pin.device_id != *local) {
            let id = (pin.group_id.clone(), pin.device_id.clone());
            if !seen.insert(id.clone()) {
                continue;
            }
            let accepted = !blocked.contains(&id)
                && floors.contains_key(&pin.group_id)
                && bundle
                    .groups
                    .iter()
                    .filter(|g| g.group_id == pin.group_id)
                    .max_by_key(|g| g.group_epoch)
                    .is_some_and(|g| g.members.iter().any(|m| m.member_id == pin.device_id))
                && db.group_member_role(&pin.group_id, &pin.device_id)?.is_some();
            let result = if accepted {
                db.write_transaction(|| self.restore_own_member_pin(pin))
            } else {
                Err(SdkError::InboundRejected("snapshot pin context rejected".into()))
            };
            match result {
                Ok(()) => {}
                Err(SdkError::Storage(error))
                    if !matches!(error, StorageError::GroupPermissionDenied) =>
                {
                    return Err(SdkError::Storage(error));
                }
                Err(_) => {
                    blocked.insert(id);
                    db.record_own_device_restore_skip(
                        &bundle.snapshot_id,
                        &format!("{}:{}", pin.group_id, pin.device_id),
                        "member_pin_rejected",
                    )?;
                }
            }
        }
        for group in floors.keys() {
            match db.write_transaction(|| self.pin_local_group_member(group)) {
                Ok(()) => {}
                Err(SdkError::Storage(error))
                    if !matches!(error, StorageError::GroupPermissionDenied) =>
                {
                    return Err(SdkError::Storage(error));
                }
                Err(_) => {
                    blocked.insert((group.clone(), String::new()));
                    db.record_own_device_restore_skip(
                        &bundle.snapshot_id,
                        group,
                        "local_member_pin_rejected",
                    )?;
                }
            }
        }
        Ok(blocked)
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
