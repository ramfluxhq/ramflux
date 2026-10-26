// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit devices take priority; fair implicit expansion cannot monopolize group fanout.
use crate::prelude::*;
use ramflux_protocol::group_state::{
    MAX_GROUP_DEVICES, MAX_GROUP_DEVICES_PER_ROOT, SharedGroupState,
};
pub(super) fn select(
    state: &SharedGroupState,
    manifests: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut selected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for member in &state.members {
        let root = &member.identity.root_commitment;
        let device = &member.identity.device_id;
        let current = manifests.get(root);
        if current.is_none_or(|names| names.contains(device))
            && state.effective_role(root, device).is_some()
        {
            selected.entry(root.clone()).or_default().insert(device.clone());
        } else {
            selected.entry(root.clone()).or_default();
        }
    }
    let mut count: usize = selected.values().map(BTreeSet::len).sum();
    // Every represented root has a route before other roots gain implicit siblings.
    for (root, names) in &mut selected {
        if names.is_empty()
            && let Some(device) = manifests.get(root).and_then(|devices| {
                devices.iter().find(|device| state.effective_role(root, device).is_some())
            })
        {
            names.insert(device.clone());
            count += 1;
        }
    }
    while count < MAX_GROUP_DEVICES {
        let before = count;
        for (root, names) in &mut selected {
            if count >= MAX_GROUP_DEVICES {
                break;
            }
            if names.len() >= MAX_GROUP_DEVICES_PER_ROOT {
                continue;
            }
            if let Some(device) = manifests.get(root).and_then(|devices| {
                devices.iter().find(|device| {
                    !names.contains(*device) && state.effective_role(root, device).is_some()
                })
            }) {
                names.insert(device.clone());
                count += 1;
            }
        }
        if before == count {
            break;
        }
    }
    selected
}
impl RamfluxClient {
    pub(crate) fn assert_shared_group_send_capacity(
        &self,
        group: &str,
        sender: &str,
    ) -> Result<(), SdkError> {
        self.check_group_decline_fence(group)?;
        let Some(state) = self.account_db()?.shared_group_state(group)? else {
            return Ok(());
        };
        let own = self.owned_device_identity()?;
        if sender != own.device_id()
            || state.view().effective_role(own.root_commitment(), own.device_id()).is_none()
        {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        self.ensure_shared_group_device(&state, &own)
    }
    pub(crate) fn shared_group_selected_devices(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
    ) -> Result<BTreeMap<String, BTreeSet<String>>, SdkError> {
        let mut manifests = BTreeMap::new();
        for root in state
            .view()
            .members
            .iter()
            .map(|m| &m.identity.root_commitment)
            .collect::<BTreeSet<_>>()
        {
            if let Some(set) = self.observed_device_set(root)? {
                manifests.insert(
                    root.clone(),
                    set.devices
                        .iter()
                        .filter(|device| device.status == ramflux_protocol::DeviceSetStatus::Active)
                        .map(|device| device.device_id.clone())
                        .collect(),
                );
            }
        }
        Ok(select(state.view(), &manifests))
    }
    pub(crate) fn ensure_shared_group_device(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        if self
            .shared_group_selected_devices(state)?
            .get(source.root_commitment())
            .is_none_or(|names| !names.contains(source.device_id()))
        {
            return Err(SdkError::Protocol(ramflux_protocol::ProtocolError::GroupStateLimit(
                ramflux_protocol::GroupStateLimit::Devices,
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::shared_group::tests::{person, temp_root};
    #[test]
    fn implicit_siblings_are_capped_without_hiding_other_member_roots() -> Result<(), SdkError> {
        let root = temp_root("device-cap")?;
        let owner = person(&root.join("owner"), "owner", "phone", 11, 12)?;
        let peer = person(&root.join("peer"), "peer", "phone", 21, 22)?;
        owner.shared_group_create("group", "thread", None, "target-phone")?;
        let state = owner.shared_group_change(
            "group",
            "target-phone",
            ramflux_protocol::GroupStateChange::Add {
                member: peer.owned_group_actor("target-phone")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
        let own = owner.owned_device_identity()?;
        let remote = peer.owned_device_identity()?;
        let mut devices: BTreeSet<_> = (0..80).map(|i| format!("d{i:02}")).collect();
        devices.insert("phone".into());
        let manifests = BTreeMap::from([
            (own.root_commitment().into(), devices),
            (remote.root_commitment().into(), BTreeSet::from(["phone".into()])),
        ]);
        let selected = select(state.view(), &manifests);
        assert_eq!(selected[own.root_commitment()].len(), 16);
        assert!(selected[own.root_commitment()].contains("phone"));
        assert_eq!(selected[remote.root_commitment()].len(), 1);
        assert!(selected.values().map(BTreeSet::len).sum::<usize>() <= 1024);
        drop((owner, peer));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
