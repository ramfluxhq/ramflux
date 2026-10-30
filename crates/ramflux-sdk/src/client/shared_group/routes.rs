// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Expand signed group membership through current root-bound device authority.
use crate::prelude::*;
impl RamfluxClient {
    pub(crate) fn shared_group_member_routes(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
    ) -> Result<Vec<LocalBusGroupMemberRoute>, SdkError> {
        let mut routes = Vec::new();
        let selected = self.shared_group_selected_devices(state)?;
        for (root, names) in selected {
            if names.is_empty() {
                continue;
            }
            let root = root.as_str();
            let before = routes.len();
            let has_legacy_authority = self.observed_device_set(root)?.is_some();
            let has_native_authority =
                self.current_custody_authority(root, crate::custody::network_now()?)?.is_some();
            if !has_legacy_authority && !has_native_authority {
                for member in state
                    .view()
                    .members
                    .iter()
                    .filter(|member| member.identity.root_commitment == root)
                {
                    routes.push(LocalBusGroupMemberRoute {
                        member_id: member.identity.device_id.clone(),
                        member_principal_commitment: Some(root.into()),
                        device_signing_public_key: None,
                        target_delivery_id: None,
                        federation: self
                            .shared_group_federation_route(&state.view().group_id, root)?,
                    });
                }
                continue;
            }
            for name in names {
                if state.view().effective_role(root, &name).is_none() {
                    continue;
                }
                // Missing or dormant material is excluded; metadata alone never creates authority.
                let identity = match self.device_identity_for_root(root, &name) {
                    Ok(identity) => identity,
                    Err(SdkError::Storage(error)) => return Err(error.into()),
                    Err(_) => continue,
                };
                let record = self.trusted_device(&identity)?;
                let id =
                    crate::group::group_member_route_event_id(&state.view().group_id, &identity)?;
                let federation = if let Some(bytes) = self.event_body(&id)? {
                    let stored: LocalBusGroupMemberRoute = serde_json::from_slice(&bytes)?;
                    if stored.member_id != name
                        || stored.member_principal_commitment.as_deref() != Some(root)
                    {
                        return Err(SdkError::InboundRejected(
                            "shared group route root mismatch".into(),
                        ));
                    }
                    stored.federation
                } else {
                    None
                }
                .or(self.shared_group_federation_route(&state.view().group_id, root)?);
                routes.push(LocalBusGroupMemberRoute {
                    member_id: name,
                    member_principal_commitment: Some(root.into()),
                    device_signing_public_key: record["signing_public_key"]
                        .as_str()
                        .map(str::to_owned),
                    target_delivery_id: record["target_delivery_id"].as_str().map(str::to_owned),
                    federation,
                });
            }
            if routes.len() == before {
                let member = state
                    .view()
                    .members
                    .iter()
                    .find(|member| member.identity.root_commitment == root)
                    .ok_or(StorageError::GroupPermissionDenied)?;
                routes.push(LocalBusGroupMemberRoute {
                    member_id: member.identity.device_id.clone(),
                    member_principal_commitment: Some(root.into()),
                    device_signing_public_key: None,
                    target_delivery_id: None,
                    federation: None,
                });
            }
        }
        Ok(routes)
    }
}
