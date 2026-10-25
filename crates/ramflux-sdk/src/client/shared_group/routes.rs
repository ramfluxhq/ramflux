// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Expand signed group membership through current root-bound device authority.
use crate::prelude::*;
impl RamfluxClient {
    pub(crate) fn shared_group_member_routes(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
    ) -> Result<Vec<LocalBusGroupMemberRoute>, SdkError> {
        let db = self.account_db()?;
        let mut routes = Vec::new();
        let roots = state
            .view()
            .members
            .iter()
            .map(|member| member.identity.root_commitment.as_str())
            .collect::<BTreeSet<_>>();
        for root in roots {
            let before = routes.len();
            let manifest = db.load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(
                &format!("identity/manifest-root/{root}"),
            )?;
            let names = manifest
                .map(|manifest| {
                    manifest
                        .devices
                        .into_iter()
                        .map(|device| device.device_id)
                        .collect::<BTreeSet<_>>()
                })
                .unwrap_or_default();
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
            if routes.len() > 1024 {
                return Err(SdkError::LocalBus("group device fanout budget exceeded".into()));
            }
        }
        Ok(routes)
    }
}
