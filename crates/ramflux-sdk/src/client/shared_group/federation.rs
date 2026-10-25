// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Locally configured federation hints remain scoped to a verified member root.
use crate::prelude::*;
fn key(group: &str, root: &str) -> Result<String, SdkError> {
    Ok(format!(
        "group-state/federation/{}",
        ramflux_protocol::hash_base64url(
            "ramflux.group_state.federation_route.v1",
            &ramflux_protocol::canonical_json_bytes(&(group, root))?
        )
    ))
}
impl RamfluxClient {
    pub(crate) fn shared_group_federation_route(
        &self,
        group: &str,
        root: &str,
    ) -> Result<Option<LocalBusFederationRoute>, SdkError> {
        Ok(self.account_db()?.load_actor_state(&key(group, root)?)?)
    }
    pub(crate) fn persist_shared_group_federation_route(
        &self,
        group: &str,
        root: &str,
        route: &LocalBusFederationRoute,
    ) -> Result<(), SdkError> {
        // Routing metadata cannot create membership or a RootQualifiedDeviceRef.
        if !self.account_db()?.shared_group_state(group)?.is_some_and(|state| {
            state.view().members.iter().any(|member| member.identity.root_commitment == root)
        }) {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        self.account_db()?.persist_actor_state(&key(group, root)?, route)?;
        Ok(())
    }
    pub(crate) async fn shared_group_manifest(
        &self,
        gateway: &GatewaySessionConfig,
        group: &str,
        root: &str,
    ) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
        let manifest = if let Some(federation) = self.shared_group_federation_route(group, root)? {
            let url = federation.recipient_prekey_url.ok_or_else(|| {
                SdkError::LocalBus("federated group route requires recipient_prekey_url".into())
            })?;
            let expected = root.to_owned();
            tokio::task::spawn_blocking(move || {
                crate::client::contact::fetch_verified_device_manifest_from_url(&url, &expected)
            })
            .await
            .map_err(|error| {
                SdkError::LocalBus(format!("group manifest worker failed: {error}"))
            })??
        } else {
            crate::client::contact::fetch_verified_device_manifest(gateway, root).await?
        };
        self.persist_identity_directory(&manifest)?;
        Ok(manifest)
    }
}
