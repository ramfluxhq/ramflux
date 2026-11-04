// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Remote manifest transport and the shared local authority gate.

use super::*;

#[derive(Clone, Copy)]
pub(crate) struct RemoteManifest<'a> {
    pub url: &'a str,
    pub timeout: Duration,
}

pub(super) fn recipient(
    explicit: Option<&str>,
    device: &str,
) -> Result<(String, String), SdkError> {
    let qualified = if explicit.is_none_or(str::is_empty) {
        ramflux_protocol::parse_qualified_device_id(device)?
    } else {
        None
    };
    let root = explicit.filter(|root| !root.is_empty())
        .or_else(|| qualified.as_ref().map(|(root, _)| root.as_str()))
        .ok_or_else(|| SdkError::LocalBus("federated direct messages require an explicit root or root-qualified device address".into()))?;
    Ok((root.to_owned(), qualified.as_ref().map_or(device, |(_, raw)| raw.as_str()).to_owned()))
}
impl RamfluxClient {
    pub(super) fn accept_federated_target(
        &self,
        manifest: SdkDeviceManifestResponse,
        root: &str,
        device: &str,
        source: &str,
    ) -> Result<SdkDeviceManifestEntry, SdkError> {
        self.persist_fetched_identity_directory(&manifest)?;
        let verified_at = now_unix_timestamp();
        for entry in &manifest.devices {
            self.account_db()?.upsert_device_directory_entry(
                &entry.device_id,
                &manifest.principal_commitment,
                source,
                verified_at,
            )?;
        }
        manifest.devices.into_iter().find(|entry| entry.device_id == device).ok_or_else(|| {
            SdkError::LocalBus(format!(
                "recipient device {device} is not in verified manifest for {root}"
            ))
        })
    }
    pub(crate) async fn resolve_federated_target_principal_commitment_async(
        &self,
        remote: RemoteManifest<'_>,
        explicit: Option<&str>,
        device: &str,
    ) -> Result<String, SdkError> {
        let (root, device) = recipient(explicit, device)?;
        let manifest = fetch(remote, &root).await?;
        self.accept_federated_target(manifest, &root, &device, "federation")?;
        Ok(root)
    }
    pub(crate) async fn assert_manifest_active_device_from_url_async(
        &self,
        remote: RemoteManifest<'_>,
        root: &str,
        device: &str,
        source: &str,
    ) -> Result<SdkDeviceManifestEntry, SdkError> {
        let manifest = fetch(remote, root).await?;
        self.accept_federated_target(manifest, root, device, source)
    }
}
pub(crate) async fn fetch(
    remote: RemoteManifest<'_>,
    root: &str,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    let manifest: Option<SdkDeviceManifestResponse> = crate::prekey::http_async::get(
        remote.url,
        &format!("/mvp1/device-manifest/{root}"),
        remote.timeout,
    )
    .await?;
    let manifest = manifest
        .ok_or_else(|| SdkError::LocalBus(format!("missing device manifest for {root}")))?;
    verify_device_manifest(&manifest, root)?;
    Ok(crate::client::identity_authority::ready_manifest(manifest, now_unix_timestamp()))
}
