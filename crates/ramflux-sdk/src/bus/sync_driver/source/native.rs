// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receive consent lookups use a rolled-back preview and recheck on the final decrypt.

use crate::bus::couriers::writer::Writer;
use crate::client::routed::PreparedInbound;
use crate::prekey::SdkDeviceManifestResponse;
use crate::prelude::*;

#[derive(Clone)]
struct Preview {
    route: crate::client::routed::Routing,
    body: zeroize::Zeroizing<Vec<u8>>,
    root: Option<String>,
}

pub(super) async fn prepare(
    writer: &Writer,
    config: &GatewaySessionConfig,
    entry: &GatewayInboxEntry,
    manifest: Option<SdkDeviceManifestResponse>,
) -> Result<PreparedInbound, SdkError> {
    let owned_entry = entry.clone();
    let source = manifest.clone();
    let local = config.device_id.clone();
    let preview = writer
        .apply(move |account| {
            account.client.prepare_inbound_device_manifest(&owned_entry, source.as_ref())?;
            Ok(account.client.preview_inbound_route(&owned_entry, &local))
        })
        .await?;
    let preview = match preview {
        Ok(Some((route, body))) => {
            Some(Preview { root: RamfluxClient::native_contact_root(&body)?, route, body })
        }
        Ok(None) => None,
        Err(error) => {
            crate::bus::couriers::reset::receive_failure(writer, config, entry, &error).await?;
            return Err(error);
        }
    };
    let (group_directory, history) = if let Some(preview) = preview {
        resolve(writer, config, entry, preview.clone(), None).await?;
        let history =
            super::history::prepare(writer, config, entry, &preview.route, &preview.body).await?;
        let group_directory =
            super::group::prepare(writer, config, entry, preview.route, preview.body).await?;
        (group_directory, history)
    } else {
        (None, None)
    };
    Ok(PreparedInbound {
        manifest,
        native_prepared: true,
        group_directory,
        history,
        candidate: None,
        own_copy_manifest: None,
    })
}

async fn resolve(
    writer: &Writer,
    config: &GatewaySessionConfig,
    entry: &GatewayInboxEntry,
    preview: Preview,
    candidate: Option<SdkDeviceManifestResponse>,
) -> Result<(), SdkError> {
    let Some(root) = preview.root.as_deref() else { return Ok(()) };
    let manifest = if let Some(manifest) = candidate {
        manifest
    } else {
        super::fetch_inbound_manifest(config, root).await?
    };
    let entry = entry.clone();
    let (history, entry, preview, manifest) = writer
        .apply(move |account| {
            let history = account.client.native_contact_history_request(
                &entry,
                &preview.route,
                &preview.body,
                &manifest,
            )?;
            Ok((history, entry, preview, manifest))
        })
        .await?;
    let historical = history.resolve(config).await?;
    writer
        .apply(move |account| {
            account.client.apply_native_contact_evidence(
                &entry,
                &preview.route,
                &preview.body,
                &manifest,
                &historical,
            )
        })
        .await
}

/// Stranger authentication and its own-manifest refresh preserve their original charge order.
/// The final bootstrap transaction independently checks the candidate and decrypts again.
pub(super) async fn contact(
    writer: &Writer,
    config: &GatewaySessionConfig,
    entry: &GatewayInboxEntry,
    manifest: SdkDeviceManifestResponse,
) -> Result<PreparedInbound, SdkError> {
    let entry = entry.clone();
    let (own, entry, manifest) = writer
        .apply(move |account| {
            let own = account.client.accept_contact_candidate_manifest(&entry, &manifest)?;
            Ok((own, entry, manifest))
        })
        .await?;
    let own_manifest = super::fetch_inbound_manifest(config, &own).await?;
    let local = config.device_id.clone();
    let (preview, entry, manifest) = writer
        .apply(move |account| {
            account.client.accept_fetched_device_manifest(
                own_manifest,
                &own,
                "contact-request-self",
            )?;
            let preview = if manifest.custody.is_some() {
                account
                    .client
                    .preview_native_contact_request(&entry, &manifest, &local)?
                    .map(|(route, body)| {
                        let root = RamfluxClient::native_contact_root(&body)?;
                        Ok::<_, SdkError>(Preview { route, body, root })
                    })
                    .transpose()?
            } else {
                None
            };
            Ok((preview, entry, manifest))
        })
        .await?;
    if let Some(preview) = preview {
        resolve(writer, config, &entry, preview, Some(manifest.clone())).await?;
    }
    Ok(PreparedInbound {
        manifest: None,
        candidate: Some(manifest),
        native_prepared: true,
        group_directory: None,
        history: None,
        own_copy_manifest: None,
    })
}
