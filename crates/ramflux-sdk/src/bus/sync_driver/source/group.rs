// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared-group directory requests are authenticated on the writer and fetched by receive.

use crate::bus::couriers::writer::Writer;
use crate::client::{
    routed::ReceiveGroupDirectory, routed::Routing, shared_group::GroupDirectoryEvidence,
};
use crate::{GatewayInboxEntry, GatewaySessionConfig, SdkError};

pub(super) async fn prepare(
    writer: &Writer,
    config: &GatewaySessionConfig,
    entry: &GatewayInboxEntry,
    route: Routing,
    body: zeroize::Zeroizing<Vec<u8>>,
) -> Result<Option<ReceiveGroupDirectory>, SdkError> {
    let entry = entry.clone();
    let (plan, entry, route, body) = writer
        .apply(move |account| {
            let plan = account.client.group_receive_directory_plan(&entry, &route, &body)?;
            Ok((plan, entry, route, body))
        })
        .await?;
    let Some(plan) = plan else {
        let local = config.device_id.clone();
        let request = writer
            .apply(move |account| {
                account.client.legacy_group_directory_request(&entry, &route, &body, &local)
            })
            .await?;
        return resolve_legacy(request, config).await;
    };
    let actor = super::fetch_inbound_manifest(config, &plan.actor_root).await?;
    // A fresh, active transport actor is required before it can cause an addition lookup.
    // Local membership and the selected route may also have changed during that request.
    let (addition, actor) = writer
        .apply(move |account| {
            account.client.accept_group_actor_manifest(&plan.actor, &entry, &actor)?;
            let current = account
                .client
                .confirm_group_receive_directory_plan(&entry, &route, &body)?
                .ok_or_else(|| SdkError::InboundPending("group directory plan changed".into()))?;
            account.client.accept_group_actor_manifest(&current.actor, &entry, &actor)?;
            Ok((current.addition, actor))
        })
        .await?;
    let addition =
        if let Some(request) = addition { Some(resolve_addition(request, config).await?) } else { None };
    Ok(Some(ReceiveGroupDirectory::Shared(Box::new(GroupDirectoryEvidence { actor, addition }))))
}

async fn resolve_legacy(
    request: crate::client::routed::group_directory::LegacyGroupRequest,
    config: &GatewaySessionConfig,
) -> Result<Option<ReceiveGroupDirectory>, SdkError> {
    let root = request.directory_root().map(str::to_owned);
    request.resolve(config).await.map_err(|source| match root {
        Some(root) => SdkError::DirectoryAuthorityUnavailable { root, source: Box::new(source) },
        None => source,
    })
}

async fn resolve_addition(
    request: crate::client::shared_group::GroupDirectoryRequest,
    config: &GatewaySessionConfig,
) -> Result<(crate::client::shared_group::GroupDirectoryRequest, crate::SdkDeviceManifestResponse), SdkError> {
    let root = request.root.clone();
    request.fetch(config).await.map_err(|source|
        SdkError::DirectoryAuthorityUnavailable { root, source: Box::new(source) })
}

#[cfg(test)]
mod tests;
