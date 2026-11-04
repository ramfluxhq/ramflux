// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned network-only directory, pair-material and federation submission operations.

use super::pair_material;
use crate::bus::connection_manager::SessionContext;
use crate::client::routed::{SendMaterial, SendMaterialRequest};
use crate::prelude::*;

pub(crate) async fn manifest(
    context: &SessionContext,
    config: &GatewaySessionConfig,
    root: &str,
    route: Option<&LocalBusFederationRoute>,
) -> Result<crate::SdkDeviceManifestResponse, SdkError> {
    if let Some(route) = route {
        let base = route.recipient_prekey_url.as_deref().ok_or_else(|| {
            SdkError::LocalBus("federated group route requires recipient_prekey_url".into())
        })?;
        let manifest = crate::prekey::http_async::get::<Option<crate::SdkDeviceManifestResponse>>(
            base,
            &format!("/mvp1/device-manifest/{root}"),
            context.network_wait(),
        )
        .await?
        .ok_or_else(|| SdkError::InboundPending("group manifest unavailable".into()))?;
        crate::client::contact::verify_device_manifest(&manifest, root)?;
        Ok(crate::client::identity_authority::ready_manifest(manifest, now_unix_timestamp()))
    } else {
        tokio::time::timeout(
            context.network_wait(),
            crate::client::contact::fetch_verified_device_manifest(config, root),
        )
        .await
        .map_err(|_| stopped())?
    }
}
pub(crate) async fn material(
    context: &SessionContext,
    config: &GatewaySessionConfig,
    request: SendMaterialRequest,
    route: Option<&LocalBusFederationRoute>,
) -> Result<SendMaterial, SdkError> {
    let Some(route) = route else { return pair_material::fetch(context, config, request).await };
    let base = route
        .recipient_prekey_url
        .as_deref()
        .or(config.prekey_http_url.as_deref())
        .ok_or_else(|| SdkError::LocalBus("prekey url missing".into()))?;
    let manifest = if let Some(root) = request.root {
        Some((root.clone(), manifest(context, config, &root, Some(route)).await?))
    } else {
        None
    };
    let bundle = if let Some(lookup) = request.prekey {
        Some(
            crate::prekey::http_async::get::<crate::prekey::SdkPrekeyResponse>(
                base,
                &format!("/mvp1/prekey/{lookup}"),
                context.network_wait(),
            )
            .await?
            .bundle
            .ok_or_else(|| SdkError::InboundPending("recipient prekey unavailable".into()))?,
        )
    } else {
        None
    };
    Ok(SendMaterial { manifest, bundle })
}
pub(crate) async fn submit(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
    route: Option<LocalBusFederationRoute>,
) -> Result<(), SdkError> {
    if let Some(route) = route {
        let request = crate::client::federation::federated_forward_request(&route, envelope);
        let response =
            crate::prekey::http_async::post::<_, crate::SdkFederatedEnvelopeForwardResponse>(
                &route.federation_url,
                "/s8/federation/forward",
                &request,
                context.network_wait(),
            )
            .await?;
        if !response.accepted {
            return Err(SdkError::InboundPending(
                "group state federation submission refused".into(),
            ));
        }
        Ok(())
    } else {
        context
            .call(
                move |engine| {
                    Box::pin(async move { engine.submit_envelope(envelope).await.map(|_| ()) })
                },
                context.call_deadline(),
            )
            .await
    }
}
fn stopped() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}
