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
    class: crate::bus::connection_manager::CallClass,
    route: Option<&LocalBusFederationRoute>,
) -> Result<SendMaterial, SdkError> {
    let Some(route) = route else {
        return pair_material::fetch(context, config, request, class).await;
    };
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
    let deadline = if route.is_some() {
        tokio::time::Instant::now() + context.network_wait()
    } else {
        context.call_deadline()
    };
    submit_inner(context, envelope, route, deadline, false, false).await
}

pub(crate) async fn submit_until(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
    route: Option<LocalBusFederationRoute>,
    deadline: tokio::time::Instant,
    priority: bool,
) -> Result<(), SdkError> {
    submit_inner(context, envelope, route, deadline, priority, !priority).await
}

async fn submit_inner(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
    route: Option<LocalBusFederationRoute>,
    deadline: tokio::time::Instant,
    priority: bool,
    task_forward: bool,
) -> Result<(), SdkError> {
    let deadline_error = || if task_forward { SdkError::TaskDeliveryTimeout } else { stopped() };
    if let Some(route) = route {
        if deadline <= tokio::time::Instant::now() {
            return Err(deadline_error());
        }
        let _permit = if task_forward {
            Some(
                crate::client::federation::forward_slots()
                    .try_acquire()
                    .map_err(|_| SdkError::TaskForwardWorkerCapacity)?,
            )
        } else {
            None
        };
        let request = crate::client::federation::federated_forward_request(&route, envelope);
        let response = tokio::time::timeout_at(
            deadline,
            crate::prekey::http_async::post::<_, crate::SdkFederatedEnvelopeForwardResponse>(
                &route.federation_url,
                "/s8/federation/forward",
                &request,
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            ),
        )
        .await
        .map_err(|_| deadline_error())?
        .map_err(|error| match error {
            SdkError::Io(ref io) if task_forward && io.kind() == std::io::ErrorKind::TimedOut => {
                SdkError::TaskDeliveryTimeout
            }
            other => other,
        })?;
        if !response.accepted {
            return Err(SdkError::InboundPending(
                "group state federation submission refused".into(),
            ));
        }
        Ok(())
    } else if priority {
        context
            .priority_call(
                move |engine| {
                    Box::pin(async move { engine.submit_envelope(envelope).await.map(|_| ()) })
                },
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            )
            .await
    } else {
        context
            .call(
                move |engine| {
                    Box::pin(async move { engine.submit_envelope(envelope).await.map(|_| ()) })
                },
                deadline,
            )
            .await
    }
}
fn stopped() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}
