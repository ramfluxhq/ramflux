// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned network-only directory, pair-material and federation submission operations.

use super::pair_material;
use crate::bus::connection_manager::SessionContext;
use crate::client::routed::{SendMaterial, SendMaterialRequest};
use crate::gateway::session_push::SubmitRefusal;
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
/// Maps a certain gateway refusal back to the error the unclassified callers always saw.
fn unclassified(outcome: Result<Result<(), SubmitRefusal>, SdkError>) -> Result<(), SdkError> {
    match outcome? {
        Ok(()) => Ok(()),
        Err(refusal) => Err(SdkError::GatewaySessionRejected(refusal.reason().to_owned())),
    }
}

/// The unclassified form; production sites use [`submit_classified`], tests keep this one.
#[cfg(test)]
pub(crate) async fn submit(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
    route: Option<LocalBusFederationRoute>,
) -> Result<(), SdkError> {
    unclassified(submit_classified(context, envelope, route).await)
}

/// Like [`submit`], but a gateway refusal that is certain to be a refusal (decoded from a
/// legacy `nack` with an exact outcome reason) is returned in the inner `Err`. Every other
/// failure, including all federation-routed failures, is uncertain and stays in the outer one.
pub(crate) async fn submit_classified(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
    route: Option<LocalBusFederationRoute>,
) -> Result<Result<(), SubmitRefusal>, SdkError> {
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
    unclassified(submit_inner(context, envelope, route, deadline, priority, !priority).await)
}

#[cfg(test)]
tokio::task_local! { pub(super) static TEST_LIMITER: std::sync::Arc<tokio::sync::Semaphore>; }

async fn submit_inner(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
    route: Option<LocalBusFederationRoute>,
    deadline: tokio::time::Instant,
    priority: bool,
    task_forward: bool,
) -> Result<Result<(), SubmitRefusal>, SdkError> {
    let deadline_error = || if task_forward { SdkError::TaskDeliveryTimeout } else { stopped() };
    if let Some(route) = route {
        if deadline <= tokio::time::Instant::now() {
            return Err(deadline_error());
        }
        #[cfg(test)]
        let local_limiter = TEST_LIMITER.try_with(std::sync::Arc::clone).ok();
        let slots = crate::client::federation::forward_slots();
        #[cfg(test)]
        let slots = local_limiter.as_deref().unwrap_or(slots);
        let _permit = if task_forward {
            Some(slots.try_acquire().map_err(|_| SdkError::TaskForwardWorkerCapacity)?)
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
        Ok(Ok(()))
    } else if priority {
        context
            .priority_call(
                move |engine| {
                    Box::pin(async move {
                        engine.submit_envelope_classified(envelope).await.map(|r| r.map(|_| ()))
                    })
                },
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            )
            .await
    } else {
        context
            .call(
                move |engine| {
                    Box::pin(async move {
                        engine.submit_envelope_classified(envelope).await.map(|r| r.map(|_| ()))
                    })
                },
                deadline,
            )
            .await
    }
}
fn stopped() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}
