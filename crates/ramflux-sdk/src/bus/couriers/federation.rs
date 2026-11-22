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
    base: Option<&str>,
) -> Result<crate::SdkDeviceManifestResponse, SdkError> {
    if let Some(base) = base {
        let started = std::time::Instant::now();
        let mut manifest =
            crate::prekey::http_async::get::<Option<crate::SdkDeviceManifestResponse>>(
                base,
                &format!("/mvp1/device-manifest/{root}"),
                context.network_wait(),
            )
            .await?
            .ok_or_else(|| SdkError::InboundPending("group manifest unavailable".into()))?;
        manifest.fetched_after = crate::prekey::FetchStamp(Some(started));
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
    base: Option<&str>,
) -> Result<SendMaterial, SdkError> {
    let Some(base) = base else {
        return pair_material::fetch(context, config, request, class).await;
    };
    let manifest = if let Some(root) = request.root {
        Some((root.clone(), manifest(context, config, &root, Some(base)).await?))
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

/// Submit one envelope on the local gateway, optionally with a caller-signed call intent.
///
/// Cross-node federation does not use this path. The destination forward posts only the
/// envelope, so a remote call keeps message priority.
///
/// # Errors
/// Returns an error when the gateway rejects the submit or the exchange fails.
pub(crate) async fn submit_local_call(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
    deadline: tokio::time::Instant,
    extras: crate::gateway::engine::CallSubmitExtras,
) -> Result<crate::gateway::call_resolution::CallSubmitOutcome, SdkError> {
    context
        .priority_call(
            move |engine| {
                Box::pin(
                    async move { engine.submit_correlated_call(envelope, extras, deadline).await },
                )
            },
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await
}

pub(crate) async fn submit_until(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
    route: Option<LocalBusFederationRoute>,
    deadline: tokio::time::Instant,
    priority: bool,
) -> Result<(), SdkError> {
    unclassified(submit_classified_until(context, envelope, route, deadline, priority).await)
}

/// Like [`submit_until`], with a certain gateway refusal in the inner `Err`.
pub(crate) async fn submit_classified_until(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
    route: Option<LocalBusFederationRoute>,
    deadline: tokio::time::Instant,
    priority: bool,
) -> Result<Result<(), SubmitRefusal>, SdkError> {
    submit_inner(context, envelope, route, deadline, priority, !priority).await
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
    // Producers that hold the account replace a caller target with the pinned home
    // before this point. A stored non-empty id is still the submit target.
    if let Some(target) =
        route.as_ref().map(|route| route.target_node_id.clone()).filter(|id| !id.is_empty())
    {
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
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if priority {
            context
                .priority_call(
                    move |engine| {
                        Box::pin(async move {
                            engine
                                .submit_envelope_classified_to(envelope, Some(target))
                                .await
                                .map(|result| result.map(|_| ()))
                        })
                    },
                    remaining,
                )
                .await
        } else {
            context
                .call(
                    move |engine| {
                        Box::pin(async move {
                            engine
                                .submit_envelope_classified_to(envelope, Some(target))
                                .await
                                .map(|result| result.map(|_| ()))
                        })
                    },
                    deadline,
                )
                .await
        }
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

/// Directory base for a stored route. `None` is the session directory. A caller URL is ignored.
pub(crate) async fn manifest_for_route(
    context: &SessionContext,
    writer: &super::writer::Writer,
    config: &GatewaySessionConfig,
    root: &str,
    route: Option<&LocalBusFederationRoute>,
) -> Result<crate::SdkDeviceManifestResponse, SdkError> {
    let base = route_base(writer, root, route).await?;
    manifest(context, config, root, base.as_deref()).await
}

/// Pin lookup for one stored route. A caller URL is not an origin.
pub(crate) struct HomeLookup<'a> {
    pub writer: &'a super::writer::Writer,
    pub commitment: &'a str,
    pub route: Option<&'a LocalBusFederationRoute>,
}

/// Pair material for a stored route. An empty request does not open a socket.
pub(crate) async fn material_for_route(
    context: &SessionContext,
    config: &GatewaySessionConfig,
    request: SendMaterialRequest,
    class: crate::bus::connection_manager::CallClass,
    home: HomeLookup<'_>,
) -> Result<SendMaterial, SdkError> {
    let base = if request.root.is_none() && request.prekey.is_none() {
        None
    } else {
        route_base(home.writer, home.commitment, home.route).await?
    };
    material(context, config, request, class, base.as_deref()).await
}

/// Submit copy of `route`. The caller node is kept only when it is the pinned home.
pub(crate) async fn pinned_submit_route(
    writer: &super::writer::Writer,
    commitment: &str,
    route: Option<LocalBusFederationRoute>,
) -> Result<Option<LocalBusFederationRoute>, SdkError> {
    let commitment = commitment.to_owned();
    writer
        .apply(move |account| {
            crate::client::recipient_home::submit_copy(&account.client, &commitment, route)
        })
        .await
}

async fn route_base(
    writer: &super::writer::Writer,
    commitment: &str,
    route: Option<&LocalBusFederationRoute>,
) -> Result<Option<String>, SdkError> {
    let Some(route) = route else { return Ok(None) };
    let commitment = commitment.to_owned();
    let caller = route.target_node_id.clone();
    let home = writer
        .apply(move |account| {
            crate::client::recipient_home::pin_choice(
                &account.client,
                &commitment,
                Some(caller.as_str()),
            )
        })
        .await?;
    crate::client::recipient_home::fetch_base(home, true).await
}
