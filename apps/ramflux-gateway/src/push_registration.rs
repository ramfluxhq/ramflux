// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production registration is bound to the live session and fresh root-qualified authority.
//!
//! Route control runs detached from the session loop and is bounded, so a slow router or notify
//! never delays submits, ACKs or heartbeats. Every reply carries the signed request id.
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
use ramflux_node_core::{GatewayServerFrame, PUSH_ROUTE_PATH};

/// Upper bound for one route-control exchange with router and notify.
const PUSH_ROUTE_CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Validates the session binding inline, then answers asynchronously.
pub(crate) fn spawn_register(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    frame: ramflux_node_core::PushRouteRegistrationFrame,
) {
    let request_id = frame.signed_request.request_id.clone();
    let checked =
        bind_session(context, runtime, PUSH_ROUTE_PATH, &frame.signed_request, &frame.body)
            .and_then(|()| Ok(frame.body.validate()?));
    let (send, context, runtime) = (send.clone(), context.clone(), runtime.clone());
    tokio::spawn(async move {
        let outcome = match checked {
            Ok(()) => bounded(register(&context, &runtime, frame.body)).await,
            Err(error) => Err(error),
        };
        let reply = match outcome {
            Ok(expires_at) => {
                GatewayServerFrame::PushRouteRegistered { expires_at, request_id: Some(request_id) }
            }
            Err(error) => refused(request_id, &error),
        };
        reply_or_log(&send, &reply).await;
    });
}

/// Deletes this device's routes on explicit deregistration.
pub(crate) fn spawn_deregister(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    frame: ramflux_node_core::PushRouteDeregistrationFrame,
) {
    let request_id = frame.signed_request.request_id.clone();
    let checked = bind_session(
        context,
        runtime,
        ramflux_node_core::PUSH_ROUTE_DELETE_PATH,
        &frame.signed_request,
        &frame.body,
    );
    let (send, context, runtime) = (send.clone(), context.clone(), runtime.clone());
    tokio::spawn(async move {
        let outcome = match checked {
            Ok(()) => bounded(deregister(&context, &runtime, frame.body)).await,
            Err(error) => Err(error),
        };
        let reply = match outcome {
            Ok(removed) => GatewayServerFrame::PushRouteDeregistered { request_id, removed },
            Err(error) => refused(request_id, &error),
        };
        reply_or_log(&send, &reply).await;
    });
}

fn bind_session<T: serde::Serialize>(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    path: &str,
    signed_request: &ramflux_protocol::SignedRequest,
    body: &T,
) -> anyhow::Result<()> {
    crate::session::validate_gateway_session_signed_request(
        context,
        runtime,
        signed_request,
        "POST",
        path,
        body,
    )?;
    anyhow::ensure!(
        signed_request.ext.ext.get("session_id").and_then(serde_json::Value::as_str)
            == Some(runtime.session_id.as_str()),
        "push route must bind the live session id"
    );
    Ok(())
}

async fn bounded<T>(
    work: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::time::timeout(PUSH_ROUTE_CONTROL_TIMEOUT, work)
        .await
        .map_err(|_| anyhow::anyhow!("push route control timed out"))?
}

fn refused(request_id: String, error: &anyhow::Error) -> GatewayServerFrame {
    tracing::warn!(%error, "push route control refused");
    GatewayServerFrame::PushRouteRefused {
        request_id,
        reason: "push route registration refused".to_owned(),
    }
}

async fn reply_or_log(send: &GatewaySendHandle, frame: &GatewayServerFrame) {
    let mut send = send.lock().await;
    if let Err(error) = ramflux_transport::write_gateway_session_json(&mut **send, frame).await {
        tracing::debug!(%error, "push route reply not delivered; session closed");
    }
}

/// Current, non-revoked router authority for exactly this session's device.
async fn session_authority(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
) -> anyhow::Result<ramflux_node_core::DeviceAuthKeyResponse> {
    let qualified = ramflux_protocol::qualified_device_id(
        runtime.source_identity.root_commitment(),
        runtime.source_identity.device_id(),
    )?;
    let authority: Option<ramflux_node_core::DeviceAuthKeyResponse> = crate::router_get_json_async(
        &context.router,
        &format!("/mvp1/device-auth-key/{qualified}"),
    )
    .await?;
    let authority = authority.ok_or_else(|| anyhow::anyhow!("push route authority unavailable"))?;
    anyhow::ensure!(
        authority.authenticated_device_identity()? == runtime.source_identity
            && authority.branch_public_key == runtime.branch_public_key
            && authority.device_epoch == runtime.device_epoch
            && authority.target_delivery_id == runtime.target_delivery_id,
        "push route session authority changed"
    );
    Ok(authority)
}

async fn register(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    registration: ramflux_node_core::PushRouteRegistration,
) -> anyhow::Result<u64> {
    use ramflux_node_core::{PushRouteControl, PushRouteControlBody};
    let authority = session_authority(context, runtime).await?;
    // A still-open session of a revoked device must not register or renew a route.
    anyhow::ensure!(!authority.revoked, "push route device revoked");
    let body = PushRouteControlBody {
        authority,
        registration,
        issued_at: ramflux_node_core::now_unix_seconds(),
    };
    let signature = context
        .notify
        .signer
        .sign_push_route_control(&ramflux_protocol::canonical_json_bytes(&body)?);
    post_notify(context, PUSH_ROUTE_PATH, PushRouteControl { body, signature }).await
}

async fn deregister(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    request: ramflux_node_core::PushRouteDeregistration,
) -> anyhow::Result<u64> {
    use ramflux_node_core::{PushRouteDeleteBody, PushRouteDeleteControl};
    let body = PushRouteDeleteBody {
        authority: session_authority(context, runtime).await?,
        provider: request.provider,
        issued_at: ramflux_node_core::now_unix_seconds(),
    };
    let signature = context
        .notify
        .signer
        .sign_push_route_delete(&ramflux_protocol::canonical_json_bytes(&body)?);
    post_notify(
        context,
        ramflux_node_core::PUSH_ROUTE_DELETE_PATH,
        PushRouteDeleteControl { body, signature },
    )
    .await
}

async fn post_notify<T: serde::Serialize + Send + 'static>(
    context: &GatewayQuicContext,
    path: &'static str,
    control: T,
) -> anyhow::Result<u64> {
    let mesh = context
        .notify
        .mesh
        .clone()
        .ok_or_else(|| anyhow::anyhow!("push route requires notify mesh"))?;
    Ok(tokio::task::spawn_blocking(move || {
        ramflux_transport::mesh_quic_post_json_with_peer_ca_pems(
            &mesh.endpoint,
            path,
            &mesh.tls,
            &mesh.server_name,
            &mesh.peer_ca_pems,
            &control,
        )
    })
    .await??)
}
