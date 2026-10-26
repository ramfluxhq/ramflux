// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production registration is bound to the live session and fresh root-qualified authority.
//!
//! Route control never runs inside the session loop. Each session has one serial worker: at
//! most one control is in flight, a newer control replaces a queued one (latest intent wins,
//! the replaced one is answered `superseded`), and every exchange with router and notify is
//! bounded and cancelled at the bound. Every answer carries the signed request id.
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
use ramflux_node_core::{GatewayServerFrame, PUSH_ROUTE_PATH, PushRouteRefusal};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Upper bound for one route-control exchange with router and notify.
const PUSH_ROUTE_CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// One admitted push route control request.
pub(crate) enum RouteIntent {
    Register(ramflux_node_core::PushRouteRegistrationFrame),
    Deregister(ramflux_node_core::PushRouteDeregistrationFrame),
}

impl RouteIntent {
    fn request_id(&self) -> &str {
        match self {
            Self::Register(frame) => &frame.signed_request.request_id,
            Self::Deregister(frame) => &frame.signed_request.request_id,
        }
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type Execute = Arc<dyn Fn(RouteIntent) -> BoxFuture<GatewayServerFrame> + Send + Sync>;
type Reply = Arc<dyn Fn(GatewayServerFrame) -> BoxFuture<()> + Send + Sync>;

/// Per-session serial executor with latest-intent-wins coalescing.
pub(crate) struct RouteControlQueue {
    slot: Arc<tokio::sync::Mutex<Option<RouteIntent>>>,
    wake: Arc<tokio::sync::Notify>,
    reply: Reply,
    worker: tokio::task::JoinHandle<()>,
}

impl Drop for RouteControlQueue {
    fn drop(&mut self) {
        // The session ended: cancel the in-flight exchange together with the worker.
        self.worker.abort();
    }
}

impl RouteControlQueue {
    pub(crate) fn start(execute: Execute, reply: Reply) -> Self {
        let slot: Arc<tokio::sync::Mutex<Option<RouteIntent>>> = Arc::default();
        let wake = Arc::new(tokio::sync::Notify::new());
        let worker = tokio::spawn({
            let (slot, wake, reply) = (Arc::clone(&slot), Arc::clone(&wake), Arc::clone(&reply));
            async move {
                loop {
                    let next = slot.lock().await.take();
                    match next {
                        Some(intent) => reply(execute(intent).await).await,
                        None => wake.notified().await,
                    }
                }
            }
        });
        Self { slot, wake, reply, worker }
    }

    /// Queues `intent`; a queued but not yet started intent is answered `superseded`.
    pub(crate) async fn submit(&self, intent: RouteIntent) {
        let replaced = self.slot.lock().await.replace(intent);
        self.wake.notify_one();
        if let Some(replaced) = replaced {
            (self.reply)(refused(replaced.request_id().to_owned(), PushRouteRefusal::Superseded))
                .await;
        }
    }

    /// Production queue for one authenticated session.
    pub(crate) fn for_session(
        send: &GatewaySendHandle,
        context: &GatewayQuicContext,
        runtime: &GatewaySessionRuntime,
    ) -> Self {
        let (context, runtime) = (context.clone(), runtime.clone());
        let execute: Execute = Arc::new(move |intent| {
            let (context, runtime) = (context.clone(), runtime.clone());
            Box::pin(async move { execute(&context, &runtime, intent).await })
        });
        let send = send.clone();
        let reply: Reply = Arc::new(move |frame| {
            let send = send.clone();
            Box::pin(async move { reply_or_log(&send, &frame).await })
        });
        Self::start(execute, reply)
    }
}

/// Validates the signed session binding inline; only admitted requests reach the queue.
pub(crate) async fn admit(
    queue: &RouteControlQueue,
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    intent: RouteIntent,
) {
    let checked = match &intent {
        RouteIntent::Register(frame) => {
            bind_session(context, runtime, PUSH_ROUTE_PATH, &frame.signed_request, &frame.body)
                .and_then(|()| Ok(frame.body.validate()?))
        }
        RouteIntent::Deregister(frame) => bind_session(
            context,
            runtime,
            ramflux_node_core::PUSH_ROUTE_DELETE_PATH,
            &frame.signed_request,
            &frame.body,
        ),
    };
    match checked {
        Ok(()) => queue.submit(intent).await,
        Err(error) => {
            tracing::warn!(%error, "push route control refused");
            reply_or_log(
                send,
                &refused(intent.request_id().to_owned(), PushRouteRefusal::Rejected),
            )
            .await;
        }
    }
}

async fn execute(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    intent: RouteIntent,
) -> GatewayServerFrame {
    let request_id = intent.request_id().to_owned();
    let outcome = tokio::time::timeout(PUSH_ROUTE_CONTROL_TIMEOUT, async {
        match intent {
            RouteIntent::Register(frame) => register(context, runtime, frame.body).await,
            RouteIntent::Deregister(frame) => deregister(context, runtime, frame.body).await,
        }
    })
    .await;
    match outcome {
        Ok(Ok(Answer::Registered(expires_at))) => {
            GatewayServerFrame::PushRouteRegistered { expires_at, request_id: Some(request_id) }
        }
        Ok(Ok(Answer::Deregistered(removed))) => {
            GatewayServerFrame::PushRouteDeregistered { request_id, removed }
        }
        Ok(Ok(Answer::Refused(code))) => refused(request_id, code),
        Ok(Err(error)) => {
            tracing::warn!(%error, "push route control failed");
            refused(request_id, PushRouteRefusal::Unavailable)
        }
        Err(_elapsed) => refused(request_id, PushRouteRefusal::Unavailable),
    }
}

enum Answer {
    Registered(u64),
    Deregistered(u64),
    Refused(PushRouteRefusal),
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

fn refused(request_id: String, code: PushRouteRefusal) -> GatewayServerFrame {
    GatewayServerFrame::PushRouteRefused {
        request_id,
        reason: "push route registration refused".to_owned(),
        code,
    }
}

async fn reply_or_log(send: &GatewaySendHandle, frame: &GatewayServerFrame) {
    let mut send = send.lock().await;
    if let Err(error) = ramflux_transport::write_gateway_session_json(&mut **send, frame).await {
        tracing::debug!(%error, "push route reply not delivered; session closed");
    }
}

/// Current router authority for exactly this session's device; revoked records are refused.
async fn session_authority(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
) -> anyhow::Result<Option<ramflux_node_core::DeviceAuthKeyResponse>> {
    let qualified = ramflux_protocol::qualified_device_id(
        runtime.source_identity.root_commitment(),
        runtime.source_identity.device_id(),
    )?;
    let authority: Option<ramflux_node_core::DeviceAuthKeyResponse> = crate::router_get_json_async(
        &context.router,
        &format!("/mvp1/device-auth-key/{qualified}"),
    )
    .await?;
    let Some(authority) = authority else {
        return Ok(None);
    };
    let current = !authority.revoked
        && authority.authenticated_device_identity().is_ok_and(|id| id == runtime.source_identity)
        && authority.branch_public_key == runtime.branch_public_key
        && authority.device_epoch == runtime.device_epoch
        && authority.target_delivery_id == runtime.target_delivery_id;
    Ok(current.then_some(authority))
}

async fn register(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    registration: ramflux_node_core::PushRouteRegistration,
) -> anyhow::Result<Answer> {
    use ramflux_node_core::{PushRouteControl, PushRouteControlBody, PushRouteRegisterAnswer};
    let Some(authority) = session_authority(context, runtime).await? else {
        return Ok(Answer::Refused(PushRouteRefusal::Rejected));
    };
    let body = PushRouteControlBody {
        authority,
        registration,
        issued_at: ramflux_node_core::now_unix_seconds(),
    };
    let signature = context
        .notify
        .signer
        .sign_push_route_control(&ramflux_protocol::canonical_json_bytes(&body)?);
    let answer: PushRouteRegisterAnswer =
        post_notify(context, PUSH_ROUTE_PATH, &PushRouteControl { body, signature }).await?;
    Ok(match answer {
        PushRouteRegisterAnswer::Registered { expires_at } => Answer::Registered(expires_at),
        PushRouteRegisterAnswer::Refused { code } => Answer::Refused(code),
    })
}

async fn deregister(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    request: ramflux_node_core::PushRouteDeregistration,
) -> anyhow::Result<Answer> {
    use ramflux_node_core::{PushRouteDeleteBody, PushRouteDeleteControl};
    let Some(authority) = session_authority(context, runtime).await? else {
        return Ok(Answer::Refused(PushRouteRefusal::Rejected));
    };
    let body = PushRouteDeleteBody {
        authority,
        provider: request.provider,
        issued_at: ramflux_node_core::now_unix_seconds(),
    };
    let signature = context
        .notify
        .signer
        .sign_push_route_delete(&ramflux_protocol::canonical_json_bytes(&body)?);
    let removed: u64 = post_notify(
        context,
        ramflux_node_core::PUSH_ROUTE_DELETE_PATH,
        &PushRouteDeleteControl { body, signature },
    )
    .await?;
    Ok(Answer::Deregistered(removed))
}

/// Async mesh request: dropping it at the control bound cancels the exchange.
async fn post_notify<T: serde::Serialize, R: serde::de::DeserializeOwned>(
    context: &GatewayQuicContext,
    path: &str,
    control: &T,
) -> anyhow::Result<R> {
    let mesh = context
        .notify
        .mesh
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("push route requires notify mesh"))?;
    Ok(ramflux_transport::mesh_quic_post_json_with_peer_ca_pems_async(
        &mesh.endpoint,
        path,
        &mesh.tls,
        &mesh.server_name,
        &mesh.peer_ca_pems,
        control,
    )
    .await?)
}

#[cfg(test)]
#[path = "push_registration_tests.rs"]
mod tests;
