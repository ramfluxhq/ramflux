// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated own-device push test (`device.push_route.test`).
//!
//! The session's own device is the only target. The gateway commits a signed `WakeV2` of class
//! `t` through the same dedup table as an offline wake, then posts it to notify. Notify admits it
//! into the wake WAL and queue; the reply means queued, not delivered.

use crate::push_registration::{bind_session, reply_or_log, session_authority};
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
use ramflux_node_core::{
    GatewayServerFrame, PUSH_ROUTE_TEST_PATH, PUSH_ROUTE_TEST_SIGNED_PATH, PushRouteTestAnswer,
    PushRouteTestFrame,
};
use std::time::Duration;

/// Upper bound for the whole test exchange with notify.
const PUSH_TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Answers one signed push-test frame on the session.
pub(crate) async fn handle(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    frame: PushRouteTestFrame,
) {
    let request_id = frame.signed_request.request_id.clone();
    let answer = match tokio::time::timeout(
        PUSH_TEST_TIMEOUT,
        admit_and_send(context, runtime, &frame),
    )
    .await
    {
        Ok(Ok(answer)) => answer,
        Ok(Err(error)) => {
            tracing::warn!(%error, "push test refused");
            PushRouteTestAnswer::refused("unavailable", None)
        }
        Err(_elapsed) => PushRouteTestAnswer::refused("unavailable", None),
    };
    reply_or_log(
        send,
        &GatewayServerFrame::PushRouteTested {
            request_id,
            status: answer.status,
            reason: answer.reason,
            retry_after_ms: answer.retry_after_ms,
        },
    )
    .await;
}

async fn admit_and_send(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    frame: &PushRouteTestFrame,
) -> anyhow::Result<PushRouteTestAnswer> {
    if bind_session(context, runtime, PUSH_ROUTE_TEST_SIGNED_PATH, &frame.signed_request, &frame.body)
        .await
        .is_err()
    {
        return Ok(PushRouteTestAnswer::refused("rejected", None));
    }
    match frame.body.class.as_deref() {
        None | Some("alert") => {}
        // PushKit has no test payload yet; refused rather than sent on another path.
        Some("voip") => return Ok(PushRouteTestAnswer::refused("unsupported_class", None)),
        Some(_) => return Ok(PushRouteTestAnswer::refused("rejected", None)),
    }
    let Some(authority) = session_authority(context, runtime).await? else {
        return Ok(PushRouteTestAnswer::refused("rejected", None));
    };
    let target = authority.target_delivery_id.clone();
    let Some(owner) = crate::clients::lookup_target_owner_epoch(&context.router, &target).await
    else {
        return Ok(PushRouteTestAnswer::refused("unavailable", None));
    };
    let now = ramflux_node_core::now_unix_seconds();
    let Some(signed) = crate::notify_wake::signed_test_wake(
        &context.store,
        &context.notify.signer,
        &runtime.source_identity.storage_key(),
        &target,
        owner.device_epoch,
        now,
    )?
    else {
        return Ok(PushRouteTestAnswer::refused("unavailable", None));
    };
    post_test_wake(context, &target, signed).await
}

#[derive(serde::Serialize)]
struct PushTestRequest<'a> {
    device_delivery_id: &'a str,
    signed_wake: ramflux_protocol::SignedWakeV2,
}

/// Posts the signed test wake to notify over the mesh and returns notify's answer.
async fn post_test_wake(
    context: &GatewayQuicContext,
    target: &str,
    signed: ramflux_protocol::SignedWakeV2,
) -> anyhow::Result<PushRouteTestAnswer> {
    let request = PushTestRequest { device_delivery_id: target, signed_wake: signed };
    let mesh = context
        .notify
        .mesh
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("push test requires notify mesh"))?;
    let answer: PushRouteTestAnswer = ramflux_transport::mesh_quic_post_json_with_peer_ca_pems_async(
        &mesh.endpoint,
        PUSH_ROUTE_TEST_PATH,
        &mesh.tls,
        &mesh.server_name,
        &mesh.peer_ca_pems,
        &request,
    )
    .await?;
    Ok(answer)
}
