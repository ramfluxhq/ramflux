// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated own-device push test (`device.push_route.test`).
//!
//! The session's own device is the only target and the request names one of its own route tags.
//! The gateway signs a `WakeV2` of class `t` and posts it with the tag to notify, which resolves
//! the route (unknown or foreign tag, `VoIP` route), applies the rate limit and admits the wake.
//! The reply means queued, not delivered.

use crate::push_registration::{bind_session, post_notify, reply_or_log, session_authority};
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
use ramflux_node_core::{
    GatewayServerFrame, PUSH_ROUTE_TEST_PATH, PUSH_ROUTE_TEST_SIGNED_PATH, PushRouteTestAnswer,
    PushRouteTestFrame, PushRouteTestMeshRequest, push_route_tag_valid,
};
use std::time::Duration;

/// Upper bound for the whole test exchange with router and notify.
const PUSH_TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Answers one signed push-test frame on the session.
pub(crate) async fn handle(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    frame: PushRouteTestFrame,
) {
    let request_id = frame.signed_request.request_id.clone();
    let answer =
        match tokio::time::timeout(PUSH_TEST_TIMEOUT, admit_and_send(context, runtime, &frame))
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
        || !push_route_tag_valid(&frame.body.route_tag)
    {
        return Ok(PushRouteTestAnswer::refused("rejected", None));
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
    let Some(signed_wake) = crate::notify_wake::signed_test_wake(
        &context.notify.signer,
        &target,
        owner.device_epoch,
        now,
    ) else {
        return Ok(PushRouteTestAnswer::refused("unavailable", None));
    };
    let request = PushRouteTestMeshRequest {
        device_delivery_id: target,
        signed_wake,
        route_tag: frame.body.route_tag.clone(),
    };
    post_notify(context, PUSH_ROUTE_TEST_PATH, &request).await
}
