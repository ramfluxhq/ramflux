// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A gateway channel whose router session was closed is no longer a live agent session.

use crate::{GatewayQuicContext, GatewaySendHandle, router_session_async};

/// `true` when the router has closed this target's session. A missing session or a
/// router error leaves the channel up; only an explicit close drops it.
pub(crate) async fn channel_closed(context: &GatewayQuicContext, target: &str) -> bool {
    match router_session_async(&context.router, target).await {
        Ok(Some(session)) => session.lifecycle == ramflux_node_core::SessionLifecycle::Closed,
        _ => false,
    }
}

/// Nack a submit or heartbeat on a closed router session and tell the caller to drop it.
///
/// # Errors
/// Returns an error when the nack cannot be written.
pub(crate) async fn refuse_closed_channel(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    frame: &ramflux_node_core::GatewayClientFrame,
    target: &str,
) -> anyhow::Result<bool> {
    let watched = matches!(
        frame,
        ramflux_node_core::GatewayClientFrame::Submit { .. }
            | ramflux_node_core::GatewayClientFrame::Heartbeat { .. }
    );
    if !watched || !channel_closed(context, target).await {
        return Ok(false);
    }
    crate::session::write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Nack { reason: "recipient unreachable".to_owned() },
    )
    .await?;
    Ok(true)
}
