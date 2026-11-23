// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Chooses local delivery or a home forward for one gateway submit.

use crate::RouterMeshClient;
use crate::clients::router_post_json_async;

pub(crate) enum Route<'a> {
    Local,
    Remote(&'a str),
    Refused(&'static str),
}

pub(crate) fn route_frame<'a>(
    local_node: &str,
    submit: &'a ramflux_node_core::GatewaySubmitFrame,
) -> Route<'a> {
    let call = submit.call_intent.is_some()
        || submit.wake_id.is_some()
        || submit.call_ref.is_some()
        || submit.call_terminal.is_some()
        || submit.call_context.is_some();
    route(local_node, submit.target_node.as_deref(), call)
}

pub(crate) fn route<'a>(local_node: &str, target: Option<&'a str>, call: bool) -> Route<'a> {
    let Some(target) = target.map(str::trim).filter(|value| !value.is_empty()) else {
        return Route::Local;
    };
    if !node_id(target) {
        return Route::Refused("rejected_target_node");
    }
    if target == local_node {
        return Route::Local;
    }
    if call {
        return Route::Refused("rejected_target_node");
    }
    Route::Remote(target)
}

fn node_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

pub(crate) async fn ack_home_forward(
    send: &crate::state::GatewaySendHandle,
    runtime: &crate::state::GatewaySessionRuntime,
    response: &ramflux_node_core::EnvelopeSubmitResponse,
    envelope: &ramflux_protocol::Envelope,
) -> anyhow::Result<bool> {
    if response.outcome != "forwarded" {
        return Ok(false);
    }
    anyhow::ensure!(
        response.target_delivery_id == envelope.target_delivery_id,
        "forward acknowledgement target does not match submitted envelope"
    );
    let frame = if runtime.supports_forward_ack {
        ramflux_node_core::GatewayServerFrame::ForwardAck {
            ack: ramflux_node_core::GatewayForwardAck {
                envelope_id: envelope.envelope_id.clone(),
                target_delivery_id: response.target_delivery_id.clone(),
                inbox_seq: response.inbox_seq,
            },
        }
    } else {
        ramflux_node_core::GatewayServerFrame::Nack { reason: response.outcome.clone() }
    };
    crate::session::write_gateway_handle(send, &frame).await?;
    Ok(true)
}

pub(crate) async fn post(
    router: &RouterMeshClient,
    decision: Route<'_>,
    envelope: &ramflux_protocol::Envelope,
) -> Result<serde_json::Value, ramflux_transport::TransportError> {
    match decision {
        Route::Local | Route::Refused(_) => {
            router_post_json_async(router, "/mvp0/envelope", envelope).await
        }
        Route::Remote(target_node) => {
            let body = ramflux_node_core::HomeSubmitForward {
                target_node: target_node.to_owned(),
                envelope: envelope.clone(),
            };
            router_post_json_async(router, "/internal/cross-node/submit", &body).await
        }
    }
}
