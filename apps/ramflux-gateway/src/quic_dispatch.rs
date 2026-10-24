// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{RouterMeshClient, router_get_json_async, router_post_json, router_post_json_async};
use std::time::Instant;

pub(crate) async fn dispatch_quic_json_request(
    router: &RouterMeshClient,
    request: ramflux_transport::GatewayQuicRequest,
    source: std::net::IpAddr,
) -> anyhow::Result<ramflux_transport::GatewayQuicResponse> {
    if let Some(response) = crate::principal_directory::reject_unauthenticated(&request) {
        return Ok(response);
    }
    tracing::info!(
        method = %request.method,
        path = %request.path,
        "gateway QUIC request received"
    );
    let body = match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/mvp0/envelope") => forward_quic_envelope(router, request.body).await?,
        ("POST", "/mvp0/ack") => {
            let ack: ramflux_protocol::Ack = serde_json::from_value(request.body)?;
            let response: ramflux_node_core::InboxCursorResponse =
                router_post_json(router, "/mvp0/ack", &ack)?;
            serde_json::to_value(response)?
        }
        ("POST", "/mvp2/device-set") => {
            let request: ramflux_node_core::DeviceSetPublishRequest =
                serde_json::from_value(request.body)?;
            let response: ramflux_protocol::SignedDeviceSetRecord =
                router_post_json(router, "/mvp2/device-set", &request)?;
            serde_json::to_value(response)?
        }
        ("GET", path) if path.starts_with("/mvp2/device-set/") => {
            let response: Option<ramflux_protocol::SignedDeviceSetRecord> =
                router_get_json_async(router, path).await?;
            serde_json::to_value(response)?
        }
        ("POST", "/mvp1/identity/register") => {
            let mut registration: ramflux_node_core::IdentityRegisterRequest =
                serde_json::from_value(request.body)?;
            crate::principal_directory::registration_context(&mut registration, source)?;
            let response: serde_json::Value =
                router_post_json(router, "/mvp1/identity/register", &registration)?;
            if serde_json::from_value::<ramflux_protocol::IdentityRegistrationFailure>(
                response.clone(),
            )
            .is_ok()
            {
                return Ok(ramflux_transport::GatewayQuicResponse { status: 409, body: response });
            }
            response
        }
        ("POST", "/mvp1/prekey/publish") => {
            let prekey: ramflux_node_core::PrekeyPublishRequest =
                serde_json::from_value(request.body)?;
            let response: ramflux_node_core::PrekeyResponse =
                router_post_json(router, "/mvp1/prekey/publish", &prekey)?;
            serde_json::to_value(response)?
        }
        ("POST", "/mvp1/device/revoke") => {
            let revoke: ramflux_node_core::DeviceRevokeRequest =
                serde_json::from_value(request.body)?;
            let response: ramflux_node_core::DeviceRevokeResponse =
                router_post_json(router, "/mvp1/device/revoke", &revoke)?;
            serde_json::to_value(response)?
        }
        ("GET", path) if path.starts_with("/mvp0/cursor/") => {
            let response: Option<ramflux_node_core::InboxCursorResponse> =
                router_get_json_async(router, path).await?;
            serde_json::to_value(response)?
        }
        ("GET", path) if path.starts_with("/mvp1/prekey/") => {
            let response: ramflux_node_core::PrekeyResponse =
                match router_get_json_async(router, path).await {
                    Ok(response) => response,
                    Err(error) => return Ok(lookup_error(&error)),
                };
            serde_json::to_value(response)?
        }
        ("GET", path) if path.starts_with("/mvp1/device-manifest/") => {
            let response: Option<ramflux_node_core::DeviceManifestResponse> =
                router_get_json_async(router, path).await?;
            serde_json::to_value(response)?
        }
        _ => {
            return Ok(ramflux_transport::GatewayQuicResponse {
                status: 404,
                body: serde_json::json!({ "error": "not found" }),
            });
        }
    };
    Ok(ramflux_transport::GatewayQuicResponse { status: 200, body })
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn lookup_error(error: &dyn std::fmt::Display) -> ramflux_transport::GatewayQuicResponse {
    ramflux_transport::GatewayQuicResponse {
        status: 400,
        body: serde_json::json!({"error":error.to_string()}),
    }
}

async fn forward_quic_envelope(
    router: &RouterMeshClient,
    body: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let total_started = Instant::now();
    let decode_started = Instant::now();
    let envelope: ramflux_protocol::Envelope = serde_json::from_value(body)?;
    ramflux_node_core::record_gateway_submit_decode_us(elapsed_us(decode_started));
    ramflux_node_core::record_gateway_submit_received();
    let router_started = Instant::now();
    let response: ramflux_node_core::EnvelopeSubmitResponse =
        router_post_json_async(router, "/mvp0/envelope", &envelope).await?;
    ramflux_node_core::record_gateway_submit_router_us(elapsed_us(router_started));
    tracing::info!(
        envelope_id = %envelope.envelope_id,
        target_delivery_id = %envelope.target_delivery_id,
        outcome = %response.outcome,
        "gateway QUIC forwarded envelope to router"
    );
    let response_started = Instant::now();
    let body = serde_json::to_value(response)?;
    ramflux_node_core::record_gateway_submit_response_encode_us(elapsed_us(response_started));
    ramflux_node_core::record_gateway_submit_total_us(elapsed_us(total_started));
    Ok(body)
}
