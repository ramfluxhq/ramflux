// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{RouterMeshClient, router_get_json, router_post_json};

pub(crate) fn dispatch_quic_json_request(
    router: &RouterMeshClient,
    request: ramflux_transport::GatewayQuicRequest,
) -> anyhow::Result<ramflux_transport::GatewayQuicResponse> {
    tracing::info!(
        method = %request.method,
        path = %request.path,
        "gateway QUIC request received"
    );
    let body = match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/mvp0/envelope") => {
            let envelope: ramflux_protocol::Envelope = serde_json::from_value(request.body)?;
            ramflux_node_core::record_gateway_submit_received();
            let response: ramflux_node_core::ItestMvp0SubmitResponse =
                router_post_json(router, "/mvp0/envelope", &envelope)?;
            tracing::info!(
                envelope_id = %envelope.envelope_id,
                target_delivery_id = %envelope.target_delivery_id,
                outcome = %response.outcome,
                "gateway QUIC forwarded envelope to router"
            );
            serde_json::to_value(response)?
        }
        ("POST", "/mvp0/ack") => {
            let ack: ramflux_protocol::Ack = serde_json::from_value(request.body)?;
            let response: ramflux_node_core::ItestMvp0CursorResponse =
                router_post_json(router, "/mvp0/ack", &ack)?;
            serde_json::to_value(response)?
        }
        ("POST", "/mvp1/identity/register") => {
            let registration: ramflux_node_core::ItestMvp1RegisterIdentityRequest =
                serde_json::from_value(request.body)?;
            let response: ramflux_node_core::ItestMvp1IdentityRegistrationResponse =
                router_post_json(router, "/mvp1/identity/register", &registration)?;
            serde_json::to_value(response)?
        }
        ("POST", "/mvp1/prekey/publish") => {
            let prekey: ramflux_node_core::ItestMvp1PublishPrekeyRequest =
                serde_json::from_value(request.body)?;
            let response: ramflux_node_core::ItestMvp1PrekeyResponse =
                router_post_json(router, "/mvp1/prekey/publish", &prekey)?;
            serde_json::to_value(response)?
        }
        ("POST", "/mvp1/device/revoke") => {
            let revoke: ramflux_node_core::ItestMvp1RevokeDeviceRequest =
                serde_json::from_value(request.body)?;
            let response: ramflux_node_core::ItestMvp1RevokeDeviceResponse =
                router_post_json(router, "/mvp1/device/revoke", &revoke)?;
            serde_json::to_value(response)?
        }
        ("GET", path) if path.starts_with("/mvp0/cursor/") => {
            let response: Option<ramflux_node_core::ItestMvp0CursorResponse> =
                router_get_json(router, path)?;
            serde_json::to_value(response)?
        }
        ("GET", path) if path.starts_with("/mvp1/prekey/") => {
            let response: ramflux_node_core::ItestMvp1PrekeyResponse =
                router_get_json(router, path)?;
            serde_json::to_value(response)?
        }
        ("GET", path) if path.starts_with("/mvp1/device-manifest/") => {
            let response: Option<ramflux_node_core::ItestMvp1DeviceManifestResponse> =
                router_get_json(router, path)?;
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
