// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production registration is bound to the live session and fresh root-qualified authority.
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
pub(crate) async fn handle(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    frame: &ramflux_node_core::PushRouteRegistrationFrame,
) -> anyhow::Result<()> {
    use ramflux_node_core::{PUSH_ROUTE_PATH, PushRouteControl, PushRouteControlBody};
    crate::session::validate_gateway_session_signed_request(
        context,
        runtime,
        &frame.signed_request,
        "POST",
        PUSH_ROUTE_PATH,
        &frame.body,
    )?;
    anyhow::ensure!(
        frame.signed_request.ext.ext.get("session_id").and_then(serde_json::Value::as_str)
            == Some(runtime.session_id.as_str()),
        "push route must bind the live session id"
    );
    frame.body.validate()?;
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
    let body = PushRouteControlBody {
        authority,
        registration: frame.body.clone(),
        issued_at: ramflux_node_core::now_unix_seconds(),
    };
    let signature = context
        .notify
        .signer
        .sign_push_route_control(&ramflux_protocol::canonical_json_bytes(&body)?);
    let mesh = context
        .notify
        .mesh
        .clone()
        .ok_or_else(|| anyhow::anyhow!("push route requires notify mesh"))?;
    let expires_at: u64 = tokio::task::spawn_blocking(move || {
        ramflux_transport::mesh_quic_post_json_with_peer_ca_pems(
            &mesh.endpoint,
            PUSH_ROUTE_PATH,
            &mesh.tls,
            &mesh.server_name,
            &mesh.peer_ca_pems,
            &PushRouteControl { body, signature },
        )
    })
    .await??;
    let mut send = send.lock().await;
    ramflux_transport::write_gateway_session_json(
        &mut **send,
        &ramflux_node_core::GatewayServerFrame::PushRouteRegistered { expires_at },
    )
    .await?;
    Ok(())
}
