// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Voice leases require current caller registration and a signed request on the live session.
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
use ramflux_protocol::{
    VoiceAllocation, VoiceLeaseFrame, VoiceLeaseRequest, VoiceLeaseResponse, VoiceLeaseStatus,
};
pub(crate) async fn handle(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    request: &VoiceLeaseFrame,
) -> anyhow::Result<()> {
    let result = issue(context, runtime, request).await;
    let response = match result {
        Ok(response) => {
            ramflux_node_core::GatewayServerFrame::VoiceLease { response: Box::new(response) }
        }
        Err(_) => {
            ramflux_node_core::GatewayServerFrame::Nack { reason: "voice lease rejected".into() }
        }
    };
    let mut send = send.lock().await;
    ramflux_transport::write_gateway_session_json(&mut **send, &response).await?;
    Ok(())
}
async fn issue(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    request: &VoiceLeaseFrame,
) -> anyhow::Result<VoiceLeaseResponse> {
    crate::session::validate_gateway_session_signed_request(
        context,
        runtime,
        &request.signed_request,
        "POST",
        "/voice/v1/lease",
        &request.body,
    )?;
    let scope = match &request.body {
        VoiceLeaseRequest::Allocate { scope }
        | VoiceLeaseRequest::Renew { scope }
        | VoiceLeaseRequest::Release { scope } => scope,
    };
    ramflux_node_core::validate_voice_scope(scope)?;
    if scope.caller.device_id != runtime.device_id
        || scope.caller.principal_id != runtime.principal_id
    {
        anyhow::bail!("voice caller mismatch");
    }
    // Query the current registry for every mutation; session-open state is not revocation authority.
    let lookup = ramflux_node_core::PrincipalLookupRequest {
        principal_id: runtime.principal_id.clone(),
        session_id: runtime.session_id.clone(),
        requester_device_id: runtime.device_id.clone(),
        target_delivery_id: runtime.target_delivery_id.clone(),
        gateway_id: context.gateway_id.clone(),
        source: context.remote_addr.ip(),
    };
    let lookup: ramflux_protocol::PrincipalLookupResponse<
        ramflux_node_core::DeviceManifestResponse,
    > = crate::router_post_json_async(&context.router, "/mvp1/principal-lookup", &lookup).await?;
    let manifest =
        lookup.manifest.ok_or_else(|| anyhow::anyhow!("voice caller authority unavailable"))?;
    if manifest.principal_id != scope.caller.principal_id
        || manifest.root_public_key != scope.caller.root_public_key
        || !manifest.devices.iter().any(|d| {
            d.device_id == runtime.device_id && d.branch_public_key == runtime.branch_public_key
        })
    {
        anyhow::bail!("voice caller authority changed");
    }
    let endpoint = std::env::var("RAMFLUX_RELAY_VOICE_CONTROL_ENDPOINT")
        .map_err(|_| anyhow::anyhow!("voice relay is not configured"))?;
    let tls = context.peers.tls().clone();
    let body = request.body.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<VoiceLeaseResponse> {
        let client = ramflux_transport::MeshHttpClient::new();
        if let VoiceLeaseRequest::Allocate { .. } = &body {
            let allocation: VoiceAllocation =
                client.post_json(&endpoint, "/voice/v1/lease", &tls, "ramflux-relay", &body)?;
            Ok(VoiceLeaseResponse::Allocation { allocation })
        } else {
            let status: VoiceLeaseStatus =
                client.post_json(&endpoint, "/voice/v1/lease", &tls, "ramflux-relay", &body)?;
            Ok(VoiceLeaseResponse::Status { status })
        }
    })
    .await?
}
