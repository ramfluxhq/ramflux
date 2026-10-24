// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Directory lookups run only after gateway authentication and node-wide quota admission.
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime, router_post_json_async};
use ramflux_protocol::{IdentityDirectoryReason, PrincipalLookupResponse};
pub(crate) fn reject_unauthenticated(
    request: &ramflux_transport::GatewayQuicRequest,
) -> Option<ramflux_transport::GatewayQuicResponse> {
    (request.path.starts_with("/mvp1/principal-manifest/")
        || request.path == "/mvp1/principal-lookup")
        .then(|| ramflux_transport::GatewayQuicResponse {
            status: 401,
            body: serde_json::json!(PrincipalLookupResponse::<serde_json::Value> {
                manifest: None,
                reason_code: Some(IdentityDirectoryReason::AuthenticationRequired)
            }),
        })
}
pub(crate) async fn fetch(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    principal: String,
) -> anyhow::Result<()> {
    let request = ramflux_node_core::PrincipalLookupRequest {
        principal_id: principal,
        session_id: runtime.session_id.clone(),
        requester_device_id: runtime.device_id.clone(),
        target_delivery_id: runtime.target_delivery_id.clone(),
        gateway_id: context.gateway_id.clone(),
        source: context.remote_addr.ip(),
    };
    let response: PrincipalLookupResponse<ramflux_node_core::DeviceManifestResponse> =
        router_post_json_async(&context.router, "/mvp1/principal-lookup", &request).await?;
    let frame = ramflux_node_core::GatewayServerFrame::PrincipalManifest { response };
    let mut send = send.lock().await;
    ramflux_transport::write_gateway_session_json(&mut **send, &frame).await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unauthenticated_name_queries_have_one_response_for_every_name_and_never_contact_the_router()
    -> anyhow::Result<()> {
        let query = |name: &str| {
            reject_unauthenticated(&ramflux_transport::GatewayQuicRequest {
                method: "GET".into(),
                path: format!("/mvp1/principal-manifest/{name}"),
                body: serde_json::Value::Null,
            })
            .ok_or_else(|| anyhow::anyhow!("private endpoint rejection"))
        };
        assert_eq!(query("known")?.status, 401);
        assert_eq!(query("known")?.body, query("unknown")?.body);
        assert!(
            reject_unauthenticated(&ramflux_transport::GatewayQuicRequest {
                method: "GET".into(),
                path: "/mvp1/device-manifest/opaque-root".into(),
                body: serde_json::Value::Null
            })
            .is_none()
        );
        Ok(())
    }
}
