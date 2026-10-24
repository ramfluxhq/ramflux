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

pub(crate) fn registration_context(
    request: &mut ramflux_node_core::IdentityRegisterRequest,
    source: std::net::IpAddr,
) -> anyhow::Result<()> {
    request.source_ip_hash = Some(ramflux_node_core::source_ip_hash(&source.to_string()));
    request.now = i64::try_from(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
    )?;
    Ok(())
}

#[cfg(test)]
mod registration_tests {
    #[test]
    fn actual_ipv6_transport_prefix_replaces_forged_registration_source_and_clock()
    -> anyhow::Result<()> {
        let root = ramflux_crypto::create_identity_root("p", [7; 32]);
        let device = ramflux_crypto::create_device_branch("p", "d", 1, [8; 32]);
        let mut request = ramflux_node_core::IdentityRegisterRequest {
            root_public_key: String::new(),
            principal_commitment: String::new(),
            branch_public_key: String::new(),
            proof: ramflux_crypto::authorize_device_branch(
                &root,
                &device,
                "ramflux-node",
                vec!["device.delivery.bind".into()],
                0,
                1,
            )?,
            target_delivery_id: "target".into(),
            gateway_id: "gateway".into(),
            session_id: "session".into(),
            push_alias_hash: None,
            now: 0,
            registration_pow: None,
            source_ip_hash: Some("forged".into()),
        };
        super::registration_context(&mut request, "2001:db8:1:2::1".parse()?)?;
        assert_eq!(
            request.source_ip_hash,
            Some(ramflux_node_core::source_ip_hash("2001:db8:1:2::1"))
        );
        assert_eq!(
            request.source_ip_hash,
            Some(ramflux_node_core::source_ip_hash("2001:db8:1:2::ffff"))
        );
        super::registration_context(&mut request, "192.0.2.1".parse()?)?;
        assert_eq!(request.source_ip_hash, Some(ramflux_node_core::source_ip_hash("192.0.2.1")));
        super::registration_context(&mut request, "::ffff:192.0.2.1".parse()?)?;
        assert_eq!(request.source_ip_hash, Some(ramflux_node_core::source_ip_hash("192.0.2.1")));
        assert!(request.now > 1);
        Ok(())
    }
}
