// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed registration outcomes shared by framed and test HTTP ingress.
use ramflux_protocol::{
    IdentityDirectoryReason, IdentityRegistrationFailure, IdentityRegistrationFailureBody,
};
use ramflux_transport::GatewayQuicResponse;
use std::sync::atomic::{AtomicBool, Ordering};

static GATEWAY_IDENTITY_ERROR_LOGGED: AtomicBool = AtomicBool::new(false);
pub(crate) fn rejected(reason_code: IdentityDirectoryReason) -> GatewayQuicResponse {
    GatewayQuicResponse {
        status: 409,
        body: serde_json::json!(IdentityRegistrationFailure {
            error: IdentityRegistrationFailureBody { reason_code },
        }),
    }
}
/// Blocking adapter for the synchronous test HTTP listener.
#[cfg(any(feature = "itest-http", test))]
pub(crate) fn forward(
    router: &crate::RouterMeshClient,
    body: serde_json::Value,
    source: std::net::IpAddr,
    gateway_id: &str,
) -> GatewayQuicResponse {
    let request = match prepare(body, source, gateway_id) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let response: serde_json::Value =
        match crate::router_post_json(router, "/mvp1/identity/register", &request) {
            Ok(response) => response,
            Err(error) => {
                let identity_error = log_gateway_identity_rejection(&error);
                return crate::principal_directory::registration_forwarding_failure(
                    &error,
                    !identity_error,
                );
            }
        };
    registration_result(response)
}

const REGISTRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn prepare(
    body: serde_json::Value,
    source: std::net::IpAddr,
    gateway_id: &str,
) -> Result<ramflux_node_core::IdentityRegisterRequest, GatewayQuicResponse> {
    let mut request: ramflux_node_core::IdentityRegisterRequest = match serde_json::from_value(body)
    {
        Ok(request) => request,
        Err(_) => return Err(rejected(IdentityDirectoryReason::InvalidRegistration)),
    };
    if crate::principal_directory::registration_context(&mut request, source, gateway_id).is_err() {
        return Err(rejected(IdentityDirectoryReason::RegistrationUnavailable));
    }
    Ok(request)
}

pub(crate) async fn forward_async(
    router: &crate::RouterMeshClient,
    body: serde_json::Value,
    source: std::net::IpAddr,
    gateway_id: &str,
) -> GatewayQuicResponse {
    let request = match prepare(body, source, gateway_id) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let deadline = std::time::Instant::now() + REGISTRATION_TIMEOUT;
    match tokio::time::timeout(
        REGISTRATION_TIMEOUT,
        crate::router_post_json_until(router, "/mvp1/identity/register", &request, deadline),
    )
    .await
    {
        Ok(Ok(response)) => registration_result(response),
        Ok(Err(error)) => {
            let identity_error = log_gateway_identity_rejection(&error);
            crate::principal_directory::registration_forwarding_failure(&error, !identity_error)
        }
        Err(error) => crate::principal_directory::registration_forwarding_failure(&error, true),
    }
}

pub(crate) fn gateway_instance_rejection(error: &ramflux_transport::TransportError) -> bool {
    let ramflux_transport::TransportError::HttpStatus { status: 403, body } = error else {
        return false;
    };
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value.get("reason").and_then(serde_json::Value::as_str).map(str::to_owned)
        })
        .is_some_and(|reason| {
            matches!(reason.as_str(), "gateway_instance_missing" | "gateway_instance_mismatch")
        })
}

pub(crate) fn log_gateway_identity_rejection(error: &ramflux_transport::TransportError) -> bool {
    let ramflux_transport::TransportError::HttpStatus { status: 403, body } = error else {
        return false;
    };
    let reason = serde_json::from_str::<serde_json::Value>(body).ok().and_then(|value| {
        value.get("reason").and_then(serde_json::Value::as_str).map(str::to_owned)
    });
    let Some(reason) = reason.filter(|reason| {
        matches!(
            reason.as_str(),
            "gateway_role_required" | "gateway_instance_missing" | "gateway_instance_mismatch"
        )
    }) else {
        return false;
    };
    if !GATEWAY_IDENTITY_ERROR_LOGGED.swap(true, Ordering::AcqRel) {
        tracing::error!(
            reason,
            "gateway mesh configuration error: router rejected registration identity; check the gateway certificate and RAMFLUX_GATEWAY_ID"
        );
    }
    true
}

pub(crate) async fn publish_prekey(
    router: &crate::RouterMeshClient,
    request: &ramflux_node_core::PrekeyPublishRequest,
) -> anyhow::Result<ramflux_node_core::PrekeyResponse> {
    let deadline = std::time::Instant::now() + REGISTRATION_TIMEOUT;
    Ok(tokio::time::timeout(
        REGISTRATION_TIMEOUT,
        crate::router_post_json_until(router, "/mvp1/prekey/publish", request, deadline),
    )
    .await??)
}

fn registration_result(response: serde_json::Value) -> GatewayQuicResponse {
    if serde_json::from_value::<IdentityRegistrationFailure>(response.clone()).is_ok() {
        return GatewayQuicResponse { status: 409, body: response };
    }
    if serde_json::from_value::<ramflux_node_core::IdentityRegistrationResponse>(response.clone())
        .is_err()
    {
        return rejected(IdentityDirectoryReason::RegistrationUnavailable);
    }
    GatewayQuicResponse { status: 200, body: response }
}
pub(crate) fn session_response(
    response: GatewayQuicResponse,
) -> ramflux_node_core::GatewayServerFrame {
    match serde_json::from_value(response.body.clone()) {
        Ok(registered) if response.status == 200 => {
            ramflux_node_core::GatewayServerFrame::IdentityRegistered { response: registered }
        }
        _ => ramflux_node_core::GatewayServerFrame::IdentityRegistrationRejected {
            reason_code: serde_json::from_value::<IdentityRegistrationFailure>(response.body)
                .map_or(IdentityDirectoryReason::RegistrationUnavailable, |failure| {
                    failure.error.reason_code
                }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_registration_and_upstream_ack_are_typed_rejections() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join("unused-registration-tls");
        let router = crate::RouterMeshClient {
            endpoint: "127.0.0.1:1".into(),
            server_name: "router".into(),
            tls: ramflux_transport::MeshTlsConfig {
                ca_cert: path.clone(),
                service_cert: path.clone(),
                service_key: path,
            },
            client: ramflux_transport::MeshHttpClient::new(),
            async_mesh: None,
        };
        let response =
            forward(&router, serde_json::json!({"proof":null}), "127.0.0.1".parse()?, "gateway");
        assert_eq!(response.body["error"]["reason_code"], "invalid_registration");
        assert!(matches!(
            session_response(GatewayQuicResponse {
                status: 200,
                body: serde_json::json!({"bad_ack":true})
            }),
            ramflux_node_core::GatewayServerFrame::IdentityRegistrationRejected {
                reason_code: IdentityDirectoryReason::RegistrationUnavailable
            }
        ));
        for bytes in [
            br#"{"frame_type":"identity_register","request":null}"#.as_slice(),
            br#"{"frame_type":"identity_register","request":{},"request":{}}"#.as_slice(),
        ] {
            let crate::ingress::Ingress::Rejected(value) =
                crate::ingress::parse(bytes, "127.0.0.1".parse()?)?
            else {
                anyhow::bail!("missing typed rejection")
            };
            assert_eq!(value["reason_code"], "invalid_registration");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "registration_async_tests.rs"]
mod async_tests;
