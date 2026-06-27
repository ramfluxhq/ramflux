// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{RouterMeshClient, router_get_json, router_post_json};
#[cfg(feature = "itest-http")]
use crate::{gateway_state, is_timeout_error, pre_auth_gate};

#[cfg(feature = "itest-http")]
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "itest-http")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "itest-http")]
pub(crate) fn serve_itest_http(
    router: &RouterMeshClient,
    store: &Arc<ramflux_node_core::GatewayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::GatewayState>>,
) -> anyhow::Result<()> {
    let addr = std::env::var("RAMFLUX_ITEST_GATEWAY_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18081".to_owned());
    let listener = TcpListener::bind(&addr)?;
    tracing::info!(addr, "gateway itest HTTP surface listening");
    for stream in listener.incoming() {
        let mut stream = stream?;
        let router = router.clone();
        let state = Arc::clone(state);
        let store = Arc::clone(store);
        std::thread::spawn(move || {
            if let Err(error) = handle_itest_request(&mut stream, &router, &state, &store) {
                let body = format!("{error}");
                if let Err(write_error) = ramflux_node_core::write_itest_text_response(
                    &mut stream,
                    "500 Internal Server Error",
                    &body,
                ) {
                    tracing::warn!(%write_error, "failed to write gateway itest error response");
                }
            }
        });
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_itest_request(
    stream: &mut TcpStream,
    router: &RouterMeshClient,
    state: &Arc<Mutex<ramflux_node_core::GatewayState>>,
    store: &ramflux_node_core::GatewayRedbStore,
) -> anyhow::Result<()> {
    let read_timeout = gateway_state(state)?.pre_auth_read_timeout();
    let request =
        match ramflux_node_core::read_itest_http_request_with_timeout(stream, read_timeout) {
            Ok(Some(request)) => request,
            Ok(None) => {
                let mut gateway = gateway_state(state)?;
                gateway.record_slowloris_timeout();
                store.save_pre_auth_metrics_only(&gateway)?;
                return Ok(());
            }
            Err(error) => {
                if is_timeout_error(&error) {
                    let mut gateway = gateway_state(state)?;
                    gateway.record_slowloris_timeout();
                    store.save_pre_auth_metrics_only(&gateway)?;
                    return Ok(());
                }
                return Err(error.into());
            }
        };
    tracing::info!(
        method = %request.method,
        path = %request.path,
        "gateway HTTP itest request received"
    );
    if handle_preauth_control_request(stream, &request, state, store)? {
        return Ok(());
    }
    if let Some(challenge) = pre_auth_gate(&request, state, store)? {
        ramflux_node_core::write_itest_json_response(stream, "401 Unauthorized", &challenge)?;
        return Ok(());
    }
    dispatch_protected_itest_request(stream, router, &request)
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_preauth_control_request(
    stream: &mut TcpStream,
    request: &ramflux_node_core::ItestHttpRequest,
    state: &Arc<Mutex<ramflux_node_core::GatewayState>>,
    store: &ramflux_node_core::GatewayRedbStore,
) -> anyhow::Result<bool> {
    if request.method == "POST" && request.path == "/mvp6/preauth/policy" {
        let policy: ramflux_node_core::GatewayPreAuthPolicy =
            serde_json::from_slice(&request.body)?;
        let mut gateway = gateway_state(state)?;
        gateway.set_pre_auth_policy(policy);
        let response = gateway.pre_auth_policy().clone();
        store.save_state(&gateway)?;
        ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        return Ok(true);
    }
    if request.method == "GET" && request.path == "/mvp6/preauth/metrics" {
        let gateway = gateway_state(state)?;
        ramflux_node_core::write_itest_json_response(stream, "200 OK", gateway.pre_auth_metrics())?;
        return Ok(true);
    }
    if request.method == "GET" && request.path == "/perf/metrics" {
        let snapshot = serde_json::json!({
            "service": "ramflux-gateway",
            "node": ramflux_node_core::node_perf_snapshot(),
            "transport": ramflux_transport::mesh_perf_snapshot()
        });
        ramflux_node_core::write_itest_json_response(stream, "200 OK", &snapshot)?;
        return Ok(true);
    }
    if request.method == "POST" && request.path == "/perf/metrics/reset" {
        ramflux_node_core::node_perf_reset();
        ramflux_transport::mesh_perf_reset();
        ramflux_node_core::write_itest_json_response(
            stream,
            "200 OK",
            &serde_json::json!({"reset": true}),
        )?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(feature = "itest-http")]
#[allow(clippy::too_many_lines)]
pub(crate) fn dispatch_protected_itest_request(
    stream: &mut TcpStream,
    router: &RouterMeshClient,
    request: &ramflux_node_core::ItestHttpRequest,
) -> anyhow::Result<()> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => {
            ramflux_node_core::write_itest_json_response(
                stream,
                "200 OK",
                &serde_json::json!({
                    "service": "ramflux-gateway",
                    "status": "ok"
                }),
            )?;
        }
        ("POST", "/mvp0/envelope") => {
            let envelope: ramflux_protocol::Envelope = serde_json::from_slice(&request.body)?;
            ramflux_node_core::record_gateway_submit_received();
            let response: ramflux_node_core::ItestMvp0SubmitResponse =
                router_post_json(router, "/mvp0/envelope", &envelope)?;
            log_forwarded_envelope(&envelope, &response);
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp0/ack") => {
            let ack: ramflux_protocol::Ack = serde_json::from_slice(&request.body)?;
            let response: ramflux_node_core::ItestMvp0CursorResponse =
                router_post_json(router, "/mvp0/ack", &ack)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp0/nack") => {
            let nack: ramflux_protocol::Nack = serde_json::from_slice(&request.body)?;
            let response: ramflux_node_core::ItestMvp0CursorResponse =
                router_post_json(router, "/mvp0/nack", &nack)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp0/cursor/") => {
            let response: Option<ramflux_node_core::ItestMvp0CursorResponse> =
                router_get_json(router, path)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp1/identity/register") => {
            let mut registration: ramflux_node_core::ItestMvp1RegisterIdentityRequest =
                serde_json::from_slice(&request.body)?;
            registration.source_ip_hash =
                registration.source_ip_hash.or_else(|| request.source_ip_hash.clone());
            let response: ramflux_node_core::ItestMvp1IdentityRegistrationResponse =
                router_post_json(router, "/mvp1/identity/register", &registration)?;
            log_forwarded_identity_registration(&registration, &response);
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp6/registration/policy") => {
            let request: ramflux_node_core::ItestRegistrationPolicy =
                serde_json::from_slice(&request.body)?;
            let response: ramflux_node_core::ItestRegistrationPolicy =
                router_post_json(router, "/mvp6/registration/policy", &request)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp6/friend/request") => {
            let request: ramflux_node_core::ItestMvp6FriendRequestBudgetRequest =
                serde_json::from_slice(&request.body)?;
            let response: ramflux_node_core::ItestMvp6FriendRequestBudgetResponse =
                router_post_json(router, "/mvp6/friend/request", &request)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        (method, path) if path.starts_with("/mvp10/") => {
            handle_mvp10_itest_request(stream, router, method, path, &request.body)?;
        }
        (method, path) if path.starts_with("/mvp7/") => {
            handle_mvp7_itest_request(stream, router, method, path, &request.body)?;
        }
        ("POST", "/mvp6/preauth/probe") => {
            ramflux_node_core::write_itest_json_response(
                stream,
                "200 OK",
                &serde_json::json!({"pre_auth": "accepted"}),
            )?;
        }
        ("POST", "/mvp1/device/revoke") => {
            let request: ramflux_node_core::ItestMvp1RevokeDeviceRequest =
                serde_json::from_slice(&request.body)?;
            let response: ramflux_node_core::ItestMvp1RevokeDeviceResponse =
                router_post_json(router, "/mvp1/device/revoke", &request)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp1/prekey/publish") => {
            let request: ramflux_node_core::ItestMvp1PublishPrekeyRequest =
                serde_json::from_slice(&request.body)?;
            let response: ramflux_node_core::ItestMvp1PrekeyResponse =
                router_post_json(router, "/mvp1/prekey/publish", &request)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp1/prekey/") => {
            write_prekey_fetch(stream, router, path)?;
        }
        ("GET", path) if path.starts_with("/mvp1/device-manifest/") => {
            let response: Option<ramflux_node_core::ItestMvp1DeviceManifestResponse> =
                router_get_json(router, path)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp1/inbox/") => {
            write_inbox_fetch(stream, router, path)?;
        }
        _ => {
            ramflux_node_core::write_itest_text_response(stream, "404 Not Found", "not found")?;
        }
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn write_prekey_fetch(
    stream: &mut TcpStream,
    router: &RouterMeshClient,
    path: &str,
) -> anyhow::Result<()> {
    let response: ramflux_node_core::ItestMvp1PrekeyResponse = router_get_json(router, path)?;
    log_fetched_prekey(path, &response);
    ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
    Ok(())
}

#[cfg(feature = "itest-http")]
fn write_inbox_fetch(
    stream: &mut TcpStream,
    router: &RouterMeshClient,
    path: &str,
) -> anyhow::Result<()> {
    let response: ramflux_node_core::ItestMvp1InboxResponse = router_get_json(router, path)?;
    log_fetched_inbox(path, &response);
    ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
    Ok(())
}

#[cfg(feature = "itest-http")]
fn log_forwarded_envelope(
    envelope: &ramflux_protocol::Envelope,
    response: &ramflux_node_core::ItestMvp0SubmitResponse,
) {
    tracing::info!(
        envelope_id = %envelope.envelope_id,
        target_delivery_id = %envelope.target_delivery_id,
        outcome = %response.outcome,
        "gateway HTTP forwarded envelope to router"
    );
}

#[cfg(feature = "itest-http")]
fn log_forwarded_identity_registration(
    registration: &ramflux_node_core::ItestMvp1RegisterIdentityRequest,
    response: &ramflux_node_core::ItestMvp1IdentityRegistrationResponse,
) {
    tracing::info!(
        principal_id = %registration.proof.principal_id,
        device_id = %registration.proof.device_id,
        target_delivery_id = %registration.target_delivery_id,
        session_bound = response.session_bound,
        "gateway HTTP forwarded identity registration to router"
    );
}

#[cfg(feature = "itest-http")]
fn log_fetched_prekey(path: &str, response: &ramflux_node_core::ItestMvp1PrekeyResponse) {
    tracing::info!(
        path,
        device_id = %response.device_id,
        "gateway HTTP fetched prekey from router"
    );
}

#[cfg(feature = "itest-http")]
fn log_fetched_inbox(path: &str, response: &ramflux_node_core::ItestMvp1InboxResponse) {
    tracing::info!(
        path,
        entries = response.entries.len(),
        "gateway HTTP fetched inbox from router"
    );
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_mvp10_itest_request(
    stream: &mut TcpStream,
    router: &RouterMeshClient,
    method: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    match (method, path) {
        ("POST", "/mvp10/own-devices/fanout") => {
            let request: ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest =
                serde_json::from_slice(body)?;
            let response: ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse =
                router_post_json(router, "/mvp10/own-devices/fanout", &request)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => {
            ramflux_node_core::write_itest_text_response(stream, "404 Not Found", "not found")?;
        }
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_mvp7_itest_request(
    stream: &mut TcpStream,
    router: &RouterMeshClient,
    method: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    match (method, path) {
        ("POST", "/mvp7/lifecycle/event") => {
            let request: ramflux_node_core::ItestMvp7LifecycleRequest =
                serde_json::from_slice(body)?;
            let response: ramflux_node_core::ItestMvp7LifecycleResponse =
                router_post_json(router, "/mvp7/lifecycle/event", &request)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp7/lifecycle/cancel") => {
            let request: ramflux_node_core::ItestMvp7LifecycleCancelRequest =
                serde_json::from_slice(body)?;
            let response: ramflux_node_core::ItestMvp7LifecycleResponse =
                router_post_json(router, "/mvp7/lifecycle/cancel", &request)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp7/lifecycle/finalize") => {
            let request: ramflux_node_core::ItestMvp7LifecycleFinalizeRequest =
                serde_json::from_slice(body)?;
            let response: ramflux_node_core::ItestMvp7LifecycleResponse =
                router_post_json(router, "/mvp7/lifecycle/finalize", &request)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp7/lifecycle/") => {
            let response: Option<ramflux_node_core::AccountLifecycleRecord> =
                router_get_json(router, path)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp7/metadata/") => {
            let response: ramflux_node_core::ItestMvp7MetadataSummary =
                router_get_json(router, path)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp7/abuse/report") => {
            let request: ramflux_node_core::AbuseReportRequest = serde_json::from_slice(body)?;
            let response: ramflux_node_core::AbuseReportResponse =
                router_post_json(router, "/mvp7/abuse/report", &request)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp7/abuse/report/") => {
            let response: Option<ramflux_node_core::AbuseReportRecord> =
                router_get_json(router, path)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => {
            ramflux_node_core::write_itest_text_response(stream, "404 Not Found", "not found")?;
        }
    }
    Ok(())
}
