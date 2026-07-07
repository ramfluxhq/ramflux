// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::io::Write;
use std::time::Instant;

use crate::lifecycle::{
    handle_home_node_migration_apply, handle_home_node_route_update_apply,
    handle_mvp7_abuse_report, handle_mvp7_abuse_report_get, handle_mvp7_federated_tombstone,
    handle_mvp7_lifecycle_cancel, handle_mvp7_lifecycle_event, handle_mvp7_lifecycle_finalize,
    handle_mvp7_lifecycle_get, handle_mvp7_metadata_get,
};

#[cfg(feature = "itest-http")]
use std::net::TcpStream;

#[cfg(feature = "itest-http")]
pub(crate) fn handle_itest_request(
    stream: &mut TcpStream,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<()> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(());
    };
    log_router_itest_request(&request);
    if handle_healthz_request(stream, &request)? || handle_perf_metrics_request(stream, &request)? {
        return Ok(());
    }
    if handle_itest_mvp0_request(stream, &request, router)?
        || handle_itest_s1_request(stream, &request, router)?
        || handle_itest_admin_request(stream, &request, router)?
    {
        return Ok(());
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/mvp1/identity/register") => {
            let response =
                handle_mvp1_identity_register(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp6/registration/policy") => {
            let response =
                handle_mvp6_registration_policy(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp6/friend/request") => {
            let response =
                handle_mvp6_friend_request(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp10/own-devices/fanout") => {
            let response = handle_mvp10_own_devices_fanout(&request.body, router)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp7/lifecycle/event") => {
            let response =
                handle_mvp7_lifecycle_event(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp7/lifecycle/cancel") => {
            let response =
                handle_mvp7_lifecycle_cancel(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp7/lifecycle/finalize") => {
            let response =
                handle_mvp7_lifecycle_finalize(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp7/lifecycle/") => {
            let response = handle_mvp7_lifecycle_get(path, router.state());
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp7/metadata/") => {
            let response = handle_mvp7_metadata_get(path, router.state());
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp7/federation/tombstone/apply") => {
            let response =
                handle_mvp7_federated_tombstone(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp7/abuse/report") => {
            let response = handle_mvp7_abuse_report(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp7/abuse/report/") => {
            let response = handle_mvp7_abuse_report_get(path, router.state());
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp1/device/revoke") => {
            let response =
                handle_mvp1_device_revoke(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp1/prekey/publish") => {
            let response =
                handle_mvp1_prekey_publish(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp1/prekey/") => {
            let response = handle_mvp1_prekey_fetch(path, router.state());
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp1/device-manifest/") => {
            let response = handle_mvp1_device_manifest_fetch(path, router.state());
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp1/device-auth-key/") => {
            let response = handle_mvp1_device_auth_key_fetch(path, router.state());
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp1/inbox/") => {
            let response = handle_mvp1_inbox_fetch(path, router.state())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => {
            ramflux_node_core::write_itest_text_response(stream, "404 Not Found", "not found")?;
        }
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn handle_itest_admin_request(
    stream: &mut TcpStream,
    request: &ramflux_node_core::NodeHttpRequest,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<bool> {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/admin/home-node-migration/apply") => {
            let response =
                handle_home_node_migration_apply(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/admin/home-node-route/update/apply") => {
            let response =
                handle_home_node_route_update_apply(&request.body, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(feature = "itest-http")]
fn handle_itest_s1_request(
    stream: &mut TcpStream,
    request: &ramflux_node_core::NodeHttpRequest,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<bool> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", path) if path.starts_with("/s1/session/") => {
            let response = handle_s1_session_get(path, router.state());
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(feature = "itest-http")]
fn handle_itest_mvp0_request(
    stream: &mut TcpStream,
    request: &ramflux_node_core::NodeHttpRequest,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<bool> {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/mvp0/envelope") => {
            let response = handle_mvp0_envelope(&request.body, router)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp0/ack") => {
            let response = handle_mvp0_ack(&request.body, router)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp0/ack-bound") => {
            let response = handle_mvp0_ack_bound(&request.body, router)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp0/nack") => {
            let response = handle_mvp0_nack(&request.body, router)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp0/nack-bound") => {
            let response = handle_mvp0_nack_bound(&request.body, router)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp0/cursor/") => {
            let response = handle_mvp0_cursor(path, router.state());
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(feature = "itest-http")]
fn handle_healthz_request(
    stream: &mut TcpStream,
    request: &ramflux_node_core::NodeHttpRequest,
) -> anyhow::Result<bool> {
    if (request.method.as_str(), request.path.as_str()) != ("GET", "/healthz") {
        return Ok(false);
    }
    ramflux_node_core::write_itest_json_response(
        stream,
        "200 OK",
        &serde_json::json!({
            "service": "ramflux-router",
            "status": "ok"
        }),
    )?;
    Ok(true)
}

#[cfg(feature = "itest-http")]
fn handle_perf_metrics_request(
    stream: &mut TcpStream,
    request: &ramflux_node_core::NodeHttpRequest,
) -> anyhow::Result<bool> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/perf/metrics") => {
            let snapshot = serde_json::json!({
                "service": "ramflux-router",
                "node": ramflux_node_core::node_perf_snapshot(),
                "transport": ramflux_transport::mesh_perf_snapshot()
            });
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &snapshot)?;
            Ok(true)
        }
        ("POST", "/perf/metrics/reset") => {
            ramflux_node_core::node_perf_reset();
            ramflux_transport::mesh_perf_reset();
            ramflux_node_core::write_itest_json_response(
                stream,
                "200 OK",
                &serde_json::json!({"reset": true}),
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(feature = "itest-http")]
fn log_router_itest_request(request: &ramflux_node_core::NodeHttpRequest) {
    tracing::info!(
        method = %request.method,
        path = %request.path,
        "router HTTP itest request received"
    );
}

pub(crate) fn handle_mesh_request(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    router: &crate::router_runtime::RouterHandle,
    peer_service_id: &str,
) -> anyhow::Result<bool> {
    let Some(request) = ramflux_transport::read_mesh_http_request(stream)? else {
        return Ok(false);
    };
    tracing::info!(
        method = %request.method,
        path = %request.path,
        "router mesh request received"
    );
    let response = handle_mesh_request_value(request, router, peer_service_id)?;
    write_mesh_value_response(stream, &response)?;
    Ok(response.keep_alive)
}

pub(crate) struct MeshResponse {
    pub(crate) status: &'static str,
    pub(crate) content_type: &'static str,
    pub(crate) body: Vec<u8>,
    pub(crate) keep_alive: bool,
}

impl MeshResponse {
    fn json(status: &'static str, body: Vec<u8>) -> Self {
        Self { status, content_type: "application/json", body, keep_alive: true }
    }

    fn text(status: &'static str, body: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.as_bytes().to_vec(),
            keep_alive: true,
        }
    }
}

pub(crate) fn handle_mesh_request_value(
    request: ramflux_transport::MeshHttpRequest,
    router: &crate::router_runtime::RouterHandle,
    peer_service_id: &str,
) -> anyhow::Result<MeshResponse> {
    let ramflux_transport::MeshHttpRequest { method, path, body } = request;
    if let Some(response) = handle_mesh_retention_value(&method, &path, &body, peer_service_id)? {
        return Ok(response);
    }
    if let Some(response) = handle_mesh_fast_path_value(&method, &path, &body, router)? {
        return Ok(response);
    }
    if let Some(response) = handle_mesh_mvp0_value(&method, &path, &body, router)? {
        return Ok(response);
    }
    handle_mesh_general_value(&method, &path, &body, router)
}

pub(crate) async fn handle_mesh_quic_request_value(
    request: &ramflux_transport::GatewayQuicRequest,
    router: &crate::router_runtime::RouterHandle,
    peer_service_id: &str,
) -> anyhow::Result<ramflux_transport::GatewayQuicResponse> {
    let body = serde_json::to_vec(&request.body)?;
    if (request.method.as_str(), request.path.as_str()) == ("POST", "/mvp0/envelope") {
        let response = handle_mvp0_envelope_async(&body, router).await?;
        return Ok(ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(response)?,
        });
    }
    let response = handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: request.method.clone(),
            path: request.path.clone(),
            body,
        },
        router,
        peer_service_id,
    )?;
    Ok(ramflux_transport::GatewayQuicResponse {
        status: mesh_response_status_code(response.status),
        body: serde_json::from_slice(&response.body).unwrap_or_else(
            |_| serde_json::json!({ "error": String::from_utf8_lossy(&response.body) }),
        ),
    })
}

fn handle_mesh_retention_value(
    method: &str,
    path: &str,
    body: &[u8],
    peer_service_id: &str,
) -> anyhow::Result<Option<MeshResponse>> {
    if peer_service_id == "ramflux-retention" && path != "/internal/retention/gc_sweep" {
        return Ok(MeshResponse::text(
            "403 Forbidden",
            "retention peer is only authorized for gc_sweep",
        )
        .into());
    }
    if method == "POST" && path == "/internal/retention/gc_sweep" {
        if peer_service_id != "ramflux-retention" {
            return Ok(MeshResponse::text(
                "403 Forbidden",
                "gc_sweep requires ramflux-retention peer",
            )
            .into());
        }
        let sweep: ramflux_node_core::RetentionGcSweepRequest = serde_json::from_slice(body)?;
        return Ok(Some(MeshResponse::json("200 OK", serde_json::to_vec(&sweep.response(0))?)));
    }
    Ok(None)
}

fn handle_mesh_fast_path_value(
    method: &str,
    path: &str,
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<Option<MeshResponse>> {
    match (method, path) {
        ("POST", "/s1/session/upsert") => {
            let response = handle_s1_session_upsert(body, router.state(), router.store())?;
            tracing::info!(
                target_delivery_id = %response.target_delivery_id,
                session_id = %response.session_id,
                "router mesh session upsert returned"
            );
            Ok(Some(MeshResponse::json("200 OK", serde_json::to_vec(&response)?)))
        }
        ("GET", path) if path.starts_with("/s1/session/") => {
            let response = handle_s1_session_get(path, router.state());
            Ok(Some(MeshResponse::json("200 OK", serde_json::to_vec(&response)?)))
        }
        ("GET", "/healthz") => Ok(MeshResponse::json(
            "200 OK",
            serde_json::to_vec(&serde_json::json!({
                "service": "ramflux-router",
                "status": "ok"
            }))?,
        )
        .into()),
        ("POST", "/mvp0/envelope") => {
            let response = handle_mvp0_envelope(body, router)?;
            tracing::info!(
                target_delivery_id = %response.target_delivery_id,
                outcome = %response.outcome,
                inbox_seq = ?response.inbox_seq,
                "router mesh mvp0 envelope returned"
            );
            Ok(Some(MeshResponse::json("200 OK", serde_json::to_vec(&response)?)))
        }
        #[cfg(feature = "itest-http")]
        ("POST", "/mvp0/ack") => {
            let response = handle_mvp0_ack(body, router)?;
            Ok(Some(MeshResponse::json("200 OK", serde_json::to_vec(&response)?)))
        }
        ("POST", "/mvp0/ack-bound") => {
            let response = handle_mvp0_ack_bound(body, router)?;
            Ok(Some(MeshResponse::json("200 OK", serde_json::to_vec(&response)?)))
        }
        _ => Ok(None),
    }
}

fn handle_mesh_mvp0_value(
    method: &str,
    path: &str,
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<Option<MeshResponse>> {
    match (method, path) {
        #[cfg(feature = "itest-http")]
        ("POST", "/mvp0/nack") => {
            let response = handle_mvp0_nack(body, router)?;
            Ok(Some(MeshResponse::json("200 OK", serde_json::to_vec(&response)?)))
        }
        ("POST", "/mvp0/nack-bound") => {
            let response = handle_mvp0_nack_bound(body, router)?;
            Ok(Some(MeshResponse::json("200 OK", serde_json::to_vec(&response)?)))
        }
        ("GET", path) if path.starts_with("/mvp0/cursor/") => {
            let response = handle_mvp0_cursor(path, router.state());
            Ok(Some(MeshResponse::json("200 OK", serde_json::to_vec(&response)?)))
        }
        _ => Ok(None),
    }
}

fn handle_mesh_general_value(
    method: &str,
    path: &str,
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<MeshResponse> {
    match (method, path) {
        ("POST", "/mvp1/identity/register") => {
            let response = handle_mvp1_identity_register(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp6/registration/policy") => {
            let response = handle_mvp6_registration_policy(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp6/friend/request") => {
            let response = handle_mvp6_friend_request(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp10/own-devices/fanout") => {
            let response = handle_mvp10_own_devices_fanout(body, router)?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp7/lifecycle/event") => {
            let response = handle_mvp7_lifecycle_event(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp7/lifecycle/cancel") => {
            let response = handle_mvp7_lifecycle_cancel(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp7/lifecycle/finalize") => {
            let response = handle_mvp7_lifecycle_finalize(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("GET", path) if path.starts_with("/mvp7/lifecycle/") => {
            let response = handle_mvp7_lifecycle_get(path, router.state());
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("GET", path) if path.starts_with("/mvp7/metadata/") => {
            let response = handle_mvp7_metadata_get(path, router.state());
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp7/federation/tombstone/apply") => {
            let response = handle_mvp7_federated_tombstone(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/admin/home-node-migration/apply") => {
            let response = handle_home_node_migration_apply(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/admin/home-node-route/update/apply") => {
            let response =
                handle_home_node_route_update_apply(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp7/abuse/report") => {
            let response = handle_mvp7_abuse_report(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("GET", path) if path.starts_with("/mvp7/abuse/report/") => {
            let response = handle_mvp7_abuse_report_get(path, router.state());
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp1/device/revoke") => {
            let response = handle_mvp1_device_revoke(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp1/prekey/publish") => {
            let response = handle_mvp1_prekey_publish(body, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("GET", path) if path.starts_with("/mvp1/prekey/") => {
            let response = handle_mvp1_prekey_fetch(path, router.state());
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("GET", path) if path.starts_with("/mvp1/device-manifest/") => {
            let response = handle_mvp1_device_manifest_fetch(path, router.state());
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("GET", path) if path.starts_with("/mvp1/device-auth-key/") => {
            let response = handle_mvp1_device_auth_key_fetch(path, router.state());
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("GET", path) if path.starts_with("/mvp1/inbox/") => {
            let response = handle_mvp1_inbox_fetch(path, router.state())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        _ => Ok(MeshResponse::text("404 Not Found", "not found")),
    }
}

fn write_mesh_value_response(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    response: &MeshResponse,
) -> anyhow::Result<()> {
    let connection = if response.keep_alive { "keep-alive" } else { "close" };
    write!(
        stream,
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len(),
        connection
    )?;
    stream.write_all(&response.body)?;
    stream.flush()?;
    Ok(())
}

fn handle_mvp0_envelope(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    let total_started = Instant::now();
    let decode_started = Instant::now();
    let envelope: ramflux_protocol::Envelope = serde_json::from_slice(body)?;
    ramflux_node_core::record_router_submit_decode_us(elapsed_us(decode_started));
    router.submit_envelope(envelope, total_started)
}

pub(crate) async fn handle_mvp0_envelope_async(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    let total_started = Instant::now();
    let decode_started = Instant::now();
    let envelope: ramflux_protocol::Envelope = serde_json::from_slice(body)?;
    ramflux_node_core::record_router_submit_decode_us(elapsed_us(decode_started));
    router.submit_envelope_async(envelope, total_started).await
}

fn mesh_response_status_code(status: &str) -> u16 {
    status.split_ascii_whitespace().next().and_then(|code| code.parse::<u16>().ok()).unwrap_or(500)
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(feature = "itest-http")]
fn handle_mvp0_ack(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let ack: ramflux_protocol::Ack = serde_json::from_slice(body)?;
    router.apply_ack(&ack)
}

fn handle_mvp0_ack_bound(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let request: ramflux_node_core::TargetAckRequest = serde_json::from_slice(body)?;
    router.apply_bound_ack(&request)
}

#[cfg(feature = "itest-http")]
fn handle_mvp0_nack(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let nack: ramflux_protocol::Nack = serde_json::from_slice(body)?;
    router.apply_nack(&nack)
}

fn handle_mvp0_nack_bound(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let request: ramflux_node_core::TargetNackRequest = serde_json::from_slice(body)?;
    router.apply_bound_nack(&request)
}

fn handle_mvp0_cursor(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> Option<ramflux_node_core::InboxCursorResponse> {
    let target_delivery_id = path.trim_start_matches("/mvp0/cursor/");
    state
        .cursor_state(target_delivery_id)
        .as_ref()
        .map(ramflux_node_core::InboxCursorResponse::from)
}

fn handle_s1_session_upsert(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::SessionDescriptor> {
    let descriptor: ramflux_node_core::SessionDescriptor = serde_json::from_slice(body)?;
    state.upsert_session(descriptor.clone())?;
    state.mark_live(&descriptor.target_delivery_id)?;
    let session = state
        .session(&descriptor.target_delivery_id)
        .ok_or_else(|| anyhow::anyhow!("session missing after upsert"))?;
    store.record_session_entry(&session)?;
    Ok(descriptor)
}

fn handle_s1_session_get(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> Option<ramflux_node_core::SessionDescriptor> {
    let target_delivery_id = path.trim_start_matches("/s1/session/");
    state.session(target_delivery_id)
}

fn handle_mvp1_identity_register(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::IdentityRegistrationResponse> {
    let request: ramflux_node_core::IdentityRegisterRequest = serde_json::from_slice(body)?;
    tracing::info!(
        principal_id = %request.proof.principal_id,
        device_id = %request.proof.device_id,
        target_delivery_id = %request.target_delivery_id,
        "router decoded mvp1 identity registration"
    );
    let response = state.mvp1_register_identity(&request)?;
    store.record_identity_registry(&state.mvp1_identities_snapshot())?;
    let session = state
        .session(&response.target_delivery_id)
        .ok_or_else(|| anyhow::anyhow!("session missing after identity registration"))?;
    store.record_session_entry(&session)?;
    tracing::info!(
        principal_id = %response.principal_id,
        device_id = %response.device_id,
        target_delivery_id = %response.target_delivery_id,
        session_bound = response.session_bound,
        "router mvp1 identity registration outcome"
    );
    Ok(response)
}

fn handle_mvp1_device_auth_key_fetch(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> Option<ramflux_node_core::DeviceAuthKeyResponse> {
    let device_id = path.trim_start_matches("/mvp1/device-auth-key/");
    state.mvp1_device_auth_key(device_id)
}

fn handle_mvp6_registration_policy(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::RegistrationPolicy> {
    let request: ramflux_node_core::RegistrationPolicy = serde_json::from_slice(body)?;
    state.mvp6_set_registration_policy(request);
    let response = state.mvp6_registration_policy();
    store.record_identity_registry(&state.mvp1_identities_snapshot())?;
    Ok(response)
}

fn handle_mvp6_friend_request(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::FriendRequestBudgetResponse> {
    let request: ramflux_node_core::FriendRequestBudgetRequest = serde_json::from_slice(body)?;
    let response = state.mvp6_record_friend_request(&request)?;
    store.record_identity_registry(&state.mvp1_identities_snapshot())?;
    Ok(response)
}

fn handle_mvp10_own_devices_fanout(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse> {
    let request: ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest =
        serde_json::from_slice(body)?;
    router.own_device_fanout(&request)
}

fn handle_mvp1_device_revoke(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::DeviceRevokeResponse> {
    let request: ramflux_node_core::DeviceRevokeRequest = serde_json::from_slice(body)?;
    let response = state.mvp1_revoke_device(&request)?;
    store.record_identity_registry(&state.mvp1_identities_snapshot())?;
    Ok(response)
}

fn handle_mvp1_prekey_publish(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::PrekeyResponse> {
    let request: ramflux_node_core::PrekeyPublishRequest = serde_json::from_slice(body)?;
    tracing::info!(
        device_id = %request.device_id,
        "router decoded mvp1 prekey publish"
    );
    let response = state.mvp1_publish_prekey(request)?;
    store.record_identity_registry(&state.mvp1_identities_snapshot())?;
    tracing::info!(
        device_id = %response.device_id,
        has_bundle = response.bundle.is_some(),
        target_delivery_id = ?response.target_delivery_id,
        "router mvp1 prekey publish outcome"
    );
    Ok(response)
}

fn handle_mvp1_prekey_fetch(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> ramflux_node_core::PrekeyResponse {
    let device_id = path.trim_start_matches("/mvp1/prekey/");
    let response = state.mvp1_prekey(device_id);
    tracing::info!(
        device_id = %response.device_id,
        has_bundle = response.bundle.is_some(),
        target_delivery_id = ?response.target_delivery_id,
        "router mvp1 prekey fetch outcome"
    );
    response
}

fn handle_mvp1_device_manifest_fetch(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> Option<ramflux_node_core::DeviceManifestResponse> {
    let principal_commitment = path.trim_start_matches("/mvp1/device-manifest/");
    let response = state.mvp1_device_manifest(principal_commitment);
    tracing::info!(
        principal_commitment,
        found = response.is_some(),
        device_count = response.as_ref().map_or(0, |manifest| manifest.devices.len()),
        "router mvp1 device manifest fetch outcome"
    );
    response
}

fn handle_mvp1_inbox_fetch(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> anyhow::Result<ramflux_node_core::InboxFetchResponse> {
    let request = path.trim_start_matches("/mvp1/inbox/");
    let (target_delivery_id, query) = request.split_once('?').unwrap_or((request, ""));
    let mut after_inbox_seq = 0;
    let mut limit = 100;
    for part in query.split('&').filter(|part| !part.is_empty()) {
        if let Some(value) = part.strip_prefix("after=") {
            after_inbox_seq = value.parse()?;
        } else if let Some(value) = part.strip_prefix("limit=") {
            limit = value.parse()?;
        }
    }
    let response = state.mvp1_inbox(target_delivery_id, after_inbox_seq, limit);
    tracing::info!(
        target_delivery_id = %response.target_delivery_id,
        after_inbox_seq,
        limit,
        entries = response.entries.len(),
        "router mvp1 inbox fetch outcome"
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};

    use super::*;

    #[test]
    fn mesh_quic_request_submit_uses_async_router_path() -> anyhow::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let path = temp_path("mesh_quic_request_submit_uses_async_router_path")?;
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let router = Arc::new(ramflux_node_core::RouterCore::new());
        let handle = crate::router_runtime::RouterHandle::tokio(router, store, None);
        let envelope = current_envelope("env_router_async_ingress", "target_router_async_ingress");
        let request = ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: "/mvp0/envelope".to_owned(),
            body: serde_json::to_value(&envelope)?,
        };

        let accepted = runtime.block_on(handle_mesh_quic_request_value(
            &request,
            &handle,
            "ramflux-gateway",
        ))?;
        assert_eq!(accepted.status, 200);
        let accepted: ramflux_node_core::EnvelopeSubmitResponse =
            serde_json::from_value(accepted.body)?;
        assert_eq!(accepted.outcome, "offline_queued");

        let replay = runtime.block_on(handle_mesh_quic_request_value(
            &request,
            &handle,
            "ramflux-gateway",
        ))?;
        let replay: ramflux_node_core::EnvelopeSubmitResponse =
            serde_json::from_value(replay.body)?;
        assert!(replay.outcome.starts_with("rejected_security:"));
        assert!(replay.outcome.contains("replay:"));

        let _removed = std::fs::remove_file(&path);
        let _removed = std::fs::remove_dir_all(path.with_extension("redb.wal"));
        Ok(())
    }

    #[test]
    fn mesh_quic_request_enforces_retention_peer_path_gate() -> anyhow::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let path = temp_path("mesh_quic_request_enforces_retention_peer_path_gate")?;
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let router = Arc::new(ramflux_node_core::RouterCore::new());
        let handle = crate::router_runtime::RouterHandle::tokio(router, store, None);
        let request = ramflux_transport::GatewayQuicRequest {
            method: "GET".to_owned(),
            path: "/mvp1/prekey/device-a".to_owned(),
            body: serde_json::Value::Null,
        };

        let response = runtime.block_on(handle_mesh_quic_request_value(
            &request,
            &handle,
            "ramflux-retention",
        ))?;
        assert_eq!(response.status, 403);
        assert_eq!(response.body["error"], "retention peer is only authorized for gc_sweep");

        let _removed = std::fs::remove_file(&path);
        let _removed = std::fs::remove_dir_all(path.with_extension("redb.wal"));
        Ok(())
    }

    fn current_envelope(envelope_id: &str, target_delivery_id: &str) -> Envelope {
        Envelope {
            schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
            ext: Ext::default(),
            signed: SignedFields {
                signing_key_id: "router_async_ingress_test".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "signature".to_owned(),
            },
            envelope_id: envelope_id.to_owned(),
            source_principal_id: "principal_router_async_ingress".to_owned(),
            source_device_id: "device_router_async_ingress".to_owned(),
            target_delivery_id: target_delivery_id.to_owned(),
            routing_set_id: None,
            delivery_class: DeliveryClass::OpaqueEvent,
            priority: Priority::Normal,
            ttl: 300,
            created_at: i64::try_from(ramflux_node_core::now_unix_seconds())
                .unwrap_or(i64::MAX - 300),
            encrypted_payload: "ciphertext".to_owned(),
            payload_hash: "payload_hash".to_owned(),
        }
    }

    fn temp_path(test_name: &str) -> anyhow::Result<PathBuf> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        Ok(std::env::temp_dir().join(format!(
            "ramflux-router-{test_name}-{}-{}",
            std::process::id(),
            elapsed.as_nanos()
        )))
    }
}
