// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

mod entry_fetch;
mod session_push;

use crate::identity_authority::handle_signed_device_set;
use std::io::Write;
use std::time::Instant;

use crate::lifecycle::{
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
    if handle_healthz_request(stream, &request)?
        || handle_perf_metrics_request(stream, &request, router)?
    {
        return Ok(());
    }
    if handle_itest_mvp0_request(stream, &request, router)?
        || handle_itest_s1_request(stream, &request, router)?
        || handle_itest_admin_request(stream, &request, router)?
        || handle_itest_directory_request(stream, &request, router)?
    {
        return Ok(());
    }
    if crate::identity_authority::handle_itest_identity_authority(stream, &request, router)? {
        return Ok(());
    }
    if handle_itest_device_lookup(stream, &request, router)? {
        return Ok(());
    }
    match (request.method.as_str(), request.path.as_str()) {
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
        ("GET", path) if path.starts_with("/mvp1/inbox-entry/") => {
            let (status, value) = entry_fetch::value(path, router.state())?;
            ramflux_node_core::write_itest_json_response(stream, status, &value)?;
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
fn handle_itest_directory_request(
    stream: &mut TcpStream,
    request: &ramflux_node_core::NodeHttpRequest,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<bool> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", path) if path.starts_with("/mvp1/prekey/") => {
            let response = handle_mvp1_prekey_fetch(path, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path)
            if path.starts_with(ramflux_protocol::custody::CUSTODY_HISTORY_PATH_PREFIX) =>
        {
            let response = handle_custody_consent_history(path, router)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp1/principal-manifest/") => {
            ramflux_node_core::write_itest_json_response(
                stream,
                "401 Unauthorized",
                &unauthenticated_principal_lookup(),
            )?;
        }
        ("GET", path) if is_identity_manifest_path(path) => {
            let response = handle_mvp1_device_manifest_fetch(path, router.state(), router.store())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp1/device-auth-key/") => {
            let response = handle_mvp1_device_auth_key_fetch(path, router.state())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn unauthenticated_principal_lookup() -> ramflux_protocol::PrincipalLookupResponse<serde_json::Value>
{
    ramflux_protocol::PrincipalLookupResponse {
        manifest: None,
        reason_code: Some(ramflux_protocol::IdentityDirectoryReason::AuthenticationRequired),
    }
}
#[cfg(feature = "itest-http")]
fn handle_itest_admin_request(
    stream: &mut TcpStream,
    request: &ramflux_node_core::NodeHttpRequest,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<bool> {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/admin/custody/budgets") => {
            let response = crate::lifecycle::handle_custody_budgets(&request.body, router.store())?;
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
        ("POST", "/mvp1/envelope-authority") => {
            let response = forward_authority_response(&request.body, router)?;
            ramflux_node_core::write_itest_text_response(
                stream,
                response.status,
                std::str::from_utf8(&response.body)?,
            )?;
        }
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
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<bool> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/perf/metrics") => {
            let snapshot = serde_json::json!({
                "service": "ramflux-router",
                "custody": router.custody_budget_snapshot(),
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
    connection: &ramflux_node_core::ConnectionGuard,
) -> anyhow::Result<bool> {
    let _deadline = if router.home_migration_enabled() {
        Some(ramflux_transport::mesh_request_deadline(
            stream,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        )?)
    } else {
        None
    };
    let Some(request) = ramflux_transport::read_bounded_mesh_http_request(
        stream,
        ramflux_protocol::home_migration::MAX_FRAME_BYTES,
    )?
    else {
        return Ok(false);
    };
    let Some(_request) = connection.begin_request() else {
        let _ = ramflux_transport::write_mesh_text_response(
            stream,
            "503 Service Unavailable",
            "shutting down",
        );
        return Ok(false);
    };
    #[cfg(feature = "itest-http")]
    if request.path == "/__itest/shutdown-connections" {
        ramflux_transport::write_mesh_json_response(
            stream,
            "200 OK",
            &serde_json::json!({
                "other_connections": connection.other_connection_count(),
                "root_workers": ramflux_node_core::service_worker_count(),
            }),
        )?;
        return Ok(true);
    }
    #[cfg(feature = "itest-http")]
    ramflux_node_core::shutdown_request_test_delay();

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
    if let Some(response) =
        session_push::route(&request.method, &request.path, &request.body, router, peer_service_id)?
    {
        return Ok(response);
    }
    handle_mesh_request_inner(request, router, peer_service_id)
}
fn handle_mesh_request_inner(
    request: ramflux_transport::MeshHttpRequest,
    router: &crate::router_runtime::RouterHandle,
    peer_service_id: &str,
) -> anyhow::Result<MeshResponse> {
    let ramflux_transport::MeshHttpRequest { method, path, body } = request;
    if method == "POST"
        && path == "/mvp10/own-devices/fanout"
        && peer_service_id != "ramflux-gateway"
    {
        return Ok(MeshResponse::text("403 Forbidden", "own-device fanout requires gateway peer"));
    }

    if method == "POST" && path == ramflux_node_core::MIGRATION_PEER_PATH {
        if peer_service_id != "ramflux-federation" {
            return Ok(MeshResponse::text(
                "403 Forbidden",
                "migration peer requires federation identity",
            ));
        }
        let request = ramflux_protocol::home_migration::decode(
            &body,
            ramflux_protocol::home_migration::MAX_FRAME_BYTES,
        )?;
        return Ok(MeshResponse::json(
            "200 OK",
            serde_json::to_vec(&router.migration_peer(&request)?)?,
        ));
    }
    if method == "POST" && path == ramflux_protocol::custody::CUSTODY_RPC_PATH {
        if peer_service_id != "ramflux-gateway" {
            anyhow::bail!("custody proxy ingress requires authenticated gateway")
        }
        let request = ramflux_protocol::custody::decode(
            &body,
            ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES,
        )?;
        return Ok(MeshResponse::json(
            "200 OK",
            serde_json::to_vec(&router.custody(request, peer_service_id))?,
        ));
    }

    if method == "POST" && path == "/mvp1/envelope-authority" {
        if peer_service_id != "ramflux-federation" {
            anyhow::bail!("source authority refresh requires federation peer");
        }
        return forward_authority_response(&body, router);
    }
    if let Some(response) =
        handle_mesh_retention_value(&method, &path, &body, peer_service_id, router)?
    {
        return Ok(response);
    }
    if let Some(response) =
        handle_mesh_fast_path_value(&method, &path, &body, router, peer_service_id)?
    {
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
        let response = handle_mvp0_envelope_async_from(
            &body,
            router,
            envelope_origin_for_peer(peer_service_id)?,
        )
        .await?;
        return Ok(ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(response)?,
        });
    }
    if (request.method.as_str(), request.path.as_str()) == ("POST", "/mvp0/envelope/forwarded") {
        if peer_service_id != "ramflux-federation" {
            return Ok(ramflux_transport::GatewayQuicResponse {
                status: 403,
                body: serde_json::json!({"error": "forwarded ingress requires federation peer"}),
            });
        }
        return Ok(ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: router.submit_forwarded_async(serde_json::from_slice(&body)?).await?,
        });
    }
    if (request.method.as_str(), request.path.as_str()) == ("POST", "/mvp10/own-devices/fanout") {
        if peer_service_id != "ramflux-gateway" {
            return Ok(ramflux_transport::GatewayQuicResponse {
                status: 403,
                body: serde_json::json!({"reason":"gateway peer required"}),
            });
        }

        let request: ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest =
            serde_json::from_slice(&body)?;
        let router = router.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            ramflux_node_core::publication::capture(|| {
                crate::router_engine::own_device_fanout_inner(
                    router.state(),
                    router.store(),
                    &request,
                )
            })
        })
        .await??;
        return Ok(ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(
                prepared.published().await?.resolved_with_metadata().await?,
            )?,
        });
    }
    let mesh_request = ramflux_transport::MeshHttpRequest {
        method: request.method.clone(),
        path: request.path.clone(),
        body,
    };
    let response = if request.path == ramflux_protocol::custody::CUSTODY_RPC_PATH
        || request.path == "/mvp0/ack-bound-batch"
        || request.path == "/mvp0/ack-bound"
        || request.path == "/s1/session"
        || request.path == ramflux_node_core::MIGRATION_PEER_PATH
    {
        let router = router.clone();
        let peer = peer_service_id.to_owned();
        tokio::task::spawn_blocking(move || handle_mesh_request_value(mesh_request, &router, &peer))
            .await??
    } else {
        handle_mesh_request_value(mesh_request, router, peer_service_id)?
    };
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
    router: &crate::router_runtime::RouterHandle,
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
        return Ok(Some(MeshResponse::json(
            "200 OK",
            serde_json::to_vec(&crate::retention::sweep(router, &sweep)?)?,
        )));
    }
    Ok(None)
}

fn handle_mesh_fast_path_value(
    method: &str,
    path: &str,
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    peer_service_id: &str,
) -> anyhow::Result<Option<MeshResponse>> {
    match (method, path) {
        ("POST", "/mvp0/envelope/forwarded") => {
            if peer_service_id != "ramflux-federation" {
                return Ok(Some(MeshResponse::text(
                    "403 Forbidden",
                    "forwarded ingress requires federation peer",
                )));
            }
            let request = serde_json::from_slice(body)?;
            Ok(Some(MeshResponse::json(
                "200 OK",
                serde_json::to_vec(&router.submit_forwarded(request)?)?,
            )))
        }
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
            let response = handle_mvp0_envelope_mesh_from(
                body,
                router,
                envelope_origin_for_peer(peer_service_id)?,
            )?;
            tracing::info!(
                target_delivery_id = %response.delivery.target_delivery_id,
                outcome = %response.delivery.outcome,
                inbox_seq = ?response.delivery.inbox_seq,
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

/// Public prekey and current device-authority lookups (single and batched).
fn handle_mesh_device_lookup(
    method: &str,
    path: &str,
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> Option<anyhow::Result<MeshResponse>> {
    let state = router.state();
    let value = match (method, path) {
        ("GET", path)
            if path.starts_with(ramflux_protocol::custody::CUSTODY_HISTORY_PATH_PREFIX) =>
        {
            handle_custody_consent_history(path, router).and_then(|r| Ok(serde_json::to_value(r)?))
        }

        ("GET", path) if path.starts_with("/mvp1/prekey/") => {
            handle_mvp1_prekey_fetch(path, state, router.store())
                .and_then(|r| Ok(serde_json::to_value(r)?))
        }
        ("GET", path) if path.starts_with("/mvp1/device-auth-key/") => {
            handle_mvp1_device_auth_key_fetch(path, state)
                .and_then(|r| Ok(serde_json::to_value(r)?))
        }
        ("POST", ramflux_node_core::DEVICE_AUTH_KEYS_PATH) => {
            handle_mvp1_device_auth_key_batch(body, state)
                .and_then(|r| Ok(serde_json::to_value(r)?))
        }
        _ => return None,
    };
    Some(device_lookup_mesh_response(value))
}

fn handle_mesh_general_value(
    method: &str,
    path: &str,
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<MeshResponse> {
    if let Some(response) = handle_mesh_device_lookup(method, path, body, router) {
        return response;
    }
    match (method, path) {
        ("POST", "/mvp2/device-set") => {
            let response = handle_signed_device_set(body, router)?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("GET", path) if path.starts_with("/mvp2/device-set/") => {
            let response =
                router.state().signed_device_set(path.trim_start_matches("/mvp2/device-set/"));
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("POST", "/mvp1/identity/register") => {
            let response =
                handle_mvp1_identity_register(body, router.state(), router.store(), None)?;
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
        ("POST", "/mvp10/own-devices/fanout") => mesh_fanout_response(body, router),
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
        ("POST", "/admin/custody/budgets") => {
            let response = crate::lifecycle::handle_custody_budgets(body, router.store())?;
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
        ("GET", path) if path.starts_with("/mvp1/principal-manifest/") => Ok(MeshResponse::json(
            "401 Unauthorized",
            serde_json::to_vec(&unauthenticated_principal_lookup())?,
        )),
        ("POST", "/mvp1/principal-lookup") => authenticated_principal_mesh_response(body, router),
        ("GET", path) if is_identity_manifest_path(path) => {
            let response = handle_mvp1_device_manifest_fetch(path, router.state(), router.store())?;
            Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
        }
        ("GET", path) if path.starts_with("/mvp1/inbox-entry/") => {
            entry_fetch::reply(path, router.state())
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

#[cfg(feature = "itest-http")]
fn handle_mvp0_envelope(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    handle_mvp0_envelope_from(body, router, ramflux_node_core::RouterEnvelopeOrigin::Gateway)
}
pub(crate) fn envelope_origin_for_peer(
    peer_service_id: &str,
) -> anyhow::Result<ramflux_node_core::RouterEnvelopeOrigin> {
    match peer_service_id {
        "ramflux-federation" => Ok(ramflux_node_core::RouterEnvelopeOrigin::Federation),
        "ramflux-gateway" => Ok(ramflux_node_core::RouterEnvelopeOrigin::Gateway),
        _ => anyhow::bail!("mesh peer cannot submit envelopes"),
    }
}
fn handle_mvp0_envelope_mesh_from(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
    let started = Instant::now();
    let envelope = serde_json::from_slice(body)?;
    router.submit_envelope_mesh_from(envelope, started, origin)
}
#[cfg(feature = "itest-http")]
fn handle_mvp0_envelope_from(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    let total_started = Instant::now();
    let decode_started = Instant::now();
    let envelope: ramflux_protocol::Envelope = serde_json::from_slice(body)?;
    ramflux_node_core::record_router_submit_decode_us(elapsed_us(decode_started));
    router.submit_envelope_from(envelope, total_started, origin)
}

pub(crate) async fn handle_mvp0_envelope_async_from(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
    let total_started = Instant::now();
    let decode_started = Instant::now();
    let envelope: ramflux_protocol::Envelope = serde_json::from_slice(body)?;
    ramflux_node_core::record_router_submit_decode_us(elapsed_us(decode_started));
    router.submit_envelope_mesh_async_from(envelope, total_started, origin).await
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
) -> anyhow::Result<ramflux_node_core::RouterAckResponse> {
    let ack: ramflux_protocol::Ack = serde_json::from_slice(body)?;
    ack_response(router.apply_ack(&ack))
}

fn handle_mvp0_ack_bound(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_node_core::RouterAckResponse> {
    let request: ramflux_node_core::TargetAckRequest = serde_json::from_slice(body)?;
    ack_response(router.apply_bound_ack(&request))
}

fn ack_response(
    result: anyhow::Result<ramflux_node_core::InboxCursorResponse>,
) -> anyhow::Result<ramflux_node_core::RouterAckResponse> {
    match result {
        Ok(cursor) => Ok(ramflux_node_core::RouterAckResponse::Cursor(cursor)),
        Err(error)
            if matches!(
                error.downcast_ref::<ramflux_node_core::NodeCoreError>(),
                Some(ramflux_node_core::NodeCoreError::AckBackpressureRetry)
            ) =>
        {
            Ok(ramflux_node_core::RouterAckResponse::Rejected {
                reason: "ack_backpressure_retry".into(),
            })
        }
        Err(error) => Err(error),
    }
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

pub(crate) fn handle_mvp1_identity_register(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    source_override: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let mut request: ramflux_node_core::IdentityRegisterRequest =
        match ramflux_protocol::parse_i_json(body) {
            Ok(request) => request,
            Err(_) => {
                return Ok(serde_json::json!(ramflux_protocol::IdentityRegistrationFailure {
                    error: ramflux_protocol::IdentityRegistrationFailureBody {
                        reason_code: ramflux_protocol::IdentityDirectoryReason::InvalidRegistration
                    }
                }));
            }
        };
    if let Some(source) = source_override {
        request.source_ip_hash = Some(source.into());
    }
    request.now = match std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
    {
        Some(now) => now,
        None => {
            return Ok(serde_json::json!(ramflux_protocol::IdentityRegistrationFailure {
                error: ramflux_protocol::IdentityRegistrationFailureBody {
                    reason_code: ramflux_protocol::IdentityDirectoryReason::RegistrationUnavailable
                }
            }));
        }
    };
    tracing::info!(
        principal_id = %request.proof.principal_id,
        device_id = %request.proof.device_id,
        target_delivery_id = %request.target_delivery_id,
        "router decoded mvp1 identity registration"
    );
    let response = match state.register_identity_durable(&request, store) {
        Ok(response) => response,
        Err(
            error @ (ramflux_node_core::NodeCoreError::PrincipalIdTaken
            | ramflux_node_core::NodeCoreError::DeviceIdTaken),
        ) => {
            return Ok(serde_json::to_value(ramflux_protocol::IdentityRegistrationFailure {
                error: ramflux_protocol::IdentityRegistrationFailureBody {
                    reason_code: if matches!(error, ramflux_node_core::NodeCoreError::DeviceIdTaken)
                    {
                        ramflux_protocol::IdentityDirectoryReason::DeviceIdTaken
                    } else {
                        ramflux_protocol::IdentityDirectoryReason::PrincipalIdTaken
                    },
                },
            })?);
        }
        Err(error) => {
            tracing::warn!(%error, stage="identity_registration_admission", "router registration rejected");
            let reason_code = match &error {
                ramflux_node_core::NodeCoreError::Capacity { .. } => {
                    ramflux_protocol::IdentityDirectoryReason::Capacity
                }
                ramflux_node_core::NodeCoreError::Redb(_)
                | ramflux_node_core::NodeCoreError::SnapshotSerialization(_) => {
                    ramflux_protocol::IdentityDirectoryReason::RegistrationUnavailable
                }
                ramflux_node_core::NodeCoreError::ItestHttp(reason)
                    if reason.contains("branch proof replay") =>
                {
                    ramflux_protocol::IdentityDirectoryReason::RegistrationReplay
                }
                _ => ramflux_protocol::IdentityDirectoryReason::InvalidRegistration,
            };
            return Ok(serde_json::to_value(ramflux_protocol::IdentityRegistrationFailure {
                error: ramflux_protocol::IdentityRegistrationFailureBody { reason_code },
            })?);
        }
    };
    tracing::info!(
        principal_id = %response.principal_id,
        device_id = %response.device_id,
        target_delivery_id = %response.target_delivery_id,
        session_bound = response.session_bound,
        "router mvp1 identity registration outcome"
    );
    Ok(serde_json::to_value(response)?)
}

#[cfg(feature = "itest-http")]
fn handle_itest_device_lookup(
    stream: &mut TcpStream,
    request: &ramflux_node_core::NodeHttpRequest,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<bool> {
    let state = router.state();
    if request.method != "GET" {
        return Ok(false);
    }
    let result = if request.path.starts_with("/mvp1/prekey/") {
        handle_mvp1_prekey_fetch(&request.path, state, router.store())
            .and_then(|r| serde_json::to_value(r).map_err(anyhow::Error::from))
    } else if request.path.starts_with("/mvp1/device-auth-key/") {
        handle_mvp1_device_auth_key_fetch(&request.path, state)
            .and_then(|r| serde_json::to_value(r).map_err(anyhow::Error::from))
    } else {
        return Ok(false);
    };
    match result {
        Ok(value) => ramflux_node_core::write_itest_json_response(stream, "200 OK", &value)?,
        Err(error) => ramflux_node_core::write_itest_json_response(
            stream,
            "400 Bad Request",
            &serde_json::json!({"error":error.to_string()}),
        )?,
    }
    Ok(true)
}

fn device_lookup_mesh_response(
    result: anyhow::Result<serde_json::Value>,
) -> anyhow::Result<MeshResponse> {
    match result {
        Ok(response) => Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?)),
        Err(error) => Ok(MeshResponse::json(
            "400 Bad Request",
            serde_json::to_vec(&serde_json::json!({"error":error.to_string()}))?,
        )),
    }
}

fn handle_mvp1_device_auth_key_fetch(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> anyhow::Result<Option<ramflux_node_core::DeviceAuthKeyResponse>> {
    let device_id = path.trim_start_matches("/mvp1/device-auth-key/");
    Ok(state.mvp1_device_auth_key_checked(device_id)?)
}

/// Answers up to 256 current-authority lookups; invalid selectors read as absent devices.
fn handle_mvp1_device_auth_key_batch(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
) -> anyhow::Result<ramflux_node_core::DeviceAuthKeyBatchResponse> {
    let request: ramflux_node_core::DeviceAuthKeyBatchRequest = serde_json::from_slice(body)?;
    anyhow::ensure!(
        request.devices.len() <= ramflux_node_core::DEVICE_AUTH_KEY_BATCH_LIMIT,
        "device authority batch too large"
    );
    Ok(ramflux_node_core::DeviceAuthKeyBatchResponse {
        keys: request
            .devices
            .iter()
            .map(|device| state.mvp1_device_auth_key_checked(device).ok().flatten())
            .collect(),
    })
}

fn handle_mvp6_registration_policy(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::RegistrationPolicy> {
    let request: ramflux_node_core::RegistrationPolicy = serde_json::from_slice(body)?;
    state.mvp6_set_registration_policy(request);
    let response = state.mvp6_registration_policy();
    state.persist_identity_registry(store)?;
    Ok(response)
}

fn handle_mvp6_friend_request(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::FriendRequestBudgetResponse> {
    let request: ramflux_node_core::FriendRequestBudgetRequest = serde_json::from_slice(body)?;
    let response = state.mvp6_record_friend_request(&request)?;
    state.persist_identity_registry(store)?;
    Ok(response)
}

#[cfg(feature = "itest-http")]
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
    state.persist_identity_registry(store)?;
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
    let response = if let Some(native) =
        state.publish_custody_prekey(&request, ramflux_node_core::now_unix_seconds(), store)?
    {
        native
    } else {
        let response = state.mvp1_publish_prekey(request)?;
        state.persist_identity_registry(store)?;
        response
    };
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
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::PrekeyResponse> {
    let device_id = path.trim_start_matches("/mvp1/prekey/");
    let response = if let Some(native) =
        state.custody_prekey_response(device_id, ramflux_node_core::now_unix_seconds(), store)?
    {
        native
    } else {
        state.mvp1_prekey_checked(device_id)?
    };
    tracing::info!(
        device_id = %response.device_id,
        has_bundle = response.bundle.is_some(),
        target_delivery_id = ?response.target_delivery_id,
        "router mvp1 prekey fetch outcome"
    );
    Ok(response)
}

fn handle_custody_consent_history(
    path: &str,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<Option<ramflux_node_core::CustodyPublication>> {
    let selector = path
        .strip_prefix(ramflux_protocol::custody::CUSTODY_HISTORY_PATH_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("invalid custody history path"))?;
    let (anchor, hash) = selector
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid custody history selector"))?;
    Ok(router.state().custody_consent_history(
        anchor,
        hash,
        ramflux_node_core::now_unix_seconds(),
        router.store(),
    )?)
}

fn is_identity_manifest_path(path: &str) -> bool {
    path.starts_with("/mvp1/device-manifest/")
}

fn handle_mvp1_device_manifest_fetch(
    path: &str,
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<Option<ramflux_node_core::DeviceManifestResponse>> {
    let principal_commitment = path.trim_start_matches("/mvp1/device-manifest/");
    let response = state.ordinary_device_manifest(
        principal_commitment,
        ramflux_node_core::now_unix_seconds(),
        store,
    )?;
    tracing::info!(
        principal_commitment,
        found = response.is_some(),
        device_count = response.as_ref().map_or(0, |manifest| manifest.devices.len()),
        "router mvp1 device manifest fetch outcome"
    );
    Ok(response)
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
    // Reads filter by deadline only; the periodic sweep owns deletion.
    let response = state.mvp1_inbox_at(
        target_delivery_id,
        after_inbox_seq,
        limit,
        i64::try_from(ramflux_node_core::now_unix_seconds())?,
    );
    tracing::info!(
        target_delivery_id = %response.target_delivery_id,
        after_inbox_seq,
        limit,
        entries = response.entries.len(),
        "router mvp1 inbox fetch outcome"
    );
    Ok(response)
}

fn authenticated_principal_mesh_response(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<MeshResponse> {
    let request: ramflux_node_core::PrincipalLookupRequest = serde_json::from_slice(body)?;
    let response = router.state().authenticated_principal_lookup(
        &request,
        ramflux_node_core::now_unix_seconds(),
        router.store(),
    )?;
    Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
}

fn forward_authority_response(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<MeshResponse> {
    authority_refresh_response(refresh_forward_authority(body, router))
}

fn authority_refresh_response(
    result: anyhow::Result<ramflux_protocol::Envelope>,
) -> anyhow::Result<MeshResponse> {
    match result {
        Ok(envelope) => Ok(MeshResponse::json("200 OK", serde_json::to_vec(&envelope)?)),
        Err(error) => {
            let reason = match error.downcast_ref::<ramflux_node_core::NodeCoreError>() {
                Some(ramflux_node_core::NodeCoreError::SourceAuthorityRefused { reason_code }) => {
                    *reason_code
                }
                _ => return Err(error),
            };
            Ok(MeshResponse::json(
                "409 Conflict",
                serde_json::to_vec(&ramflux_node_core::EnvelopeAuthorityRefusal {
                    reason_code: reason,
                })?,
            ))
        }
    }
}

fn refresh_forward_authority(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_protocol::Envelope> {
    let mut envelope: ramflux_protocol::Envelope = serde_json::from_slice(body)?;
    router.state().authenticated_envelope_source_from(
        &envelope,
        Some(router.store()),
        ramflux_node_core::RouterEnvelopeOrigin::Federation,
    )?;
    router.state().refresh_registered_envelope_authority(&mut envelope)?;
    Ok(envelope)
}

fn mesh_fanout_response(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<MeshResponse> {
    let request: ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest =
        serde_json::from_slice(body)?;
    let response = ramflux_node_core::publication::capture(|| {
        crate::router_engine::own_device_fanout_inner(router.state(), router.store(), &request)
    })?
    .published_blocking()??;
    let response = tokio::runtime::Builder::new_current_thread()
        .build()?
        .block_on(response.resolved_with_metadata())?;
    Ok(MeshResponse::json("200 OK", serde_json::to_vec(&response)?))
}

#[cfg(test)]
mod tests {
    mod forwarded_reply;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[cfg(feature = "itest-http")]
    fn legacy_release_subprocesses() -> anyhow::Result<bool> {
        const CHILD: &str = "RAMFLUX_LEGACY_RELEASE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            for flag in [None, Some("0")] {
                let mut command = std::process::Command::new(std::env::current_exe()?);
                command.args(["--exact", "handlers::tests::legacy_home_node_apply_routes_are_absent_on_http_and_mesh_admin"])
                    .env(CHILD, "1").env("RAMFLUX_ROUTER_ADMIN_TOKEN", "release-token").env_remove("RAMFLUX_HOME_MIGRATION_ENABLED");
                if let Some(flag) = flag {
                    command.env("RAMFLUX_HOME_MIGRATION_ENABLED", flag);
                }
                let output = command.output()?;
                assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
                    "child must run exactly one test: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
            return Ok(true);
        }
        Ok(false)
    }

    #[test]
    #[cfg(feature = "itest-http")]
    fn legacy_home_node_apply_routes_are_absent_on_http_and_mesh_admin() -> anyhow::Result<()> {
        if legacy_release_subprocesses()? {
            return Ok(());
        }
        let (state, store, path) = crate::router_runtime::tests::test_router("legacy-release")?;
        let now = 1_760_000_020;
        let request = crate::router_runtime::tests::register_test_device_at(
            &state,
            "alice",
            "alice_phone",
            "target_alice",
            1,
            now,
        )?;
        store.bootstrap_router(&state)?;
        let before = serde_json::to_value(state.mvp1_identities_snapshot())?;
        let handle = crate::router_runtime::RouterHandle::tokio(state, store, None);
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let _client = std::net::TcpStream::connect(listener.local_addr()?)?;
        let (mut stream, _) = listener.accept()?;
        for (path, body) in [
            (concat!("/admin/home-node-", "migration/apply"), b"{}".to_vec()),
            (concat!("/admin/home-node-", "route/update/apply"), b"{}".to_vec()),
        ] {
            let request = ramflux_transport::MeshHttpRequest {
                method: "POST".into(),
                path: path.into(),
                body: body.clone(),
            };
            let response = handle_mesh_request_value(request, &handle, "ramflux-gateway")?;
            assert_eq!(response.status, "404 Not Found");
            let request = ramflux_node_core::NodeHttpRequest {
                method: "POST".into(),
                path: path.into(),
                body,
                keep_alive: false,
                source_ip_hash: None,
                pre_auth_cookie: None,
                pre_auth_now: None,
            };
            assert!(!handle_itest_admin_request(&mut stream, &request, &handle)?);
        }
        let sibling = handle_mesh_request_value(
            ramflux_transport::MeshHttpRequest {
                method: "POST".into(),
                path: "/admin/custody/budgets".into(),
                body: br#"{"admin_token":"release-token"}"#.to_vec(),
            },
            &handle,
            "ramflux-gateway",
        )?;
        assert_eq!(sibling.status, "200 OK");
        assert!(handle_itest_admin_request(
            &mut stream,
            &ramflux_node_core::NodeHttpRequest {
                method: "POST".into(),
                path: "/admin/custody/budgets".into(),
                body: br#"{"admin_token":"release-token"}"#.to_vec(),
                keep_alive: false,
                source_ip_hash: None,
                pre_auth_cookie: None,
                pre_auth_now: None,
            },
            &handle,
        )?);

        assert_eq!(before, serde_json::to_value(handle.state().mvp1_identities_snapshot())?);
        assert!(handle.state().home_node_migration(&request.proof.principal_id).is_none());
        assert!(handle.state().resolve_home_node_route(&request.proof.principal_id).is_none());
        drop(handle);
        let store = ramflux_node_core::RouterRedbStore::open(&path)?;
        let restored =
            store.load_router()?.ok_or_else(|| anyhow::anyhow!("missing restored router"))?;
        assert_eq!(before, serde_json::to_value(restored.mvp1_identities_snapshot())?);
        assert!(restored.home_node_migration(&request.proof.principal_id).is_none());
        assert!(restored.resolve_home_node_route(&request.proof.principal_id).is_none());
        drop(store);
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn custody_budget_inspection_requires_admin_token_and_mesh_peer() -> anyhow::Result<()> {
        const CHILD: &str = "RAMFLUX_BUDGET_ADMIN_TEST_CHILD";
        const TOKEN: &str = "custody-budget-inspection-private-test-token";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "handlers::tests::custody_budget_inspection_requires_admin_token_and_mesh_peer",
                ])
                .env(CHILD, "1")
                .env("RAMFLUX_ROUTER_ADMIN_TOKEN", TOKEN)
                .output()?;
            anyhow::ensure!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
            return Ok(());
        }
        let path = temp_path("custody_budget_admin")?;
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let handle = crate::router_runtime::RouterHandle::tokio(
            Arc::new(ramflux_node_core::RouterCore::new()),
            store,
            None,
        );
        for token in ["", "wrong"] {
            let request = ramflux_transport::MeshHttpRequest {
                method: "POST".into(),
                path: "/admin/custody/budgets".into(),
                body: serde_json::to_vec(&serde_json::json!({"admin_token": token}))?,
            };
            assert!(handle_mesh_request_value(request, &handle, "ramflux-gateway").is_err());
        }
        let request = || ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: "/admin/custody/budgets".into(),
            body: serde_json::to_vec(&serde_json::json!({"admin_token": TOKEN}))
                .unwrap_or_default(),
        };
        let response = handle_mesh_request_value(request(), &handle, "ramflux-retention")?;
        assert_eq!(response.status, "403 Forbidden");
        let response = handle_mesh_request_value(request(), &handle, "ramflux-gateway")?;
        assert_eq!(response.status, "200 OK");
        let value: serde_json::Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["rows"], serde_json::json!([]));
        assert!(value["observed_at"].is_u64());
        assert_eq!(handle.store().custody_publication_write_count(), 0);
        drop(handle);
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn forwarded_endpoint_is_not_reachable_from_client_listener() -> anyhow::Result<()> {
        let (state, store, path) = crate::router_runtime::tests::test_router("forwarded-role")?;
        let mut envelope =
            crate::router_runtime::tests::current_envelope("forwarded-role", "active-target")?;
        state.refresh_registered_envelope_authority(&mut envelope)?;
        let handle = crate::router_runtime::RouterHandle::tokio(state, store, None);
        let body = serde_json::to_vec(&ramflux_node_core::ForwardedEnvelopeRequest {
            peer_node_id: "test-peer".into(),
            envelope,
            migration_evidence: None,
        })?;
        for peer in ["ramflux-gateway", "ramflux-relay", "ramflux-retention"] {
            let response = handle_mesh_request_value(
                ramflux_transport::MeshHttpRequest {
                    method: "POST".into(),
                    path: "/mvp0/envelope/forwarded".into(),
                    body: body.clone(),
                },
                &handle,
                peer,
            )?;
            assert_eq!(response.status, "403 Forbidden");
        }
        #[cfg(feature = "itest-http")]
        {
            use std::io::{Read, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let mut client = std::net::TcpStream::connect(listener.local_addr()?)?;
            client.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
            let (mut server, _) = listener.accept()?;
            write!(
                client,
                "POST /mvp0/envelope/forwarded HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            client.write_all(&body)?;
            handle_itest_request(&mut server, &handle)?;
            drop(server);
            let mut reply = String::new();
            client.read_to_string(&mut reply)?;
            assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
        }
        assert_eq!(handle.state().resume("active-target", 0, 10), []);
        let response = handle_mesh_request_value(
            ramflux_transport::MeshHttpRequest {
                method: "POST".into(),
                path: "/mvp0/envelope/forwarded".into(),
                body,
            },
            &handle,
            "ramflux-federation",
        )?;
        assert_eq!(response.status, "200 OK");
        let body: serde_json::Value = serde_json::from_slice(&response.body)?;
        assert_eq!(body["accepted"], true);
        assert_eq!(handle.state().resume("active-target", 0, 10).len(), 1);
        drop(handle);
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn migration_peer_ingress_requires_the_federation_role_before_decoding() -> anyhow::Result<()> {
        let (state, store, path) = crate::router_runtime::tests::test_router("migration-role")?;
        let handle = crate::router_runtime::RouterHandle::tokio(state, store, None);
        for peer in ["ramflux-gateway", "ramflux-relay", "ramflux-retention"] {
            let response = handle_mesh_request_value(
                ramflux_transport::MeshHttpRequest {
                    method: "POST".into(),
                    path: ramflux_node_core::MIGRATION_PEER_PATH.into(),
                    body: b"{}".to_vec(),
                },
                &handle,
                peer,
            )?;
            assert_eq!(response.status, "403 Forbidden");
        }
        drop(handle);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn only_explicit_authority_refusals_are_terminal() -> anyhow::Result<()> {
        use ramflux_node_core::{EnvelopeAuthorityReason, NodeCoreError};
        for error in [
            NodeCoreError::Unauthorized("partial restore".into()),
            NodeCoreError::ItestHttp("directory missing".into()),
            NodeCoreError::ItestJson("incomplete state".into()),
            NodeCoreError::Capacity { resource: "directory" },
        ] {
            assert!(authority_refresh_response(Err(error.into())).is_err());
        }
        for reason_code in [
            EnvelopeAuthorityReason::Revoked,
            EnvelopeAuthorityReason::AuthorityMismatch,
            EnvelopeAuthorityReason::StaleEpoch,
        ] {
            let response =
                authority_refresh_response(Err(NodeCoreError::SourceAuthorityRefused {
                    reason_code,
                }
                .into()))?;
            assert_eq!(response.status, "409 Conflict");
        }
        Ok(())
    }

    #[test]
    fn authority_refresh_requires_federation_mesh_and_replaces_attached_authority()
    -> anyhow::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (state, store, path) = crate::router_runtime::tests::test_router("authority-refresh")?;
        let handle = crate::router_runtime::RouterHandle::tokio(state, store, None);
        let mut envelope =
            crate::router_runtime::tests::current_envelope("refresh-authority", "peer")?;
        envelope
            .ext
            .ext
            .insert("source_device_authority".into(), serde_json::json!({"obsolete":true}));
        let request = ramflux_transport::GatewayQuicRequest {
            method: "POST".into(),
            path: "/mvp1/envelope-authority".into(),
            body: serde_json::to_value(envelope)?,
        };
        assert!(
            runtime
                .block_on(handle_mesh_quic_request_value(&request, &handle, "ramflux-gateway"))
                .is_err()
        );
        let response = runtime.block_on(handle_mesh_quic_request_value(
            &request,
            &handle,
            "ramflux-federation",
        ))?;
        assert_eq!(response.status, 200);
        let refreshed: ramflux_protocol::Envelope = serde_json::from_value(response.body)?;
        let (authority, _) =
            ramflux_node_core::DeviceAuthKeyResponse::forwarded_envelope_source(&refreshed)?;
        assert!(authority.signed_device_set.is_some());
        let mut invalid = request.clone();
        invalid.body["signature"] = serde_json::json!(ramflux_protocol::encode_base64url([0; 64]));
        let refused = runtime.block_on(handle_mesh_quic_request_value(
            &invalid,
            &handle,
            "ramflux-federation",
        ))?;
        assert_eq!(refused.status, 409);
        let refusal: ramflux_node_core::EnvelopeAuthorityRefusal =
            serde_json::from_value(refused.body)?;
        assert_eq!(
            refusal.reason_code,
            ramflux_node_core::EnvelopeAuthorityReason::AuthorityMismatch
        );
        drop(handle);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn mesh_quic_request_submit_uses_async_router_path() -> anyhow::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (state, store, path) = crate::router_runtime::tests::test_router("mesh_async_submit")?;
        let handle = crate::router_runtime::RouterHandle::tokio(state, store, None);
        let envelope = crate::router_runtime::tests::current_envelope(
            "env_router_async_ingress",
            "target_router_async_ingress",
        )?;
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
        let point = serde_json::to_value(handle.state().fetch_entry(
            "target_router_async_ingress",
            1,
            0,
        )?)?;
        assert_eq!(accepted.body["incarnation_id"], point["incarnation_id"]);
        assert_eq!(accepted.body["retain_until"], point["record"]["retain_until"]);
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
        assert_eq!(replay.outcome, accepted.outcome);
        assert_eq!(replay.inbox_seq, accepted.inbox_seq);
        assert_eq!(replay.target_delivery_id, accepted.target_delivery_id);
        let rows = handle.state().resume("target_router_async_ingress", 0, 10);
        assert_eq!(rows.len(), 1, "identical retry adds no second delivery");
        assert_eq!(Some(rows[0].inbox_seq), accepted.inbox_seq);
        assert_eq!(rows[0].envelope.envelope_id, "env_router_async_ingress");

        let _removed = std::fs::remove_file(&path);
        let _removed = std::fs::remove_dir_all(path.with_extension("redb.wal"));
        Ok(())
    }

    #[test]
    fn mesh_device_lookup_errors_are_explicit_responses() -> anyhow::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let path = temp_path("device_lookup_errors")?;
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        let handle = crate::router_runtime::RouterHandle::tokio(state, store, None);
        for path in ["/mvp1/prekey/missing", "/mvp1/device-auth-key/missing"] {
            let request = ramflux_transport::GatewayQuicRequest {
                method: "GET".into(),
                path: path.into(),
                body: serde_json::Value::Null,
            };
            let response = runtime.block_on(handle_mesh_quic_request_value(
                &request,
                &handle,
                "ramflux-gateway",
            ))?;
            assert_eq!(response.status, 400);
            assert!(
                response.body["error"]
                    .as_str()
                    .is_some_and(|s| s.contains("qualified device required"))
            );
        }
        drop(handle);
        let _ = std::fs::remove_file(path);
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

    #[test]
    fn ack_backpressure_is_a_typed_legacy_refusal() -> anyhow::Result<()> {
        let response =
            ack_response(Err(ramflux_node_core::NodeCoreError::AckBackpressureRetry.into()))?;
        let json = serde_json::to_value(&response)?;
        assert_eq!(json, serde_json::json!({"reason": "ack_backpressure_retry"}));
        assert!(matches!(serde_json::from_value::<ramflux_node_core::RouterAckResponse>(json)?,
            ramflux_node_core::RouterAckResponse::Rejected { reason } if reason == "ack_backpressure_retry"));
        let cursor = ramflux_node_core::InboxCursorResponse::from(
            &ramflux_node_core::CursorAckState::default(),
        );
        let json = serde_json::to_value(&cursor)?;
        assert_eq!(
            serde_json::to_value(ack_response(Ok(cursor))?)?,
            json,
            "legacy successful cursor JSON stays unchanged"
        );
        assert!(
            ack_response(Err(anyhow::anyhow!("ack_backpressure_retry"))).is_err(),
            "only a typed refusal may take the retry branch"
        );
        Ok(())
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
