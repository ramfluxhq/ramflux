// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::{FederationDiscoverySurface, RouterMeshClient, router_get_json};

// Deliberately has no admin credential or mutable federation trust store.
#[derive(Clone)]
pub(crate) struct FederationPublicHttpContext {
    pub(crate) router: Arc<RouterMeshClient>,
    pub(crate) discovery: FederationDiscoverySurface,
}

pub(crate) fn serve_public_http(
    addr: &str,
    context: FederationPublicHttpContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let limit = public_connection_limit(
        ramflux_node_core::environment::var("RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS")
            .ok()
            .as_deref(),
    )?;
    let limits = crate::http_limits::configured(true)?;
    let listener = TcpListener::bind(addr).map_err(|error| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "federation public HTTP bind failed at {addr}: {error}"
        ))
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|error| ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()))?;
    let connections = ramflux_node_core::ConnectionSet::new(limit);
    tracing::info!(addr, limit, "federation public client HTTP surface listening");
    ramflux_node_core::spawn_service_worker("ramflux-federation-public-http", move |shutdown| {
        while !shutdown.is_cancelled() {
            match listener.accept().map(|(stream, _)| stream) {
                Ok(stream) => {
                    if let Err(error) =
                        spawn_public_connection(stream, context.clone(), &connections, limits)
                    {
                        tracing::warn!(%error, "federation public worker unavailable");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(error) => tracing::warn!(%error, "federation public accept failed"),
            }
        }
    })?;
    Ok(())
}

fn public_connection_limit(value: Option<&str>) -> Result<usize, ramflux_node_core::NodeCoreError> {
    let limit =
        value.unwrap_or("64").parse::<usize>().ok().filter(|value| (1..=4096).contains(value));
    limit.ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestHttp(
            "RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS must be 1..4096".into(),
        )
    })
}

pub(crate) fn spawn_public_connection(
    stream: TcpStream,
    context: FederationPublicHttpContext,
    connections: &Arc<ramflux_node_core::ConnectionSet>,
    limits: ramflux_node_core::HttpRequestLimits,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    let accepted_at = std::time::Instant::now();
    let registration = stream
        .try_clone()
        .map_err(|error| ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()))?;
    connections.spawn(&registration, (stream, context), move |context, connection| {
        let (stream, context) = context;
        handle_public_connection_with_guard(stream, context, limits, accepted_at, Some(connection));
    })
}

#[cfg(test)]
pub(crate) fn handle_public_connection(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
) {
    handle_public_connection_with_limits(
        stream,
        context,
        crate::http_limits::defaults(true),
        std::time::Instant::now(),
    );
}
#[cfg(test)]
pub(crate) fn handle_public_connection_with_limits(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: std::time::Instant,
) {
    handle_public_connection_with_guard(stream, context, limits, accepted_at, None);
}
fn handle_public_connection_with_guard(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: std::time::Instant,
    connection: Option<&ramflux_node_core::ConnectionGuard>,
) {
    if let Err(error) =
        handle_public_request_with_limits(stream, context, limits, accepted_at, connection)
    {
        tracing::warn!(%error, "federation public request failed");
        let status = crate::http_limits::rejection(&error).unwrap_or("500 Internal Server Error");
        let body = if crate::http_limits::rejection(&error).is_some() {
            "request rejected"
        } else {
            "internal server error"
        };
        let _ = ramflux_node_core::write_itest_text_response(stream, status, body);
    }
}

#[cfg(test)]
pub(crate) fn handle_public_request(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    handle_public_request_with_limits(
        stream,
        context,
        crate::http_limits::defaults(true),
        std::time::Instant::now(),
        None,
    )
}
fn handle_public_request_with_limits(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: std::time::Instant,
    connection: Option<&ramflux_node_core::ConnectionGuard>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(request) =
        ramflux_node_core::read_http_request_with_limits(stream, limits, accepted_at)?
    else {
        return Ok(());
    };
    let Some(_request) = ramflux_node_core::begin_connection_request(connection) else {
        return ramflux_node_core::write_itest_text_response(
            stream,
            "503 Service Unavailable",
            "shutting down",
        );
    };

    let discovery = &context.discovery;
    let router = context.router.as_ref();
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => {
            ramflux_node_core::write_itest_json_response(
                stream,
                "200 OK",
                &serde_json::json!({
                    "service": "ramflux-federation-public", "status": "ok"
                }),
            )?;
        }
        ("GET", "/.well-known/ramflux/client") => {
            let record = discovery.client_record()?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &record)?;
        }
        ("GET", "/.well-known/ramflux/server") => {
            let record = discovery.well_known_record()?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &record)?;
        }
        ("GET", path) if path.starts_with("/mvp1/prekey/") => {
            let response: serde_json::Value = router_get_json(router, path)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp1/device-manifest/") => {
            let response: serde_json::Value = router_get_json(router, path)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => ramflux_node_core::write_itest_text_response(stream, "404 Not Found", "not found")?,
    }
    Ok(())
}

#[cfg(test)]
mod limits_tests {
    use super::public_connection_limit;
    #[test]
    fn connection_limit_is_bounded_and_invalid_configuration_fails_closed() {
        assert_eq!(public_connection_limit(None).ok(), Some(64));
        assert_eq!(public_connection_limit(Some("1")).ok(), Some(1));
        for invalid in ["", "0", "-1", "4097", "abc", "${UNRESOLVED}"] {
            assert!(public_connection_limit(Some(invalid)).is_err());
        }
    }
}
