// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::http_response::HttpResponse;
use crate::public_source_limits::{
    PublicSourceLimitConfig, PublicSourceLimits, SourceConnectionPermit,
};
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
    let limit = crate::http_connections::connection_limit(
        true,
        ramflux_node_core::environment::var("RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS")
            .ok()
            .as_deref(),
    )?;
    let source_limits = PublicSourceLimits::new(PublicSourceLimitConfig::configured(limit)?);
    let limits = crate::http_limits::configured(true)?;
    let listener = TcpListener::bind(addr).map_err(|error| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "federation public HTTP bind failed at {addr}: {error}"
        ))
    })?;
    let connections = ramflux_node_core::ConnectionSet::new(limit);
    tracing::info!(addr, limit, "federation public client HTTP surface listening");
    listener
        .set_nonblocking(true)
        .map_err(|error| ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()))?;
    ramflux_node_core::spawn_service_worker("ramflux-federation-public-http", move |shutdown| {
        let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
        while !shutdown.is_cancelled() {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
                Err(error) => {
                    std::thread::sleep(backoff.failure(&error));
                    continue;
                }
            };
            match spawn_public_connection(
                stream,
                context.clone(),
                &connections,
                limits,
                &source_limits,
            ) {
                Ok(_) => backoff.success(),
                Err(error) => std::thread::sleep(backoff.failure(&error)),
            }
        }
    })?;
    Ok(())
}

pub(crate) fn spawn_public_connection(
    stream: TcpStream,
    context: FederationPublicHttpContext,
    connections: &Arc<ramflux_node_core::ConnectionSet>,
    limits: ramflux_node_core::HttpRequestLimits,
    source_limits: &Arc<PublicSourceLimits>,
) -> std::io::Result<bool> {
    let accepted_at = std::time::Instant::now();
    let source = stream.peer_addr()?.ip();
    tracing::debug!(%source, "federation public connection source observed");
    if source_limits.observe_accepted_source(source) {
        tracing::warn!(
            "more than 90 percent of public connections share one private source; verify proxy or rootless port forwarding and RAMFLUX_FEDERATION_PER_SOURCE_LIMITS"
        );
    }
    let Ok(source_permit) = source_limits.acquire_connection(source, accepted_at) else {
        // Source refusals keep their generic 503, but response I/O belongs to a tracked worker.
        crate::http_connections::spawn_connection(
            stream,
            connections,
            (),
            accepted_at,
            |stream, (), at, connection| {
                let Some(_response) = connection.begin_request() else {
                    return;
                };
                let _ = ramflux_node_core::write_http_response_with_deadline(
                    stream,
                    "503 Service Unavailable",
                    "text/plain; charset=utf-8",
                    b"service unavailable",
                    at + std::time::Duration::from_secs(1),
                );
            },
        )?;
        return Ok(false);
    };
    crate::http_connections::spawn_connection(
        stream,
        connections,
        (context, source_permit),
        accepted_at,
        move |stream, context, at, connection| {
            handle_public_connection_tracked(
                stream,
                &context.0,
                limits,
                at,
                Some(&context.1),
                Some(connection),
            );
        },
    )
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
    handle_public_connection_with_source_limits(stream, context, limits, accepted_at, None);
}

#[cfg(test)]
fn handle_public_connection_with_source_limits(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: std::time::Instant,
    source_permit: Option<&SourceConnectionPermit>,
) {
    handle_public_connection_tracked(stream, context, limits, accepted_at, source_permit, None);
}

struct RequestAdmission<'a> {
    connection: Option<&'a ramflux_node_core::ConnectionGuard>,
    request: Option<ramflux_node_core::ConnectionRequestGuard>,
}

impl RequestAdmission<'_> {
    fn begin(&mut self) -> bool {
        self.request = ramflux_node_core::begin_connection_request(self.connection);
        self.request.is_some()
    }
}

fn handle_public_connection_tracked(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: std::time::Instant,
    source_permit: Option<&SourceConnectionPermit>,
    connection: Option<&ramflux_node_core::ConnectionGuard>,
) {
    let mut admission = RequestAdmission { connection, request: None };
    let response = match public_response(
        stream,
        context,
        limits,
        accepted_at,
        source_permit,
        &mut admission,
    ) {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "federation public request failed");
            let status =
                crate::http_limits::rejection(&error).unwrap_or("500 Internal Server Error");
            let body = if crate::http_limits::rejection(&error).is_some() {
                "request rejected"
            } else {
                "internal server error"
            };
            Some(HttpResponse::text(status, body))
        }
    };
    if let Some(response) = response
        && let Err(error) = response.write(stream, limits, accepted_at)
    {
        tracing::warn!(%error, "federation public response failed");
    }
}

#[cfg(test)]
pub(crate) fn handle_public_request(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let limits = crate::http_limits::defaults(true);
    let accepted_at = std::time::Instant::now();
    let mut admission = RequestAdmission { connection: None, request: None };
    if let Some(response) =
        public_response(stream, context, limits, accepted_at, None, &mut admission)?
    {
        response.write(stream, limits, accepted_at)?;
    }
    Ok(())
}

fn public_response(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: std::time::Instant,
    source_permit: Option<&SourceConnectionPermit>,
    admission: &mut RequestAdmission<'_>,
) -> Result<Option<HttpResponse>, ramflux_node_core::NodeCoreError> {
    let Some(request) =
        ramflux_node_core::read_http_request_with_limits(stream, limits, accepted_at)?
    else {
        return Ok(None);
    };
    if !admission.begin() {
        return Ok(Some(HttpResponse::text("503 Service Unavailable", "shutting down")));
    }
    #[cfg(feature = "itest-http")]
    ramflux_node_core::shutdown_request_test_delay();

    if source_permit.is_some_and(|permit| !permit.allow_request(std::time::Instant::now())) {
        return Ok(Some(HttpResponse::text("429 Too Many Requests", "too many requests")));
    }
    let discovery = &context.discovery;
    let router = context.router.as_ref();
    let response = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => HttpResponse::json(&serde_json::json!({
            "service": "ramflux-federation-public", "status": "ok"
        }))?,
        ("GET", "/.well-known/ramflux/client") => HttpResponse::json(&discovery.client_record()?)?,
        ("GET", "/.well-known/ramflux/server") => {
            HttpResponse::json(&discovery.well_known_record()?)?
        }
        ("GET", path)
            if path.starts_with("/mvp1/prekey/") || path.starts_with("/mvp1/device-manifest/") =>
        {
            let response: serde_json::Value = router_get_json(router, path)?;
            HttpResponse::json(&response)?
        }
        _ => HttpResponse::text("404 Not Found", "not found"),
    };
    Ok(Some(response))
}

#[cfg(test)]
mod limits_tests {
    #[test]
    fn connection_limits_are_bounded_and_invalid_configuration_fails_closed() {
        for public in [true, false] {
            assert_eq!(crate::http_connections::connection_limit(public, None).ok(), Some(64));
            assert_eq!(crate::http_connections::connection_limit(public, Some("1")).ok(), Some(1));
            for invalid in ["", "0", "-1", "4097", "abc", "${UNRESOLVED}"] {
                assert!(crate::http_connections::connection_limit(public, Some(invalid)).is_err());
            }
        }
    }
}
