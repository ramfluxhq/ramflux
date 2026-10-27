// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::http_response::HttpResponse;
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
    let limits = crate::http_limits::configured(true)?;
    let listener = TcpListener::bind(addr).map_err(|error| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "federation public HTTP bind failed at {addr}: {error}"
        ))
    })?;
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    tracing::info!(addr, limit, "federation public client HTTP surface listening");
    std::thread::Builder::new()
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let _worker = spawn_public_connection(
                            stream,
                            context.clone(),
                            Arc::clone(&active),
                            limit,
                            limits,
                        );
                    }
                    Err(error) => tracing::warn!(%error, "federation public accept failed"),
                }
            }
        })
        .map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "federation public listener thread unavailable: {error}"
            ))
        })?;
    Ok(())
}

pub(crate) fn spawn_public_connection(
    stream: TcpStream,
    context: FederationPublicHttpContext,
    active: Arc<std::sync::atomic::AtomicUsize>,
    limit: usize,
    limits: ramflux_node_core::HttpRequestLimits,
) -> Option<std::thread::JoinHandle<()>> {
    crate::http_connections::spawn_connection(stream, active, limit, move |stream, accepted_at| {
        handle_public_connection_with_limits(stream, &context, limits, accepted_at);
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
pub(crate) fn handle_public_connection_with_limits(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: std::time::Instant,
) {
    let response = match public_response(stream, context, limits, accepted_at) {
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
    if let Some(response) = public_response(stream, context, limits, accepted_at)? {
        response.write(stream, limits, accepted_at)?;
    }
    Ok(())
}

fn public_response(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: std::time::Instant,
) -> Result<Option<HttpResponse>, ramflux_node_core::NodeCoreError> {
    let Some(request) =
        ramflux_node_core::read_http_request_with_limits(stream, limits, accepted_at)?
    else {
        return Ok(None);
    };
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
