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
    let listener = TcpListener::bind(addr).map_err(|error| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "federation public HTTP bind failed at {addr}: {error}"
        ))
    })?;
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    tracing::info!(addr, limit, "federation public client HTTP surface listening");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let _worker = spawn_public_connection(
                        stream,
                        context.clone(),
                        Arc::clone(&active),
                        limit,
                    );
                }
                Err(error) => tracing::warn!(%error, "federation public accept failed"),
            }
        }
    });
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

struct ConnectionPermit(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

pub(crate) fn spawn_public_connection(
    mut stream: TcpStream,
    context: FederationPublicHttpContext,
    active: Arc<std::sync::atomic::AtomicUsize>,
    limit: usize,
) -> Option<std::thread::JoinHandle<()>> {
    use std::sync::atomic::Ordering;
    if active
        .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            if count < limit { Some(count + 1) } else { None }
        })
        .is_err()
    {
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(1)));
        let _ = ramflux_node_core::write_itest_text_response(
            &mut stream,
            "503 Service Unavailable",
            "service unavailable",
        );
        return None;
    }
    let permit = ConnectionPermit(active);
    match std::thread::Builder::new().spawn(move || {
        let _permit = permit;
        handle_public_connection(&mut stream, &context);
    }) {
        Ok(worker) => Some(worker),
        Err(error) => {
            tracing::warn!(%error, "federation public worker unavailable");
            None
        }
    }
}

pub(crate) fn handle_public_connection(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
) {
    if let Err(error) = handle_public_request(stream, context) {
        tracing::warn!(%error, "federation public request failed");
        let _ = ramflux_node_core::write_itest_text_response(
            stream,
            "500 Internal Server Error",
            "internal server error",
        );
    }
}

pub(crate) fn handle_public_request(
    stream: &mut TcpStream,
    context: &FederationPublicHttpContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(());
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
