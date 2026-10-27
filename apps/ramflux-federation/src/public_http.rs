// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::{FederationDiscoverySurface, RouterMeshClient, router_get_json, router_post_json};

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
    let listener = TcpListener::bind(addr)
        .map_err(|error| ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()))?;
    tracing::info!(addr, "federation public client HTTP surface listening");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let context = context.clone();
            std::thread::spawn(move || {
                if let Err(error) = handle_public_request(&mut stream, &context) {
                    let _ = ramflux_node_core::write_itest_text_response(
                        &mut stream,
                        "500 Internal Server Error",
                        &error.to_string(),
                    );
                }
            });
        }
    });
    Ok(())
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
        ("POST", "/mvp1/prekey/fetch") => {
            let value: serde_json::Value =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let response: serde_json::Value =
                router_post_json(router, "/mvp1/prekey/fetch", &value)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => ramflux_node_core::write_itest_text_response(stream, "404 Not Found", "not found")?,
    }
    Ok(())
}
