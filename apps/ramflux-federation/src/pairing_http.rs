// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-free pairing HTTPS routes. Federation forwards to the node-owned store.
use ramflux_node_core::pairing_relay::{
    PairingHttpResponse, PairingMeshForward, PairingMeshReply, encode_pairing_mesh_body,
    is_pairing_path, pairing_client_addr, pairing_request_is_tls, pairing_status_line,
    trusted_proxies_from_env,
};
use ramflux_node_core::{HttpRequestLimits, NodeHttpRequest};
use std::net::IpAddr;
use std::sync::Arc;

use crate::http_response::HttpResponse;
use crate::{RouterMeshClient, router_post_json};

pub(crate) struct PairingHttpSurface {
    pub(crate) router: Arc<RouterMeshClient>,
    pub(crate) trusted_proxies: Vec<IpAddr>,
}

impl PairingHttpSurface {
    /// # Errors
    /// Rejects a malformed trusted-proxy allowlist.
    pub(crate) fn open(
        router: Arc<RouterMeshClient>,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        Ok(Self { router, trusted_proxies: trusted_proxies_from_env()? })
    }

    /// Production assembly: capability gate then the node-forwarding surface.
    /// # Errors
    /// Rejects a malformed trusted-proxy allowlist or pairing opt-in.
    pub(crate) fn open_if_enabled(
        router: Arc<RouterMeshClient>,
    ) -> Result<Option<Arc<Self>>, ramflux_node_core::NodeCoreError> {
        if !ramflux_node_core::device_pairing_enabled()? {
            return Ok(None);
        }
        Ok(Some(Arc::new(Self::open(router)?)))
    }

    #[cfg(test)]
    pub(crate) fn with_proxies(
        router: Arc<RouterMeshClient>,
        trusted_proxies: Vec<IpAddr>,
    ) -> Self {
        Self { router, trusted_proxies }
    }
}

pub(crate) fn pairing_limits() -> HttpRequestLimits {
    ramflux_node_core::pairing_relay::pairing_http_limits()
}

pub(crate) fn pairing_route(method: &str, path: &str) -> bool {
    let _ = method;
    is_pairing_path(path)
}

pub(crate) fn respond(
    surface: &PairingHttpSurface,
    peer: IpAddr,
    request: &NodeHttpRequest,
    listener_is_tls: bool,
) -> HttpResponse {
    let forwarded_proto = request.forwarded_proto.as_deref();
    let forwarded_for = request.forwarded_for.as_deref();
    if !pairing_request_is_tls(listener_is_tls, peer, &surface.trusted_proxies, forwarded_proto) {
        return HttpResponse::text("400 Bad Request", "tls required");
    }
    let source = match pairing_client_addr(peer, &surface.trusted_proxies, forwarded_for) {
        Ok(source) => source,
        Err(reason) => return HttpResponse::text("400 Bad Request", reason),
    };
    let forward = PairingMeshForward {
        body: encode_pairing_mesh_body(&request.body),
        source: source.to_string(),
    };
    match router_post_json::<PairingMeshForward, PairingMeshReply>(
        surface.router.as_ref(),
        request.path.as_str(),
        &forward,
    ) {
        Ok(reply) => match ramflux_protocol::decode_base64url(&reply.body) {
            Ok(body) => {
                to_http(PairingHttpResponse { status: pairing_status_line(&reply.status), body })
            }
            Err(_) => HttpResponse::text("502 Bad Gateway", "request rejected"),
        },
        Err(_) => HttpResponse::text("502 Bad Gateway", "request rejected"),
    }
}

fn to_http(reply: PairingHttpResponse) -> HttpResponse {
    if reply.status == "200 OK" {
        HttpResponse::raw_json(reply.status, reply.body)
    } else {
        HttpResponse::text(
            reply.status,
            std::str::from_utf8(&reply.body).unwrap_or("request rejected"),
        )
    }
}

#[cfg(test)]
#[path = "pairing_continuity_tests.rs"]
mod continuity_tests;
#[cfg(test)]
#[path = "pairing_http_tests.rs"]
mod tests;
