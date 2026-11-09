// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-free pairing HTTPS routes. No admin token or ordinary session is consulted.
use ramflux_node_core::pairing_relay::{
    PairingHttpResponse, PairingRelayConfig, PairingRelayStore, handle_pairing_http,
    is_pairing_path,
};
use ramflux_node_core::{HttpRequestLimits, NodeHttpRequest};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::http_response::HttpResponse;

pub(crate) struct PairingHttpSurface {
    pub(crate) store: Arc<Mutex<PairingRelayStore>>,
    pub(crate) allow_plain_http: bool,
}

impl PairingHttpSurface {
    pub(crate) fn open(
        node_seed: [u8; 32],
        public_origin: String,
        allow_plain_http: bool,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let store = PairingRelayStore::new(PairingRelayConfig {
            clock: Arc::new(ramflux_node_core::pairing_relay::NodePairingClock::system()),
            node_seed,
            public_origin,
        })
        .map_err(|error| ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()))?;
        Ok(Self { store: Arc::new(Mutex::new(store)), allow_plain_http })
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
    source: IpAddr,
    request: &NodeHttpRequest,
    tls: bool,
) -> HttpResponse {
    if !tls && !surface.allow_plain_http {
        return HttpResponse::text("400 Bad Request", "tls required");
    }
    let reply = handle_pairing_http(
        &surface.store,
        source,
        request.method.as_str(),
        request.path.as_str(),
        &request.body,
    );
    to_http(reply)
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

pub(crate) fn allow_plain_http() -> bool {
    ramflux_node_core::environment::var("RAMFLUX_FEDERATION_PUBLIC_PLAIN_HTTP").as_deref()
        == Ok("1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_http::{FederationPublicHttpContext, handle_public_connection_with_limits};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn exchange(
        raw: &[u8],
        context: FederationPublicHttpContext,
        limits: ramflux_node_core::HttpRequestLimits,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        let worker = std::thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            handle_public_connection_with_limits(&mut stream, &context, limits, Instant::now());
            Ok(())
        });
        client.write_all(raw)?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        worker.join().map_err(|_| std::io::Error::other("public worker panicked"))??;
        Ok(response)
    }

    fn public_context(
        pairing: Option<Arc<PairingHttpSurface>>,
    ) -> Result<
        (FederationPublicHttpContext, crate::test_directories::TestDirectory),
        Box<dyn std::error::Error>,
    > {
        let root = crate::test_certificates::temp_cert_root("pairing-http")?;
        let admin = crate::http_listener_tests::context(&root)?;
        Ok((
            FederationPublicHttpContext {
                router: admin.router.clone(),
                discovery: admin.discovery.clone(),
                pairing,
            },
            root,
        ))
    }

    fn surface() -> Result<Arc<PairingHttpSurface>, Box<dyn std::error::Error>> {
        Ok(Arc::new(PairingHttpSurface::open([7; 32], "https://relay.example:443".into(), true)?))
    }

    #[test]
    fn pairing_routes_are_absent_when_capability_is_off() -> TestResult {
        let (context, root) = public_context(None)?;
        let limits = crate::http_limits::defaults(true);
        let response = exchange(
            b"POST /client/pairing/v1/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
            context.clone(),
            limits,
        )?;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
        let health =
            exchange(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n", context, limits)?;
        assert!(health.starts_with("HTTP/1.1 200"), "{health}");
        drop(root);
        Ok(())
    }

    #[test]
    fn pairing_header_and_body_caps_at_limit_and_one_over() -> TestResult {
        let (context, root) = public_context(Some(surface()?))?;
        let ordinary = crate::http_limits::defaults(true);
        let pairing = pairing_limits();
        let limit_body = vec![b'a'; pairing.max_body_bytes];
        let mut at = format!(
            "POST /client/pairing/v1/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            limit_body.len()
        )
        .into_bytes();
        at.extend_from_slice(&limit_body);
        let at_limit = exchange(&at, context.clone(), ordinary)?;
        assert!(
            at_limit.starts_with("HTTP/1.1 400") || at_limit.starts_with("HTTP/1.1 200"),
            "{at_limit}"
        );
        let mut over = format!(
            "POST /client/pairing/v1/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            pairing.max_body_bytes + 1
        )
        .into_bytes();
        over.extend(std::iter::repeat_n(b'b', pairing.max_body_bytes + 1));
        let over_body = exchange(&over, context.clone(), ordinary)?;
        assert!(over_body.starts_with("HTTP/1.1 413"), "{over_body}");
        let mut header = b"POST /client/pairing/v1/claim HTTP/1.1\r\nX-Padding: ".to_vec();
        header.resize(pairing.max_header_bytes + 1, b'x');
        let over_header = exchange(&header, context.clone(), ordinary)?;
        assert!(over_header.starts_with("HTTP/1.1 413"), "{over_header}");
        let health =
            exchange(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n", context, ordinary)?;
        assert!(health.starts_with("HTTP/1.1 200"), "{health}");
        drop(root);
        Ok(())
    }
}
