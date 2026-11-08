// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::admin_http::{FederationAdminHttpContext, handle_admin_request};
use crate::public_http::{FederationPublicHttpContext, handle_public_request};
use crate::public_source_limits::{PublicSourceLimitConfig, PublicSourceLimits};
use crate::test_certificates::{issue_test_ca, issue_test_service_cert, temp_cert_root};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request(
    method: &str,
    path: &str,
    body: &str,
    handler: impl FnOnce(&mut TcpStream) -> Result<(), ramflux_node_core::NodeCoreError>
    + Send
    + 'static,
) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    let worker =
        std::thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            if let Err(error) = handler(&mut stream) {
                ramflux_node_core::write_itest_text_response(
                    &mut stream,
                    "500 Internal Server Error",
                    &error.to_string(),
                )?;
            }
            Ok(())
        });
    write!(
        client,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut response = String::new();
    client.read_to_string(&mut response)?;
    worker.join().map_err(|_| "worker panicked")?.map_err(|error| error.to_string())?;
    Ok(response)
}

fn federation_forward_body(created_at: &str, ext_members: &str, admin_token: &str) -> String {
    format!(
        r#"{{"admin_token":"{admin_token}","source_node_id":"node-b","target_node_id":"node-a","delivery_class":"opaque_event","required_capability":"opaque_delivery","signing_key_id":"node-b","signature_alg":"ed25519","signature":"sig","envelope":{{"schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1","ext":{{{ext_members}}},"signing_key_id":"device","signature_alg":"ed25519","signature":"sig","envelope_id":"federated-forward","source_principal_id":"alice","source_device_id":"phone","target_delivery_id":"peer","routing_set_id":null,"delivery_class":"opaque_event","priority":"normal","ttl":3600,"created_at":{created_at},"encrypted_payload":"opaque","payload_hash":"hash"}}}}"#
    )
}

fn assert_http_response(response: &str, status: &str, body: Option<&[u8]>) -> TestResult {
    let (headers, actual_body) = response.split_once("\r\n\r\n").ok_or("missing HTTP body")?;
    assert!(headers.starts_with(&format!("HTTP/1.1 {status}\r\n")), "{response}");
    if let Some(body) = body {
        assert_eq!(actual_body.as_bytes(), body);
    }
    Ok(())
}

pub(super) fn context(
    root: &std::path::Path,
) -> Result<FederationAdminHttpContext, Box<dyn std::error::Error>> {
    let seed = [7; 32];
    Ok(FederationAdminHttpContext {
        store: Arc::new(ramflux_node_core::FederationRedbStore::open(root.join("state.redb"))?),
        state: Arc::new(crate::SharedFederationTrustState::new(
            ramflux_node_core::FederationTrustState::new(),
        )),
        router: Arc::new(crate::RouterMeshClient {
            endpoint: "127.0.0.1:1".into(),
            server_name: "ramflux-router".into(),
            tls: ramflux_transport::MeshTlsConfig {
                ca_cert: root.join("ca.pem"),
                service_cert: root.join("client.pem"),
                service_key: root.join("key.pem"),
            },
            client: ramflux_transport::MeshHttpClient::new(),
            async_mesh: None,
        }),
        discovery: crate::FederationDiscoverySurface {
            node_id: "node-a".into(),
            public_endpoint: "localhost:7443".into(),
            node_public_key: ramflux_crypto::public_key_base64url_from_seed(seed),
            node_ca_cert_pem: "test-ca".into(),
            node_signing_seed: seed,
            protocol_versions: vec!["v1".into()],
            transport_backends: vec!["https_json".into()],
            node_capabilities: vec!["opaque_delivery".into()],
            attachment_authority: None,
        },
        mesh_observability: Arc::new(crate::FederationMeshObservability::default()),
        admin_token: Some("secret".into()),
    })
}

#[test]
fn migration_local_rpc_returns_one_bounded_response_for_valid_and_malformed_bodies() -> TestResult {
    let root = temp_cert_root("migration-local-response")?;
    let admin = context(&root)?;
    let valid = serde_json::to_string(&ramflux_node_core::LocalMigrationRequest {
        admin_token: "secret".into(),
        budget_ms: 1000,
        action: ramflux_node_core::LocalMigrationAction::PeerKey { node_id: "node-b".into() },
    })?;
    for production in [false, true] {
        for (body, expected) in [("{", "500 Internal Server Error"), (valid.as_str(), "200 OK")] {
            let context = admin.clone();
            let response =
                request("POST", ramflux_node_core::MIGRATION_LOCAL_PATH, body, move |stream| {
                    let limits = crate::http_limits::defaults(false);
                    let accepted_at = std::time::Instant::now();
                    if production {
                        crate::admin_http::handle_admin_connection_with_limits(
                            stream,
                            &context,
                            limits,
                            accepted_at,
                        );
                    } else if let Err(error) = handle_admin_request(stream, &context) {
                        crate::http_response::HttpResponse::text(
                            "500 Internal Server Error",
                            &error.to_string(),
                        )
                        .write_admin(stream, limits, accepted_at)?;
                    }
                    Ok(())
                })?;
            assert!(response.starts_with(&format!("HTTP/1.1 {expected}\r\n")), "{response}");
            assert_eq!(response.matches("HTTP/1.1 ").count(), 1, "one response per RPC");
            let (header, payload) =
                response.split_once("\r\n\r\n").ok_or("missing response body")?;
            let declared: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .ok_or("missing response length")?
                .parse()?;
            assert_eq!(declared, payload.len(), "no second response or trailing bytes");
            assert!(response.len() < 1024, "small RPC returns a bounded response");
            if body == valid {
                let reply: ramflux_node_core::LocalMigrationReply = serde_json::from_str(payload)?;
                assert!(matches!(
                    reply,
                    ramflux_node_core::LocalMigrationReply::Refused {
                        reason: ramflux_protocol::home_migration::Refusal::PeeringUnavailable
                    }
                ));
            }
        }
    }
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn federation_ijson_ingress_refuses_unsafe_integer() -> TestResult {
    const EXPECTED_BODY: &[u8] = br#"{"error":"i_json_rejected","reason_code":"i_json_rejected"}"#;
    let root = temp_cert_root("federation-ijson-admin")?;
    let context = context(&root)?;

    for (path, wrap_forward) in
        [("/s8/federation/forward", false), ("/internal/home-node-migration/forward", true)]
    {
        let make_body = |created_at: &str, ext: &str, token: &str| {
            let forward = federation_forward_body(created_at, ext, token);
            if wrap_forward {
                format!(r#"{{"admin_token":"{token}","forward":{forward}}}"#)
            } else {
                forward
            }
        };
        for (created_at, ext, rejected) in [
            ("9007199254740991", r#""x_probe":"v","x_probe":"v""#, true),
            ("9007199254740992", r#""x_probe":"v""#, true),
            ("9007199254740991", r#""x_probe":"v""#, false),
        ] {
            let body = make_body(created_at, ext, "secret");
            let request_context = context.clone();
            let response = request("POST", path, &body, move |stream| {
                crate::admin_http::handle_admin_connection_with_limits(
                    stream,
                    &request_context,
                    crate::http_limits::defaults(false),
                    std::time::Instant::now(),
                );
                Ok(())
            })?;
            if rejected {
                assert_http_response(&response, "400 Bad Request", Some(EXPECTED_BODY))?;
            } else {
                assert_http_response(&response, "500 Internal Server Error", None)?;
                assert!(!response.ends_with(std::str::from_utf8(EXPECTED_BODY)?));
            }
        }

        let unauthenticated = make_body("9007199254740991", r#""x_probe":"v""#, "wrong");
        let request_context = context.clone();
        let response = request("POST", path, &unauthenticated, move |stream| {
            crate::admin_http::handle_admin_connection_with_limits(
                stream,
                &request_context,
                crate::http_limits::defaults(false),
                std::time::Instant::now(),
            );
            Ok(())
        })?;
        assert_http_response(&response, "500 Internal Server Error", None)?;
        assert!(!response.ends_with(std::str::from_utf8(EXPECTED_BODY)?));
    }

    drop(context);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn public_listener_has_no_admin_routes_even_with_valid_token() -> TestResult {
    let root = temp_cert_root("http-boundary")?;
    let mut admin = context(&root)?;
    admin.discovery.node_capabilities.push(ramflux_node_core::HOME_MIGRATION_CAPABILITY.into());
    let public = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    for path in [
        "/s8/federation/forward",
        "/internal/home-node-migration/forward",
        ramflux_node_core::MIGRATION_LOCAL_PATH,
        ramflux_node_core::MIGRATION_PEER_PATH,
        "/s8/federation/mesh-observability",
        "/admin/federation/peer",
        "/admin/federation/discover",
    ] {
        for method in ["GET", "POST"] {
            let context = public.clone();
            let response = request(method, path, r#"{"admin_token":"secret"}"#, move |s| {
                handle_public_request(s, &context)
            })?;
            assert!(response.starts_with("HTTP/1.1 404"), "{method} {path}: {response}");
        }
    }
    for path in [
        "/.well-known/ramflux/client",
        "/.well-known/ramflux/server",
        "/mvp1/prekey/root",
        "/mvp1/device-manifest/root",
    ] {
        let context = admin.clone();
        assert!(
            request("GET", path, "", move |s| handle_admin_request(s, &context))?
                .starts_with("HTTP/1.1 404")
        );
    }
    let context = admin.clone();
    assert!(
        request("POST", "/mvp1/prekey/fetch", "{}", move |s| handle_admin_request(s, &context))?
            .starts_with("HTTP/1.1 404")
    );
    let context = admin.clone();
    assert!(
        request(
            "POST",
            "/s8/federation/mesh-observability",
            r#"{"admin_token":"secret"}"#,
            move |s| handle_admin_request(s, &context)
        )?
        .starts_with("HTTP/1.1 200")
    );
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn public_discovery_and_router_client_reads_preserve_payloads() -> TestResult {
    let root = temp_cert_root("http-client")?;
    let ca = issue_test_ca(&root)?;
    let router_cert = issue_test_service_cert(&ca, "node-a", "ramflux-router")?;
    let client_cert = issue_test_service_cert(&ca, "node-a", "ramflux-federation")?;
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &router_cert.tls)?;
    let mut admin = context(&root)?;
    Arc::make_mut(&mut admin.router).endpoint = server.local_addr()?.to_string();
    Arc::make_mut(&mut admin.router).tls = client_cert.tls;
    let public = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    let worker =
        std::thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            // The mesh client can reuse a TLS connection across requests.
            let mut stream = server.accept()?;
            for (method, path) in
                [("GET", "/mvp1/prekey/root"), ("GET", "/mvp1/device-manifest/root")]
            {
                let request = ramflux_transport::read_mesh_http_request(&mut stream)?
                    .ok_or("missing request")?;
                assert_eq!((request.method.as_str(), request.path.as_str()), (method, path));
                ramflux_transport::write_mesh_json_response(
                    &mut stream,
                    "200 OK",
                    &serde_json::json!({"path":path,"unchanged":true}),
                )?;
            }
            Ok(())
        });
    for (method, path) in [("GET", "/mvp1/prekey/root"), ("GET", "/mvp1/device-manifest/root")] {
        let context = public.clone();
        let response = request(method, path, "{}", move |s| handle_public_request(s, &context))?;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let body: serde_json::Value = serde_json::from_str(
            response.split_once("\r\n\r\n").ok_or("missing response body")?.1,
        )?;
        assert_eq!(body, serde_json::json!({"path":path,"unchanged":true}));
    }
    worker.join().map_err(|_| "worker panicked")?.map_err(|error| error.to_string())?;
    for path in ["/healthz", "/.well-known/ramflux/client", "/.well-known/ramflux/server"] {
        let context = public.clone();
        let response = request("GET", path, "", move |s| handle_public_request(s, &context))?;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        if path.ends_with("/server") {
            let record = serde_json::from_str(
                response.split_once("\r\n\r\n").ok_or("missing response body")?.1,
            )?;
            ramflux_node_core::verify_federation_server_record(
                &record,
                crate::now_unix_seconds()?,
            )?;
        }
    }
    drop(public);
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn internal_home_node_forward_authenticates_and_reaches_peer_mesh() -> TestResult {
    let root = temp_cert_root("http-forward")?;
    let ca = issue_test_ca(&root)?;
    let router_cert = issue_test_service_cert(&ca, "node-a", "ramflux-router")?;
    let local = issue_test_service_cert(&ca, "node-a", "ramflux-federation")?;
    let peer_cert = issue_test_service_cert(&ca, "node-b", "ramflux-federation")?;
    let router = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &router_cert.tls)?;
    let peer = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &peer_cert.tls)?;
    let mut admin = context(&root)?;
    Arc::make_mut(&mut admin.router).endpoint = router.local_addr()?.to_string();
    Arc::make_mut(&mut admin.router).tls = local.tls;
    let mut peer_discovery = admin.discovery.clone();
    peer_discovery.node_id = "node-b".into();
    peer_discovery.public_endpoint = peer.local_addr()?.to_string();
    peer_discovery.node_ca_cert_pem = peer_cert.ca_pem;
    admit_peer(&admin, &peer_discovery)?;
    let envelope = forward_envelope()?;
    let router_worker =
        std::thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut stream = router.accept()?;
            let request =
                ramflux_transport::read_mesh_http_request(&mut stream)?.ok_or("missing request")?;
            assert_eq!(request.path, "/mvp1/envelope-authority");
            let body: serde_json::Value = serde_json::from_slice(&request.body)?;
            ramflux_transport::write_mesh_json_response(&mut stream, "200 OK", &body)?;
            Ok(())
        });
    let peer_worker = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut stream = peer.accept()?;
            let request =
                ramflux_transport::read_mesh_http_request(&mut stream)?.ok_or("missing request")?;
            assert_eq!(request.path, "/s8/federation/envelope");
            let forward: ramflux_node_core::FederatedEnvelopeForwardRequest =
                serde_json::from_slice(&request.body)?;
            assert_eq!(forward.source_node_id, "node-a");
            assert_ne!(forward.signed.signature, "");
            ramflux_transport::write_mesh_json_response(
                &mut stream,
                "200 OK",
                &serde_json::json!({
                    "accepted":true,"source_node_id":"node-a","target_node_id":"node-b",
                    "delivery":{"outcome":"accepted","target_delivery_id":"peer","inbox_seq":1,"cursor":null,"nack":null}
                }),
            )?;
            Ok(())
        },
    );
    let body = serde_json::json!({"admin_token":"secret", "forward":envelope}).to_string();
    let context = admin.clone();
    let response = request("POST", "/internal/home-node-migration/forward", &body, move |s| {
        handle_admin_request(s, &context)
    })?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("\"accepted\":true"), "{response}");
    router_worker.join().map_err(|_| "worker panicked")?.map_err(|error| error.to_string())?;
    peer_worker.join().map_err(|_| "worker panicked")?.map_err(|error| error.to_string())?;
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn admit_peer(
    admin: &FederationAdminHttpContext,
    peer: &crate::FederationDiscoverySurface,
) -> TestResult {
    let record = peer.well_known_record()?;
    let now = crate::now_unix_seconds()?;
    admin.state.update_and_save(&admin.store, |state| {
        state.resolve_discovery_result(
            &ramflux_node_core::FederationDiscoveryRequest {
                node_id: peer.node_id.clone(),
                now,
                invite_endpoint: None,
                well_known_url: Some("http://localhost/.well-known/ramflux/server".into()),
                dns_srv_records: vec![],
                address_records: vec![],
                directory_endpoint: None,
            },
            Some(&record),
            None,
        )?;
        state.admit_verified_discovered_peer(
            ramflux_node_core::FederationPeerRoute {
                node_id: peer.node_id.clone(),
                endpoint: peer.public_endpoint.clone(),
                node_public_key_hash: ramflux_crypto::blake3_256_base64url(
                    ramflux_protocol::domain::FEDERATION_HANDSHAKE,
                    peer.node_public_key.as_bytes(),
                ),
                node_capabilities: peer.node_capabilities.clone(),
                trust_status: ramflux_node_core::FederationTrustStatus::Invited,
                updated_at: now,
                expires_at: now + 3600,
                route_update_proof_hash: "test".into(),
            },
            &peer.node_capabilities,
            &peer.node_capabilities,
        )?;
        Ok(())
    })?;
    Ok(())
}

fn forward_envelope() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(serde_json::from_value::<
        ramflux_node_core::FederatedEnvelopeForwardRequest,
    >(serde_json::json!({
        "signing_key_id":"node-a","signature_alg":"ed25519","signature":"",
        "source_node_id":"node-a", "target_node_id":"node-b", "delivery_class":"opaque_event", "required_capability":"opaque_delivery",
        "envelope": {"schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1","ext":{},
        "signing_key_id":"device","signature_alg":"ed25519","signature":"device-signature",
        "envelope_id":"forward-test","source_principal_id":"alice","source_device_id":"first","target_delivery_id":"peer",
        "routing_set_id":null,"delivery_class":"opaque_event","priority":"normal","ttl":600,"created_at":crate::now_unix_seconds()?,"encrypted_payload":"opaque","payload_hash":"hash"}
    }))?)?)
}

#[test]
fn public_failures_hide_internal_details_and_unsupported_post_is_not_proxied() -> TestResult {
    let root = temp_cert_root("http-public-error")?;
    let admin = context(&root)?;
    let public = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    let context = public.clone();
    let response = request("GET", "/mvp1/prekey/root", "", move |stream| {
        crate::public_http::handle_public_connection(stream, &context);
        Ok(())
    })?;
    assert!(response.starts_with("HTTP/1.1 500"), "{response}");
    assert_eq!(response.split_once("\r\n\r\n").ok_or("missing body")?.1, "internal server error");
    let response = request("POST", "/mvp1/prekey/fetch", "{}", move |stream| {
        handle_public_request(stream, &public)
    })?;
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn public_connection_limit_rejects_excess_and_releases_after_success_and_error() -> TestResult {
    let root = temp_cert_root("http-cap")?;
    let admin = context(&root)?;
    let public = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    let active = ramflux_node_core::ConnectionSet::new(1);
    let source_limits = PublicSourceLimits::new(PublicSourceLimitConfig::for_test(2, 16, 32));
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut first = TcpStream::connect(listener.local_addr()?)?;
    let (stream, _) = listener.accept()?;
    let worker = crate::http_connections::spawn_public_test_connection(
        stream,
        public.clone(),
        active.clone(),
        crate::http_limits::defaults(true),
        &source_limits,
    )
    .ok_or("first connection rejected")?;
    assert_eq!(active.len(), 1);
    let mut excess = TcpStream::connect(listener.local_addr()?)?;
    excess.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (stream, _) = listener.accept()?;
    assert!(
        crate::http_connections::spawn_public_test_connection(
            stream,
            public.clone(),
            active.clone(),
            crate::http_limits::defaults(true),
            &source_limits
        )
        .is_none()
    );
    let mut response = String::new();
    excess.read_to_string(&mut response)?;
    assert!(response.is_empty(), "capacity must close the newcomer");
    assert_eq!(active.len(), 1);
    // The global-cap refusal must drop the source permit it acquired before admission.
    let probe = source_limits
        .acquire_connection(listener.local_addr()?.ip(), std::time::Instant::now())
        .map_err(|error| format!("source slot leaked after global refusal: {error:?}"))?;
    assert!(
        source_limits
            .acquire_connection(listener.local_addr()?.ip(), std::time::Instant::now())
            .is_err()
    );
    drop(probe);
    first.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    worker.join()?;
    first.read_to_string(&mut String::new())?;
    assert_eq!(active.len(), 0);
    let mut failed = TcpStream::connect(listener.local_addr()?)?;
    let (stream, _) = listener.accept()?;
    let worker = crate::http_connections::spawn_public_test_connection(
        stream,
        public,
        active.clone(),
        crate::http_limits::defaults(true),
        &source_limits,
    )
    .ok_or("slot not released")?;
    failed.write_all(b"GET /mvp1/prekey/root HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    worker.join()?;
    failed.read_to_string(&mut String::new())?;
    assert_eq!(active.len(), 0);
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn public_request_rate_limit_returns_generic_429_and_ignores_forwarding_headers() -> TestResult {
    let root = temp_cert_root("http-source-rate")?;
    let admin = context(&root)?;
    let public = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    let active = ramflux_node_core::ConnectionSet::new(8);
    let source_limits = PublicSourceLimits::new(
        PublicSourceLimitConfig::for_test(1, 16, 32).with_request_rate(1, 1),
    );
    let listener = TcpListener::bind("127.0.0.1:0")?;

    let mut first = TcpStream::connect(listener.local_addr()?)?;
    first.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (stream, _) = listener.accept()?;
    let worker = crate::http_connections::spawn_public_test_connection(
        stream,
        public.clone(),
        active.clone(),
        crate::http_limits::defaults(true),
        &source_limits,
    )
    .ok_or("first request refused")?;

    let mut excess = TcpStream::connect(listener.local_addr()?)?;
    excess.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (stream, _) = listener.accept()?;
    assert!(
        crate::http_connections::spawn_public_test_connection(
            stream,
            public.clone(),
            active.clone(),
            crate::http_limits::defaults(true),
            &source_limits,
        )
        .is_none()
    );
    let mut refusal = String::new();
    excess.read_to_string(&mut refusal)?;
    assert!(refusal.starts_with("HTTP/1.1 503"), "{refusal}");
    assert_eq!(
        refusal.split_once("\r\n\r\n").ok_or("missing response body")?.1,
        "service unavailable"
    );

    first.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    let mut response = String::new();
    first.read_to_string(&mut response)?;
    worker.join()?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let mut second = TcpStream::connect(listener.local_addr()?)?;
    second.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (stream, _) = listener.accept()?;
    let worker = crate::http_connections::spawn_public_test_connection(
        stream,
        public,
        active,
        crate::http_limits::defaults(true),
        &source_limits,
    )
    .ok_or("rate-limited connection rejected before request")?;
    second.write_all(
        b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.99\r\n\r\n",
    )?;
    response.clear();
    second.read_to_string(&mut response)?;
    worker.join()?;
    assert!(response.starts_with("HTTP/1.1 429"), "{response}");
    assert_eq!(
        response.split_once("\r\n\r\n").ok_or("missing response body")?.1,
        "too many requests"
    );

    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn source_slot_releases_after_error_and_timeout_and_full_idle_table_admits() -> TestResult {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    let root = temp_cert_root("http-source-release")?;
    let admin = context(&root)?;
    let public = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    let active = ramflux_node_core::ConnectionSet::new(8);
    let source_limits = PublicSourceLimits::new(PublicSourceLimitConfig::for_test(1, 16, 4));
    let limits = ramflux_node_core::HttpRequestLimits {
        request_timeout: Duration::from_millis(100),
        ..crate::http_limits::defaults(true)
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;

    let mut malformed = TcpStream::connect(listener.local_addr()?)?;
    malformed.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (stream, _) = listener.accept()?;
    let worker = crate::http_connections::spawn_public_test_connection(
        stream,
        public.clone(),
        active.clone(),
        limits,
        &source_limits,
    )
    .ok_or("malformed request connection refused")?;
    malformed.write_all(b"GET /healthz HTTP/1.1\r\nContent-Length: -1\r\n\r\n")?;
    worker.join()?;
    let mut response = String::new();
    malformed.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    let mut trickler = TcpStream::connect(listener.local_addr()?)?;
    trickler.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (stream, _) = listener.accept()?;
    let worker = crate::http_connections::spawn_public_test_connection(
        stream,
        public.clone(),
        active.clone(),
        limits,
        &source_limits,
    )
    .ok_or("source slot not released after request error")?;
    trickler.write_all(b"G")?;
    worker.join()?;
    response.clear();
    trickler.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 408"), "{response}");

    let now = Instant::now();
    for third in 1..=8_u8 {
        let source = IpAddr::V4(Ipv4Addr::new(198, 51, third, 1));
        drop(source_limits.acquire_connection(source, now).map_err(|error| format!("{error:?}"))?);
    }
    assert_eq!(source_limits.tracked_sources(), 4);

    let mut healthy = TcpStream::connect(listener.local_addr()?)?;
    healthy.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (stream, _) = listener.accept()?;
    let worker = crate::http_connections::spawn_public_test_connection(
        stream,
        public,
        active,
        limits,
        &source_limits,
    )
    .ok_or("full idle table refused a new real source")?;
    healthy.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    worker.join()?;
    response.clear();
    healthy.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn disabled_source_limits_allow_same_source_until_global_cap() -> TestResult {
    let root = temp_cert_root("http-source-disabled")?;
    let admin = context(&root)?;
    let public = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    let active = ramflux_node_core::ConnectionSet::new(2);
    let source_limits = PublicSourceLimits::new(
        PublicSourceLimitConfig::for_test(1, 1, 2).with_request_rate(1, 1).disabled(),
    );
    let limits = ramflux_node_core::HttpRequestLimits {
        request_timeout: Duration::from_millis(100),
        ..crate::http_limits::defaults(true)
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut workers = Vec::new();
    let mut clients = Vec::new();
    for _ in 0..2 {
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        let (stream, _) = listener.accept()?;
        let worker = crate::http_connections::spawn_public_test_connection(
            stream,
            public.clone(),
            active.clone(),
            limits,
            &source_limits,
        )
        .ok_or("disabled source limits refused a same-source connection")?;
        client.write_all(b"G")?;
        workers.push(worker);
        clients.push(client);
    }

    let mut refused = TcpStream::connect(listener.local_addr()?)?;
    refused.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (stream, _) = listener.accept()?;
    assert!(
        crate::http_connections::spawn_public_test_connection(
            stream,
            public.clone(),
            active.clone(),
            limits,
            &source_limits,
        )
        .is_none()
    );
    let mut response = String::new();
    refused.read_to_string(&mut response)?;
    assert!(response.is_empty(), "capacity must close the newcomer");

    for worker in workers {
        worker.join()?;
    }
    let mut healthy = TcpStream::connect(listener.local_addr()?)?;
    healthy.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (stream, _) = listener.accept()?;
    let worker = crate::http_connections::spawn_public_test_connection(
        stream,
        public,
        active,
        limits,
        &source_limits,
    )
    .ok_or("global slot was not released")?;
    healthy.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    response.clear();
    healthy.read_to_string(&mut response)?;
    worker.join()?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    drop(clients);
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn occupied_admin_address_reports_listener_and_address() -> TestResult {
    let root = temp_cert_root("admin-bind-error")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    let error = crate::admin_http::serve_admin_http(&addr, context(&root)?)
        .err()
        .ok_or("occupied bind accepted")?
        .to_string();
    assert!(error.contains("federation admin HTTP bind failed"), "{error}");
    assert!(error.contains(&addr), "{error}");
    std::fs::remove_dir_all(root)?;
    Ok(())
}
