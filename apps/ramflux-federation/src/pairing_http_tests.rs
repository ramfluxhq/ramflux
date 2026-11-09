// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Federation pairing HTTP: node-owned store over mesh, trusted-proxy TLS.
use super::*;
use crate::public_http::{FederationPublicHttpContext, handle_public_connection_with_limits};
use ramflux_node_core::pairing_relay::{
    PAIRING_CLAIM_PATH, PAIRING_CLOSE_PATH, PAIRING_POLL_PATH, PAIRING_SEND_PATH,
    PairingMeshForward, PairingRelayStore, handle_pairing_mesh,
};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::custody::pairing::PairingWire;
use ramflux_protocol::custody::pairing::native::{Create, CreateSpec, Created, Issued};
use ramflux_protocol::custody::pairing::relay::{Claim, Close, Poll, RelayFrame, Send};
use ramflux_protocol::encode_base64url;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct PairingEnv {
    _guard: MutexGuard<'static, ()>,
    previous: Option<String>,
    previous_plain: Option<String>,
}

fn pairing_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[allow(unsafe_code)]
fn enable_pairing() -> PairingEnv {
    let guard = pairing_env_lock().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = std::env::var("RAMFLUX_DEVICE_PAIRING_ENABLED").ok();
    let previous_plain = std::env::var("RAMFLUX_FEDERATION_PUBLIC_PLAIN_HTTP").ok();
    // SAFETY: `guard` is held for the whole set/restore window.
    unsafe {
        std::env::set_var("RAMFLUX_DEVICE_PAIRING_ENABLED", "1");
    }
    PairingEnv { _guard: guard, previous, previous_plain }
}

#[allow(unsafe_code)]
impl Drop for PairingEnv {
    fn drop(&mut self) {
        // SAFETY: `self._guard` is held until this drop returns.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var("RAMFLUX_DEVICE_PAIRING_ENABLED", value),
                None => std::env::remove_var("RAMFLUX_DEVICE_PAIRING_ENABLED"),
            }
            match &self.previous_plain {
                Some(value) => std::env::set_var("RAMFLUX_FEDERATION_PUBLIC_PLAIN_HTTP", value),
                None => std::env::remove_var("RAMFLUX_FEDERATION_PUBLIC_PLAIN_HTTP"),
            }
        }
    }
}

#[allow(unsafe_code)]
fn set_plain_http() {
    unsafe {
        std::env::set_var("RAMFLUX_FEDERATION_PUBLIC_PLAIN_HTTP", "1");
    }
}

struct NodeMesh {
    endpoint: String,
    store: Arc<Mutex<PairingRelayStore>>,
    client_tls: ramflux_transport::MeshTlsConfig,
    _root: crate::test_directories::TestDirectory,
}

fn node_record() -> TestResult<ramflux_crypto::custody::VerifiedNodeRecord> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let key = ramflux_crypto::fixture_signing_key();
    let body = ramflux_protocol::custody::NodeIdentityRecord {
        schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
        version: 1,
        node_id: "node".into(),
        node_signing_public_key: ramflux_protocol::encode_base64url(key.verifying_key().to_bytes()),
        client_tls_certificate_sha256: Some(encode_base64url([29; 32])),
        epoch: 1,
        previous_record_hash: None,
        issued_at: now,
        receipt_keys: vec![],
        revoked_receipt_key_ids: vec![],
        proxy_keys: vec![],
        revoked_proxy_key_ids: vec![],
        channel_binding_modes: vec![ramflux_protocol::custody::BindingMode::DirectExporter],
    };
    let record = ramflux_crypto::custody::sign_node_identity_record(&key, body)?;
    Ok(ramflux_crypto::custody::verify_node_identity_record(
        &record,
        "node",
        &ramflux_crypto::fixture_public_key_base64url(),
        now,
    )?)
}

fn spawn_node_mesh() -> TestResult<NodeMesh> {
    let root = crate::test_certificates::temp_cert_root("pairing-node-mesh")?;
    let ca = crate::test_certificates::issue_test_ca(&root)?;
    let federation =
        crate::test_certificates::issue_test_service_cert(&ca, "node-a", "ramflux-federation")?;
    let router =
        crate::test_certificates::issue_test_service_cert(&ca, "node-a", "ramflux-router")?;
    let redb = root.join("router.redb");
    let store = ramflux_node_core::RouterRedbStore::open(&redb)?;
    let router_core = ramflux_node_core::RouterCore::new();
    store.bootstrap_router(&router_core)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let service = ramflux_node_core::CustodyService::new(node_record()?, false, &store, now)?
        .with_pairing_relay_if_enabled([7; 32], "https://relay.example:443".into())?;
    let relay = service.pairing_relay().cloned().ok_or("pairing store missing")?;
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &router.tls)?;
    let endpoint = server.local_addr()?.to_string();
    let ca_pem = federation.ca_pem.clone();
    let server_tls = router.tls.clone();
    let client_tls = federation.tls.clone();
    let dispatch = Arc::clone(&relay);
    std::thread::spawn(move || {
        loop {
            let Ok(accepted) = server
                .accept_authenticated_with_pem_roots(&server_tls, std::slice::from_ref(&ca_pem))
            else {
                continue;
            };
            let mut stream = accepted.stream;
            while let Ok(Some(request)) = ramflux_transport::read_mesh_http_request(&mut stream) {
                let reply = match serde_json::from_slice::<PairingMeshForward>(&request.body) {
                    Ok(forward) => handle_pairing_mesh(&dispatch, &request.path, &forward),
                    Err(_) => ramflux_node_core::pairing_relay::PairingMeshReply {
                        status: "400 Bad Request".into(),
                        body: ramflux_node_core::pairing_relay::encode_pairing_mesh_body(
                            b"request rejected",
                        ),
                    },
                };
                if ramflux_transport::write_mesh_json_response(&mut stream, "200 OK", &reply)
                    .is_err()
                {
                    break;
                }
            }
            let _ = ramflux_transport::close_mesh_server_stream(&mut stream);
        }
    });
    Ok(NodeMesh { endpoint, store: relay, client_tls, _root: root })
}

fn public_context(
    pairing: Option<Arc<PairingHttpSurface>>,
) -> TestResult<(FederationPublicHttpContext, crate::test_directories::TestDirectory)> {
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

fn live_context(
    node: &NodeMesh,
    proxies: Vec<IpAddr>,
) -> TestResult<(FederationPublicHttpContext, crate::test_directories::TestDirectory)> {
    let root = crate::test_certificates::temp_cert_root("pairing-http-live")?;
    let admin = crate::http_listener_tests::context(&root)?;
    let router = Arc::new(RouterMeshClient {
        endpoint: node.endpoint.clone(),
        server_name: "ramflux-router".into(),
        tls: node.client_tls.clone(),
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: None,
    });
    let pairing = Arc::new(PairingHttpSurface::with_proxies(router, proxies));
    Ok((
        FederationPublicHttpContext {
            router: admin.router.clone(),
            discovery: admin.discovery.clone(),
            pairing: Some(pairing),
        },
        root,
    ))
}

fn exchange(
    raw: &[u8],
    context: FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
) -> TestResult<String> {
    exchange_at(raw, context, limits, Instant::now())
}

fn exchange_at(
    raw: &[u8],
    context: FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: Instant,
) -> TestResult<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let mut client = TcpStream::connect(addr)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        handle_public_connection_with_limits(&mut stream, &context, limits, accepted_at);
        Ok(())
    });
    client.write_all(raw)?;
    let mut response = String::new();
    client.read_to_string(&mut response)?;
    worker.join().map_err(|_| std::io::Error::other("public worker panicked"))??;
    Ok(response)
}

fn post(path: &str, body: &[u8], headers: &str) -> Vec<u8> {
    let mut raw = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body);
    raw
}

fn proxy_headers(client: &str) -> String {
    format!("X-Forwarded-Proto: https\r\nX-Forwarded-For: {client}\r\n")
}

fn localhost() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn id(tag: u8) -> String {
    let mut bytes = [0_u8; 32];
    bytes[0] = tag;
    bytes[31] = 1;
    encode_base64url(bytes)
}

fn spec(account: u8, wall: u64) -> CreateSpec {
    let account_anchor = id(account);
    CreateSpec {
        schema: "ramflux.pairing.CreateSpec.v2".into(),
        version: 2,
        account_anchor: account_anchor.clone(),
        primary_ref: DeviceRef {
            account_anchor,
            device_id: format!("device-{account}"),
            device_epoch: 1,
        },
        base_record_hash: id(2),
        base_epoch: 1,
        purpose: "enroll".into(),
        recipient_mode: "new".into(),
        destination_ref: None,
        capabilities: vec!["message".into()],
        lease_not_before: wall,
        lease_expires_at: wall + 86_400,
        data_selection: vec![],
        ttl_seconds: 300,
    }
}

fn wall() -> TestResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn native_create(store: &Mutex<PairingRelayStore>, account: u8) -> TestResult<Created> {
    let wall = wall()?;
    let mut store = store.lock().map_err(|_| "pairing lock")?;
    let issued: Issued = store.issue(spec(account, wall))?;
    Ok(store.create(Create {
        schema: "ramflux.pairing.Create.v2".into(),
        version: 2,
        ticket: issued.ticket,
        spec: spec(account, wall),
    })?)
}

fn claim_body(created: &Created, nonce: u8) -> TestResult<Vec<u8>> {
    Ok(Claim {
        schema: "ramflux.pairing.Claim.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        recipient_token: created.recipient_token.clone(),
        claim_nonce: id(nonce),
    }
    .to_wire_bytes()?)
}

#[test]
fn pairing_routes_are_absent_when_capability_is_off() -> TestResult {
    let (context, root) = public_context(None)?;
    let limits = crate::http_limits::defaults(true);
    let response = exchange(&post(PAIRING_CLAIM_PATH, b"{}", ""), context.clone(), limits)?;
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    let health = exchange(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n", context, limits)?;
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    drop(root);
    Ok(())
}

#[test]
fn pairing_header_and_body_caps_at_limit_and_one_over() -> TestResult {
    let _env = enable_pairing();
    let node = spawn_node_mesh()?;
    let (context, root) = live_context(&node, vec![localhost()])?;
    let ordinary = crate::http_limits::defaults(true);
    let pairing = pairing_limits();
    let limit_body = vec![b'a'; pairing.max_body_bytes];
    let at_limit = exchange(
        &post(PAIRING_CLAIM_PATH, &limit_body, &proxy_headers("203.0.113.10")),
        context.clone(),
        ordinary,
    )?;
    assert!(at_limit.starts_with("HTTP/1.1 400"), "{at_limit}");
    let mut over = format!(
        "POST {PAIRING_CLAIM_PATH} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        pairing.max_body_bytes + 1
    )
    .into_bytes();
    over.extend(std::iter::repeat_n(b'b', pairing.max_body_bytes + 1));
    let over_body = exchange(&over, context.clone(), ordinary)?;
    assert!(over_body.starts_with("HTTP/1.1 413"), "{over_body}");
    let mut header = format!("POST {PAIRING_CLAIM_PATH} HTTP/1.1\r\nX-Padding: ").into_bytes();
    header.resize(pairing.max_header_bytes + 1, b'x');
    let over_header = exchange(&header, context.clone(), ordinary)?;
    assert!(over_header.starts_with("HTTP/1.1 413"), "{over_header}");
    let health = exchange(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n", context, ordinary)?;
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    drop(root);
    Ok(())
}

#[test]
fn pairing_plain_from_non_proxy_is_refused() -> TestResult {
    let dummy = crate::test_certificates::temp_cert_root("pairing-plain")?;
    let admin = crate::http_listener_tests::context(&dummy)?;
    let pairing = Arc::new(PairingHttpSurface::with_proxies(admin.router.clone(), Vec::new()));
    let (context, root) = public_context(Some(pairing))?;
    let response = exchange(
        &post(PAIRING_CLAIM_PATH, b"{}", &proxy_headers("203.0.113.9")),
        context,
        crate::http_limits::defaults(true),
    )?;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(response.contains("tls required"), "{response}");
    drop(root);
    drop(dummy);
    Ok(())
}

#[test]
fn pairing_plain_http_env_does_not_disable_tls_refusal() -> TestResult {
    let _env = enable_pairing();
    set_plain_http();
    let dummy = crate::test_certificates::temp_cert_root("pairing-plain-env")?;
    let admin = crate::http_listener_tests::context(&dummy)?;
    let pairing = Arc::new(PairingHttpSurface::with_proxies(admin.router.clone(), Vec::new()));
    let (context, root) = public_context(Some(pairing))?;
    let response = exchange(
        &post(PAIRING_CLAIM_PATH, b"{}", ""),
        context,
        crate::http_limits::defaults(true),
    )?;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(response.contains("tls required"), "{response}");
    drop(root);
    drop(dummy);
    Ok(())
}

#[test]
fn pairing_untrusted_peer_forwarded_headers_are_ignored() -> TestResult {
    let dummy = crate::test_certificates::temp_cert_root("pairing-untrusted")?;
    let admin = crate::http_listener_tests::context(&dummy)?;
    let allowlist = vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))];
    let pairing = Arc::new(PairingHttpSurface::with_proxies(admin.router.clone(), allowlist));
    let (context, root) = public_context(Some(pairing))?;
    let response = exchange(
        &post(PAIRING_CLAIM_PATH, b"{}", &proxy_headers("203.0.113.9")),
        context,
        crate::http_limits::defaults(true),
    )?;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(response.contains("tls required"), "{response}");
    drop(root);
    drop(dummy);
    Ok(())
}

#[test]
fn pairing_healthz_keeps_ordinary_deadline_when_pairing_is_on() -> TestResult {
    let dummy = crate::test_certificates::temp_cert_root("pairing-healthz")?;
    let admin = crate::http_listener_tests::context(&dummy)?;
    let pairing = Arc::new(PairingHttpSurface::with_proxies(admin.router.clone(), Vec::new()));
    let (context, root) = public_context(Some(pairing))?;
    let accepted_at = Instant::now().checked_sub(Duration::from_secs(6)).ok_or("accepted_at")?;
    let health = exchange_at(
        b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n",
        context,
        crate::http_limits::defaults(true),
        accepted_at,
    )?;
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    drop(root);
    drop(dummy);
    Ok(())
}

#[test]
fn pairing_http_forwards_to_node_owned_store_end_to_end() -> TestResult {
    let _env = enable_pairing();
    let node = spawn_node_mesh()?;
    let created = native_create(&node.store, 1)?;
    let (context, root) = live_context(&node, vec![localhost()])?;
    let ordinary = crate::http_limits::defaults(true);
    let headers = proxy_headers("203.0.113.10");
    let claimed = exchange(
        &post(PAIRING_CLAIM_PATH, &claim_body(&created, 9)?, &headers),
        context.clone(),
        ordinary,
    )?;
    assert!(claimed.starts_with("HTTP/1.1 200"), "{claimed}");
    let relay_send = Send {
        schema: "ramflux.pairing.Send.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "responder".into(),
        token: created.recipient_token.clone(),
        seq: 0,
        frame: RelayFrame::Confirm {
            role: "responder".into(),
            transcript_hash: encode_base64url([1; 32]),
            mac: encode_base64url([2; 32]),
        },
    };
    let send_reply = exchange(
        &post(PAIRING_SEND_PATH, &relay_send.to_wire_bytes()?, &headers),
        context.clone(),
        ordinary,
    )?;
    assert!(send_reply.starts_with("HTTP/1.1 200"), "{send_reply}");
    let poll = Poll {
        schema: "ramflux.pairing.Poll.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "initiator".into(),
        token: created.primary_token.clone(),
        after_seq: None,
    };
    let polled = exchange(
        &post(PAIRING_POLL_PATH, &poll.to_wire_bytes()?, &headers),
        context.clone(),
        ordinary,
    )?;
    assert!(polled.starts_with("HTTP/1.1 200"), "{polled}");
    let close = Close {
        schema: "ramflux.pairing.Close.v2".into(),
        version: 2,
        invitation_id: created.invitation.body.invitation_id.clone(),
        issuer_seq: created.invitation.body.issuer_seq,
        role: "initiator".into(),
        token: created.primary_token.clone(),
        reason: "done".into(),
    };
    let closed =
        exchange(&post(PAIRING_CLOSE_PATH, &close.to_wire_bytes()?, &headers), context, ordinary)?;
    assert!(closed.starts_with("HTTP/1.1 200"), "{closed}");
    drop(root);
    Ok(())
}

#[test]
fn pairing_trusted_proxy_https_uses_forwarded_client_for_claim_budget() -> TestResult {
    let _env = enable_pairing();
    let node = spawn_node_mesh()?;
    let (context, root) = live_context(&node, vec![localhost()])?;
    let ordinary = crate::http_limits::defaults(true);
    let headers = proxy_headers("203.0.113.10");
    for account in 1_u8..=4 {
        let created = native_create(&node.store, account)?;
        let claimed = exchange(
            &post(PAIRING_CLAIM_PATH, &claim_body(&created, account)?, &headers),
            context.clone(),
            ordinary,
        )?;
        assert!(claimed.starts_with("HTTP/1.1 200"), "{claimed}");
    }
    let created = native_create(&node.store, 5)?;
    let busy = exchange(
        &post(PAIRING_CLAIM_PATH, &claim_body(&created, 5)?, &headers),
        context.clone(),
        ordinary,
    )?;
    assert!(busy.starts_with("HTTP/1.1 200"), "{busy}");
    assert!(busy.contains("Busy"), "{busy}");
    let other = proxy_headers("198.51.100.9");
    let created = native_create(&node.store, 6)?;
    let allowed =
        exchange(&post(PAIRING_CLAIM_PATH, &claim_body(&created, 6)?, &other), context, ordinary)?;
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    drop(root);
    Ok(())
}
