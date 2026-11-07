// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! The router's real async QUIC ingress keeps `/source` bodies byte-exact (P25 N5b).
use super::{RouterAsyncMeshPeerAuth, router_async_mesh_quic_connection_loop};
use ramflux_transport::{MeshQuicServer, MeshTlsConfig, mesh_quic_exchange_raw_frame};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE_PATH: &str = "/s9/attachments/renew/source";
const CAP: usize = 16 * 1024;

fn openssl(args: &[&str]) -> TestResult {
    if Command::new("openssl").args(args).status()?.success() {
        Ok(())
    } else {
        Err(format!("openssl {args:?}").into())
    }
}
fn s(path: &Path) -> TestResult<&str> {
    path.to_str().ok_or_else(|| "utf8 path".into())
}
fn service(root: &Path, ca_key: &Path, ca: &Path, id: &str) -> TestResult<MeshTlsConfig> {
    let dir = root.join(id);
    std::fs::create_dir_all(&dir)?;
    let (key, csr, cert, ext) =
        (dir.join("key.pem"), dir.join("req.csr"), dir.join("cert.pem"), dir.join("ext.cnf"));
    openssl(&["genpkey", "-algorithm", "ED25519", "-out", s(&key)?])?;
    openssl(&["req", "-new", "-key", s(&key)?, "-out", s(&csr)?, "-subj", &format!("/CN={id}")])?;
    std::fs::write(
        &ext,
        format!(
            "subjectAltName = DNS:{id}, DNS:localhost, URI:spiffe://node-a/{id}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
        ),
    )?;
    openssl(&[
        "x509",
        "-req",
        "-in",
        s(&csr)?,
        "-CA",
        s(ca)?,
        "-CAkey",
        s(ca_key)?,
        "-CAcreateserial",
        "-out",
        s(&cert)?,
        "-days",
        "30",
        "-extfile",
        s(&ext)?,
    ])?;
    Ok(MeshTlsConfig { ca_cert: ca.to_path_buf(), service_cert: cert, service_key: key })
}

/// The frame payload as a client writes it (the helper adds the length prefix), with the
/// body text under our control.
fn frame(body: &str) -> Vec<u8> {
    format!(r#"{{"method":"POST","path":"{SOURCE_PATH}","body":{body}}}"#).into_bytes()
}
fn string_body(n: usize) -> String {
    format!("\"{}\"", "a".repeat(n - 2))
}
/// A valid JSON object whose text is exactly `n` bytes, mostly whitespace. Decoding and
/// re-serializing it would shrink it to `{"a":1}`.
fn padded_body(n: usize) -> String {
    format!("{{\"a\":1{}}}", " ".repeat(n - 7))
}

struct Pki {
    root: PathBuf,
    ca_pem: String,
    router: MeshTlsConfig,
    federation: MeshTlsConfig,
    gateway: MeshTlsConfig,
}
impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn pki(name: &str) -> TestResult<Pki> {
    let root: PathBuf = std::env::temp_dir().join(format!(
        "rf-router-{name}-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&root)?;
    let (ca_key, ca) = (root.join("ca-key.pem"), root.join("ca.pem"));
    openssl(&["genpkey", "-algorithm", "ED25519", "-out", s(&ca_key)?])?;
    openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        s(&ca_key)?,
        "-out",
        s(&ca)?,
        "-days",
        "30",
        "-subj",
        "/CN=Ingress Test CA",
    ])?;
    Ok(Pki {
        ca_pem: std::fs::read_to_string(&ca)?,
        router: service(&root, &ca_key, &ca, "ramflux-router")?,
        federation: service(&root, &ca_key, &ca, "ramflux-federation")?,
        gateway: service(&root, &ca_key, &ca, "ramflux-gateway")?,
        root,
    })
}
fn auth() -> RouterAsyncMeshPeerAuth {
    RouterAsyncMeshPeerAuth {
        local_service_id: "ramflux-router".into(),
        allowed_service_ids: BTreeSet::from([
            "ramflux-federation".into(),
            "ramflux-gateway".into(),
        ]),
    }
}

/// The same matrix for every ingress runtime: exact cap on the received bytes, padded
/// bodies included, with the peer gate still first.
async fn assert_cap_matrix(endpoint: &str, pki: &Pki) -> TestResult {
    let send = |tls: &MeshTlsConfig, body: String| {
        let (endpoint, roots) = (endpoint.to_owned(), vec![pki.ca_pem.clone()]);
        let tls = tls.clone();
        async move {
            tokio::time::timeout(
                Duration::from_secs(15),
                mesh_quic_exchange_raw_frame(
                    &endpoint,
                    &tls,
                    "ramflux-router",
                    &roots,
                    &frame(&body),
                    Instant::now() + Duration::from_secs(10),
                ),
            )
            .await
        }
    };
    // Exactly at the cap the federation peer reaches the (unconfigured) route: 503, not 413.
    for body in [string_body(CAP), padded_body(CAP)] {
        let response = send(&pki.federation, body).await??;
        assert_eq!(response.status, 503, "{response:?}");
    }
    // One byte over: refused as received, including a whitespace-padded valid object that
    // would have normalized under the cap.
    for body in [string_body(CAP + 1), padded_body(CAP + 1)] {
        let response = send(&pki.federation, body).await??;
        assert_eq!(response.status, 413, "{response:?}");
    }
    // The peer gate still comes first for a service that may not use the route.
    let refused = send(&pki.gateway, string_body(CAP)).await??;
    assert_eq!(refused.status, 403, "{refused:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_route_cap_is_exact_on_raw_received_bytes_through_real_quic() -> TestResult {
    let pki = pki("ingress")?;
    let (state, store, db_path) = crate::router_runtime::tests::test_router("source-ingress")?;
    let router = Arc::new(crate::router_runtime::RouterHandle::tokio(state, store, None));
    let roots_pem = pki.ca_pem.clone();
    let server = MeshQuicServer::bind_with_pem_roots_provider(
        "127.0.0.1:0",
        &pki.router,
        Arc::new(move || Ok(vec![roots_pem.clone()])),
    )?;
    let endpoint = server.local_addr()?.to_string();
    let peer_auth = auth();
    let accept = tokio::spawn(async move {
        while let Ok(connection) = server.accept_connection().await {
            tokio::spawn(router_async_mesh_quic_connection_loop(
                connection,
                Arc::clone(&router),
                peer_auth.clone(),
            ));
        }
    });
    let outcome = assert_cap_matrix(&endpoint, &pki).await;
    accept.abort();
    let _ = std::fs::remove_file(&db_path);
    outcome
}

struct EnvelopeWire<'a> {
    envelope: &'a ramflux_protocol::Envelope,
    created_at: Option<i64>,
    duplicate_extension: bool,
}

impl serde::Serialize for EnvelopeWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let value = serde_json::to_value(self.envelope).map_err(serde::ser::Error::custom)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::ser::Error::custom("serialized envelope is not an object"))?;
        let mut map = serializer.serialize_map(Some(object.len()))?;
        for (key, value) in object {
            if key == "created_at" {
                map.serialize_entry(key, &self.created_at.unwrap_or(self.envelope.created_at))?;
            } else if key == "ext" && self.duplicate_extension {
                map.serialize_entry(key, &DuplicateExtension(value))?;
            } else {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()
    }
}

struct DuplicateExtension<'a>(&'a serde_json::Value);

impl serde::Serialize for DuplicateExtension<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let object = self
            .0
            .as_object()
            .ok_or_else(|| serde::ser::Error::custom("serialized extension is not an object"))?;
        let mut map = serializer.serialize_map(Some(object.len() + 1))?;
        let mut wrote_probe = false;
        for (key, value) in object {
            if key == "x_probe" {
                map.serialize_entry(key, value)?;
                map.serialize_entry(key, value)?;
                wrote_probe = true;
            } else {
                map.serialize_entry(key, value)?;
            }
        }
        if !wrote_probe {
            map.serialize_entry("x_probe", "v")?;
            map.serialize_entry("x_probe", "v")?;
        }
        map.end()
    }
}

struct AckWire {
    ack: ramflux_protocol::Ack,
    received_at: Option<i64>,
    duplicate_extension: bool,
    duplicate_ack_id: bool,
}

impl serde::Serialize for AckWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let value = serde_json::to_value(&self.ack).map_err(serde::ser::Error::custom)?;
        let object = value.as_object().ok_or_else(|| {
            serde::ser::Error::custom("serialized acknowledgement is not an object")
        })?;
        let mut map =
            serializer.serialize_map(Some(object.len() + usize::from(self.duplicate_ack_id)))?;
        for (key, value) in object {
            if key == "received_at" {
                map.serialize_entry(key, &self.received_at.unwrap_or(self.ack.received_at))?;
            } else if key == "ack_id" && self.duplicate_ack_id {
                map.serialize_entry(key, value)?;
                map.serialize_entry(key, value)?;
            } else if key == "ext" && self.duplicate_extension {
                map.serialize_entry(key, &DuplicateExtension(value))?;
            } else {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()
    }
}

struct NackWire {
    nack: ramflux_protocol::Nack,
    received_at: Option<i64>,
    duplicate_extension: bool,
}

impl serde::Serialize for NackWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let value = serde_json::to_value(&self.nack).map_err(serde::ser::Error::custom)?;
        let object = value.as_object().ok_or_else(|| {
            serde::ser::Error::custom("serialized negative acknowledgement is not an object")
        })?;
        let mut map = serializer.serialize_map(Some(object.len()))?;
        for (key, value) in object {
            if key == "received_at" {
                map.serialize_entry(key, &self.received_at.unwrap_or(self.nack.received_at))?;
            } else if key == "ext" && self.duplicate_extension {
                map.serialize_entry(key, &DuplicateExtension(value))?;
            } else {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()
    }
}

struct TargetAckWire {
    target_delivery_id: &'static str,
    ack: AckWire,
}

impl serde::Serialize for TargetAckWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("target_delivery_id", self.target_delivery_id)?;
        map.serialize_entry("ack", &self.ack)?;
        map.end()
    }
}

struct TargetNackWire {
    target_delivery_id: &'static str,
    nack: NackWire,
}

impl serde::Serialize for TargetNackWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("target_delivery_id", self.target_delivery_id)?;
        map.serialize_entry("nack", &self.nack)?;
        map.end()
    }
}

struct RouteEnvelopeWire {
    path: String,
    envelope: ramflux_protocol::Envelope,
    created_at: Option<i64>,
    duplicate_extension: bool,
}

impl serde::Serialize for RouteEnvelopeWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let envelope = EnvelopeWire {
            envelope: &self.envelope,
            created_at: self.created_at,
            duplicate_extension: self.duplicate_extension,
        };
        match self.path.as_str() {
            "/mvp0/envelope" | "/mvp1/envelope-authority" => {
                serde::Serialize::serialize(&envelope, serializer)
            }
            "/mvp0/envelope/forwarded" => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("peer_node_id", "test-peer")?;
                map.serialize_entry("envelope", &envelope)?;
                map.serialize_entry("migration_evidence", &Option::<serde_json::Value>::None)?;
                map.end()
            }
            "/mvp10/own-devices/fanout" => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("principal_id", "alice")?;
                map.serialize_entry("source_device_id", "alice_phone")?;
                map.serialize_entry("envelope", &envelope)?;
                map.end()
            }
            _ => Err(serde::ser::Error::custom("unsupported I-JSON route")),
        }
    }
}

async fn postcard_post(
    endpoint: &str,
    tls: &MeshTlsConfig,
    ca_pem: &str,
    envelope: &ramflux_protocol::Envelope,
    created_at: Option<i64>,
    duplicate_extension: bool,
) -> Result<serde_json::Value, ramflux_transport::TransportError> {
    let roots = [ca_pem.to_owned()];
    ramflux_transport::mesh_quic_post_postcard_with_peer_ca_pems_async::<_, serde_json::Value>(
        endpoint,
        "/mvp0/envelope",
        tls,
        "ramflux-router",
        &roots,
        &EnvelopeWire { envelope, created_at, duplicate_extension },
    )
    .await
}

fn json_quic_frame(path: &str, body: &[u8]) -> TestResult<Vec<u8>> {
    let path = serde_json::to_string(path)?;
    let mut frame = format!(r#"{{"method":"POST","path":{path},"body":"#).into_bytes();
    frame.extend_from_slice(body);
    frame.push(b'}');
    Ok(frame)
}

async fn json_quic_post(
    endpoint: &str,
    tls: &MeshTlsConfig,
    ca_pem: &str,
    path: &str,
    body: &[u8],
) -> Result<ramflux_transport::GatewayQuicResponse, ramflux_transport::TransportError> {
    ramflux_transport::mesh_quic_exchange_raw_frame(
        endpoint,
        tls,
        "ramflux-router",
        &[ca_pem.to_owned()],
        &json_quic_frame(path, body)
            .map_err(|error| ramflux_transport::TransportError::Http(error.to_string()))?,
        Instant::now() + Duration::from_secs(10),
    )
    .await
}

async fn mesh_tls_post<T: serde::Serialize + Send + 'static>(
    pki: &Pki,
    router: &Arc<crate::router_runtime::RouterHandle>,
    path: &str,
    peer: &str,
    client_tls: &MeshTlsConfig,
    payload: T,
) -> TestResult<(u16, Vec<u8>)> {
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &pki.router)?;
    let endpoint = server.local_addr()?.to_string();
    let worker_router = Arc::clone(router);
    let worker_peer = peer.to_owned();
    let worker = std::thread::spawn(move || -> Result<(), String> {
        let mut stream = server.accept().map_err(|error| error.to_string())?;
        let tcp = stream.sock.try_clone().map_err(|error| error.to_string())?;
        let set = ramflux_node_core::ConnectionSet::new(4);
        let guard = set
            .register(&tcp)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "mesh connection did not register".to_owned())?;
        loop {
            match crate::handlers::handle_mesh_request(
                &mut stream,
                &worker_router,
                &worker_peer,
                &guard,
            ) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    let _ = super::write_tls_transport_error(&mut stream, &error);
                    break;
                }
            }
        }
        let _ = ramflux_transport::close_mesh_server_stream(&mut stream);
        Ok(())
    });
    let client_tls = client_tls.clone();
    let endpoint_for_client = endpoint.clone();
    let path_for_client = path.to_owned();
    let task = fixture_wait(
        tokio::time::timeout(
            Duration::from_secs(15),
            tokio::task::spawn_blocking(move || {
                ramflux_transport::mesh_http_post_status_body(
                    &endpoint_for_client,
                    &path_for_client,
                    &client_tls,
                    "ramflux-router",
                    &payload,
                )
            }),
        )
        .await,
        "mesh TLS",
    )?;
    let response = task
        .map_err(|error| format!("mesh TLS task {path}: {error:?}"))?
        .map_err(|error| format!("mesh TLS client {path}: {error:?}"))?;
    worker
        .join()
        .map_err(|_| "mesh TLS server worker panicked")?
        .map_err(|error| format!("mesh TLS server {path}: {error}"))?;
    Ok(response)
}

#[cfg(feature = "itest-http")]
fn itest_http_post(
    router: &crate::router_runtime::RouterHandle,
    path: &str,
    body: &[u8],
) -> TestResult<(String, Vec<u8>)> {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let mut client = std::net::TcpStream::connect(listener.local_addr()?)?;
    let (mut server, _) = listener.accept()?;
    client.set_read_timeout(Some(Duration::from_secs(15)))?;
    server.set_read_timeout(Some(Duration::from_secs(15)))?;
    server.set_write_timeout(Some(Duration::from_secs(15)))?;
    write!(
        client,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    client.write_all(body)?;
    if let Err(error) = crate::handlers::handle_itest_request(&mut server, router) {
        ramflux_node_core::write_itest_text_response(
            &mut server,
            "500 Internal Server Error",
            &error.to_string(),
        )?;
    }
    drop(server);
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    let text = String::from_utf8(response)?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("missing HTTP body")?;
    let status = head.lines().next().ok_or("missing HTTP status")?.to_owned();
    Ok((status, body.as_bytes().to_vec()))
}

fn ack_fixture() -> ramflux_protocol::Ack {
    ramflux_protocol::Ack {
        schema: "ack.v1".into(),
        version: 1,
        domain: "ack".into(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "key".into(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "sig".into(),
        },
        ack_id: "ack-id".into(),
        envelope_id: "envelope-id".into(),
        receiver_device_id: "receiver".into(),
        received_at: 0,
        cursor_after: None,
    }
}

fn nack_fixture() -> ramflux_protocol::Nack {
    ramflux_protocol::Nack {
        schema: "nack.v1".into(),
        version: 1,
        domain: "nack".into(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "key".into(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "sig".into(),
        },
        nack_id: "nack-id".into(),
        envelope_id: "envelope-id".into(),
        receiver_device_id: "receiver".into(),
        reason: ramflux_protocol::NackReason::Expired,
        received_at: 0,
        retry_after: None,
        proof_hash: None,
        new_home_node_hint: None,
    }
}

fn fixture_wait<T>(result: Result<T, tokio::time::error::Elapsed>, fixture: &str) -> TestResult<T> {
    assert!(result.is_ok(), "{fixture} fixture timed out after 15 s");
    match result {
        Ok(value) => Ok(value),
        Err(_) => Err(format!("{fixture} fixture timed out").into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines, reason = "one named regression spans every router ingress surface")]
async fn router_ijson_ingress_refuses_unsafe_integer() -> TestResult {
    use std::time::Duration;

    const EXPECTED_BODY: &str = r#"{"error":"i_json_rejected","reason_code":"i_json_rejected"}"#;

    let pki = pki("ijson-postcard")?;
    let (state, store, db_path) = crate::router_runtime::tests::test_router("ijson-postcard")?;
    let router = Arc::new(crate::router_runtime::RouterHandle::tokio(state, store, None));
    let roots_pem = pki.ca_pem.clone();
    let server = MeshQuicServer::bind_with_pem_roots_provider(
        "127.0.0.1:0",
        &pki.router,
        Arc::new(move || Ok(vec![roots_pem.clone()])),
    )?;
    let endpoint = server.local_addr()?.to_string();
    let peer_auth = auth();
    let server_router = Arc::clone(&router);
    let accept = tokio::spawn(async move {
        while let Ok(connection) = server.accept_connection().await {
            tokio::spawn(router_async_mesh_quic_connection_loop(
                connection,
                Arc::clone(&server_router),
                peer_auth.clone(),
            ));
        }
    });

    let mut envelope = crate::router_runtime::tests::current_envelope(
        "ijson-postcard-envelope",
        "ijson-postcard-target",
    )?;
    envelope.ext.ext.insert("x_probe".into(), serde_json::json!("v"));
    let postcard_control_body = serde_json::to_vec(&EnvelopeWire {
        envelope: &envelope,
        created_at: Some(9_007_199_254_740_991),
        duplicate_extension: false,
    })?;
    assert!(ramflux_protocol::decode_signed_envelope_ijson(&postcard_control_body).is_ok());
    let postcard_control = fixture_wait(
        tokio::time::timeout(
            Duration::from_secs(15),
            postcard_post(
                &endpoint,
                &pki.gateway,
                &pki.ca_pem,
                &envelope,
                Some(9_007_199_254_740_991),
                false,
            ),
        )
        .await,
        "postcard control",
    )?;
    match postcard_control {
        Ok(value) => assert_ne!(value["error"], "i_json_rejected"),
        Err(ramflux_transport::TransportError::Http(message)) => {
            assert!(
                message.starts_with("HTTP 500:"),
                "safe integer reached the handler: {message}"
            );
            assert!(
                !message.contains("i_json_rejected"),
                "safe integer must not be refused as I-JSON"
            );
        }
        Err(error) => {
            return Err(format!("unexpected postcard control error: {error:?}").into());
        }
    }
    for (created_at, duplicate_extension) in [(Some(9_007_199_254_740_992), false), (None, true)] {
        let result = fixture_wait(
            tokio::time::timeout(
                Duration::from_secs(15),
                postcard_post(
                    &endpoint,
                    &pki.gateway,
                    &pki.ca_pem,
                    &envelope,
                    created_at,
                    duplicate_extension,
                ),
            )
            .await,
            "postcard rejection",
        )?;
        match result {
            Err(ramflux_transport::TransportError::Http(message)) => {
                assert_eq!(message, format!("HTTP 400: {EXPECTED_BODY}"));
            }
            other => {
                return Err(format!("expected exact postcard I-JSON refusal, got {other:?}").into());
            }
        }
    }
    let bridge = super::RouterSubmitBridge {
        router: Arc::clone(&router),
        tokio: tokio::runtime::Handle::current(),
    };
    for (created_at, duplicate_extension) in [(Some(9_007_199_254_740_992), false), (None, true)] {
        let body = serde_json::to_vec(&EnvelopeWire {
            envelope: &envelope,
            created_at,
            duplicate_extension,
        })?;
        let Err(error) = bridge
            .submit_raw_envelope(
                body,
                Instant::now(),
                ramflux_node_core::RouterEnvelopeOrigin::Gateway,
            )
            .await
        else {
            return Err("postcard submit bridge accepted an I-JSON refusal row".into());
        };
        assert!(error.chain().any(ramflux_protocol::is_i_json_rejection));
        assert_eq!(
            serde_json::to_vec(&ramflux_protocol::i_json_rejection_body())?,
            EXPECTED_BODY.as_bytes()
        );
    }

    let endpoint_bodies = [
        ("/mvp0/envelope", false),
        ("/mvp1/envelope-authority", true),
        ("/mvp0/envelope/forwarded", true),
        ("/mvp10/own-devices/fanout", false),
    ];
    for (path, federation_peer) in endpoint_bodies {
        let wrapped_control = serde_json::to_vec(&RouteEnvelopeWire {
            path: path.to_owned(),
            envelope: envelope.clone(),
            created_at: Some(9_007_199_254_740_991),
            duplicate_extension: false,
        })?;
        let control = fixture_wait(
            tokio::time::timeout(
                Duration::from_secs(15),
                json_quic_post(
                    &endpoint,
                    if federation_peer { &pki.federation } else { &pki.gateway },
                    &pki.ca_pem,
                    path,
                    &wrapped_control,
                ),
            )
            .await,
            "JSON QUIC control",
        )??;
        assert_ne!(control.status, 400, "safe-integer endpoint {path} must reach its handler");
        for (created_at, duplicate_extension) in
            [(Some(9_007_199_254_740_992), false), (None, true)]
        {
            let body = serde_json::to_vec(&RouteEnvelopeWire {
                path: path.to_owned(),
                envelope: envelope.clone(),
                created_at,
                duplicate_extension,
            })?;
            let response = fixture_wait(
                tokio::time::timeout(
                    Duration::from_secs(15),
                    json_quic_post(
                        &endpoint,
                        if federation_peer { &pki.federation } else { &pki.gateway },
                        &pki.ca_pem,
                        path,
                        &body,
                    ),
                )
                .await,
                "JSON QUIC refusal",
            )??;
            assert_eq!(response.status, 400, "{path}");
            assert_eq!(serde_json::to_vec(&response.body)?, EXPECTED_BODY.as_bytes(), "{path}");
        }
    }

    let mut ack = ack_fixture();
    ack.ext.ext.insert("x_probe".into(), serde_json::json!("v"));
    let mut nack = nack_fixture();
    nack.ext.ext.insert("x_probe".into(), serde_json::json!("v"));
    for (path, is_ack) in [("/mvp0/ack-bound", true), ("/mvp0/nack-bound", false)] {
        let mut cases = vec![
            (Some(9_007_199_254_740_991), false, false, false),
            (Some(9_007_199_254_740_992), false, false, true),
            (None, true, false, true),
        ];
        if is_ack {
            cases.push((None, false, true, true));
        }
        for (received_at, duplicate_extension, duplicate_ack_id, refused) in cases {
            let body = if is_ack {
                serde_json::to_vec(&TargetAckWire {
                    target_delivery_id: "target",
                    ack: AckWire {
                        ack: ack.clone(),
                        received_at,
                        duplicate_extension,
                        duplicate_ack_id,
                    },
                })?
            } else {
                serde_json::to_vec(&TargetNackWire {
                    target_delivery_id: "target",
                    nack: NackWire { nack: nack.clone(), received_at, duplicate_extension },
                })?
            };
            let response = fixture_wait(
                tokio::time::timeout(
                    Duration::from_secs(15),
                    json_quic_post(&endpoint, &pki.gateway, &pki.ca_pem, path, &body),
                )
                .await,
                "JSON QUIC ACK/NACK",
            )??;
            if refused {
                assert_eq!(response.status, 400, "JSON QUIC {path}");
                assert_eq!(serde_json::to_vec(&response.body)?, EXPECTED_BODY.as_bytes(), "{path}");
            } else {
                assert_ne!(
                    serde_json::to_vec(&response.body)?,
                    EXPECTED_BODY.as_bytes(),
                    "safe-integer control reaches JSON QUIC handler {path}"
                );
            }
        }
    }

    for (path, federation_peer) in endpoint_bodies {
        let control = RouteEnvelopeWire {
            path: path.to_owned(),
            envelope: envelope.clone(),
            created_at: Some(9_007_199_254_740_991),
            duplicate_extension: false,
        };
        let (status, body) = mesh_tls_post(
            &pki,
            &router,
            path,
            if federation_peer { "ramflux-federation" } else { "ramflux-gateway" },
            if federation_peer { &pki.federation } else { &pki.gateway },
            control,
        )
        .await?;
        assert_ne!(status, 400, "safe-integer TLS mesh endpoint {path} reaches its handler");
        assert_ne!(
            body,
            EXPECTED_BODY.as_bytes(),
            "safe control must not receive the refusal body"
        );
        for (created_at, duplicate_extension) in
            [(Some(9_007_199_254_740_992), false), (None, true)]
        {
            let (status, body) = mesh_tls_post(
                &pki,
                &router,
                path,
                if federation_peer { "ramflux-federation" } else { "ramflux-gateway" },
                if federation_peer { &pki.federation } else { &pki.gateway },
                RouteEnvelopeWire {
                    path: path.to_owned(),
                    envelope: envelope.clone(),
                    created_at,
                    duplicate_extension,
                },
            )
            .await?;
            assert_eq!(status, 400, "TLS mesh {path}");
            assert_eq!(body, EXPECTED_BODY.as_bytes(), "TLS mesh {path}");
        }
    }

    #[cfg(feature = "itest-http")]
    for path in ["/mvp0/envelope", "/mvp1/envelope-authority", "/mvp10/own-devices/fanout"] {
        let control = serde_json::to_vec(&RouteEnvelopeWire {
            path: path.to_owned(),
            envelope: envelope.clone(),
            created_at: Some(9_007_199_254_740_991),
            duplicate_extension: false,
        })?;
        let (status, body) = itest_http_post(&router, path, &control)?;
        assert_ne!(status, "HTTP/1.1 400 Bad Request", "safe control path {path}: {body:?}");
        assert!(
            !body.windows(EXPECTED_BODY.len()).any(|window| window == EXPECTED_BODY.as_bytes())
        );
        for (created_at, duplicate_extension) in
            [(Some(9_007_199_254_740_992), false), (None, true)]
        {
            let body = serde_json::to_vec(&RouteEnvelopeWire {
                path: path.to_owned(),
                envelope: envelope.clone(),
                created_at,
                duplicate_extension,
            })?;
            let (status, body) = itest_http_post(&router, path, &body)?;
            assert_eq!(status, "HTTP/1.1 400 Bad Request", "itest HTTP {path}");
            assert_eq!(body, EXPECTED_BODY.as_bytes(), "itest HTTP {path}");
        }
    }

    for (path, payload_kind) in [("/mvp0/ack-bound", "ack"), ("/mvp0/nack-bound", "nack")] {
        let mut scenarios = vec![
            (Some(9_007_199_254_740_991), false, false, false),
            (Some(9_007_199_254_740_992), false, false, true),
            (None, true, false, true),
        ];
        if payload_kind == "ack" {
            scenarios.push((None, false, true, true));
        }
        for (received_at, duplicate_extension, duplicate_ack_id, refused) in scenarios {
            if payload_kind == "ack" {
                let payload = TargetAckWire {
                    target_delivery_id: "target",
                    ack: AckWire {
                        ack: ack.clone(),
                        received_at,
                        duplicate_extension,
                        duplicate_ack_id,
                    },
                };
                let (status, body) =
                    mesh_tls_post(&pki, &router, path, "ramflux-gateway", &pki.gateway, payload)
                        .await?;
                if refused {
                    assert_eq!(status, 400, "TLS mesh {path}");
                    assert_eq!(body, EXPECTED_BODY.as_bytes(), "TLS mesh {path}");
                } else {
                    assert_ne!(body, EXPECTED_BODY.as_bytes(), "safe TLS mesh control {path}");
                }
            } else {
                let payload = TargetNackWire {
                    target_delivery_id: "target",
                    nack: NackWire { nack: nack.clone(), received_at, duplicate_extension },
                };
                let (status, body) =
                    mesh_tls_post(&pki, &router, path, "ramflux-gateway", &pki.gateway, payload)
                        .await?;
                if refused {
                    assert_eq!(status, 400, "TLS mesh {path}");
                    assert_eq!(body, EXPECTED_BODY.as_bytes(), "TLS mesh {path}");
                } else {
                    assert_ne!(body, EXPECTED_BODY.as_bytes(), "safe TLS mesh control {path}");
                }
            }
        }
    }

    #[cfg(feature = "itest-http")]
    for (path, kind) in [
        ("/mvp0/ack", "ack"),
        ("/mvp0/ack-bound", "target-ack"),
        ("/mvp0/nack", "nack"),
        ("/mvp0/nack-bound", "target-nack"),
    ] {
        let mut scenarios = vec![
            (Some(9_007_199_254_740_991), false, false, false),
            (Some(9_007_199_254_740_992), false, false, true),
            (None, true, false, true),
        ];
        if kind == "ack" || kind == "target-ack" {
            scenarios.push((None, false, true, true));
        }
        for (received_at, duplicate_extension, duplicate_ack_id, refused) in scenarios {
            let body = match kind {
                "ack" => serde_json::to_vec(&AckWire {
                    ack: ack.clone(),
                    received_at,
                    duplicate_extension,
                    duplicate_ack_id,
                })?,
                "target-ack" => serde_json::to_vec(&TargetAckWire {
                    target_delivery_id: "target",
                    ack: AckWire {
                        ack: ack.clone(),
                        received_at,
                        duplicate_extension,
                        duplicate_ack_id,
                    },
                })?,
                "nack" => serde_json::to_vec(&NackWire {
                    nack: nack.clone(),
                    received_at,
                    duplicate_extension,
                })?,
                "target-nack" => serde_json::to_vec(&TargetNackWire {
                    target_delivery_id: "target",
                    nack: NackWire { nack: nack.clone(), received_at, duplicate_extension },
                })?,
                _ => return Err("invalid acknowledgement fixture kind".into()),
            };
            let (status, response) = itest_http_post(&router, path, &body)?;
            if refused {
                assert_eq!(status, "HTTP/1.1 400 Bad Request", "itest HTTP {path}");
                assert_eq!(response, EXPECTED_BODY.as_bytes(), "itest HTTP {path}");
            } else {
                assert_ne!(response, EXPECTED_BODY.as_bytes(), "safe itest control {path}");
            }
        }
    }

    assert_eq!(
        router.state().resume("ijson-postcard-target", 0, 10),
        [],
        "I-JSON refusals must not persist an inbox delivery"
    );
    assert_eq!(router.state().resume("target", 0, 10), []);

    accept.abort();
    drop(router);
    let _ = std::fs::remove_file(db_path);
    Ok(())
}

/// The Linux compio-mesh ingress: its own listener, reactor and frame reader.
#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
#[test]
fn compio_source_route_cap_is_exact_on_raw_received_bytes_through_real_quic() -> TestResult {
    let pki = Arc::new(pki("ingress-compio")?);
    let (state, store, db_path) = crate::router_runtime::tests::test_router("source-compio")?;
    let router = Arc::new(crate::router_runtime::RouterHandle::tokio(state, store, None));
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let bridge = super::RouterSubmitBridge { router, tokio: runtime.handle().clone() };
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<Result<String, String>>();
    let server_pki = Arc::clone(&pki);
    std::thread::Builder::new().name("compio-ingress-test".into()).spawn(move || {
        let outcome = (|| -> anyhow::Result<()> {
            let reactor = compio::runtime::Runtime::new()?;
            reactor.block_on(async move {
                let server = super::bind_router_async_compio_mesh_quic_server(
                    0,
                    "127.0.0.1:0",
                    &server_pki.router,
                    1,
                )
                .await?;
                let _ = addr_tx.send(Ok(server.local_addr()?.to_string()));
                super::router_async_compio_mesh_quic_accept_loop(0, server, bridge, auth()).await;
                Ok(())
            })
        })();
        if let Err(error) = outcome {
            tracing::error!(%error, "compio ingress test reactor stopped");
        }
    })?;
    let endpoint = addr_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "the compio listener did not bind within 10 s")??;
    let outcome = runtime.block_on(assert_cap_matrix(&endpoint, &pki));
    let _ = std::fs::remove_file(&db_path);
    outcome
}
