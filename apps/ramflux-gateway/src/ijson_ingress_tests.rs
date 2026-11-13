// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::collections::VecDeque;
use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};

const EXPECTED_HTTP_BODY: &[u8] = br#"{"error":"i_json_rejected","reason_code":"i_json_rejected"}"#;
const EXPECTED_SESSION_NACK: &[u8] = br#"{"frame_type":"nack","reason":"gateway_request_invalid"}"#;

#[derive(Clone, Copy)]
enum Row {
    Envelope,
    Ack,
    Nack,
    OwnDeviceFanout,
}

impl Row {
    const ALL: [Self; 4] = [Self::Envelope, Self::Ack, Self::Nack, Self::OwnDeviceFanout];

    const fn path(self) -> &'static str {
        match self {
            Self::Envelope => "/mvp0/envelope",
            Self::Ack => "/mvp0/ack",
            Self::Nack => "/mvp0/nack",
            Self::OwnDeviceFanout => "/mvp10/own-devices/fanout",
        }
    }

    fn body(self, timestamp: i64) -> anyhow::Result<Vec<u8>> {
        let envelope = envelope(timestamp)?;
        let value = match self {
            Self::Envelope => serde_json::to_value(envelope)?,
            Self::Ack => serde_json::to_value(ack(timestamp)?)?,
            Self::Nack => serde_json::to_value(nack(timestamp)?)?,
            Self::OwnDeviceFanout => serde_json::json!({
                "principal_id":"principal",
                "source_device_id":"source-device",
                "envelope":envelope,
            }),
        };
        Ok(serde_json::to_vec(&value)?)
    }

    fn timestamp_key(self) -> &'static str {
        match self {
            Self::Ack | Self::Nack => "received_at",
            Self::Envelope | Self::OwnDeviceFanout => "created_at",
        }
    }
}

fn envelope(timestamp: i64) -> anyhow::Result<ramflux_protocol::Envelope> {
    let mut envelope: ramflux_protocol::Envelope = serde_json::from_value(serde_json::json!({
        "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
        "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
        "envelope_id":"ijson-envelope","source_principal_id":"principal",
        "source_device_id":"source-device","target_delivery_id":"target",
        "delivery_class":"opaque_event","priority":"normal","ttl":300,
        "created_at":timestamp,"encrypted_payload":"opaque","payload_hash":"opaque-hash",
        "ext":{"x_probe":"v"}
    }))?;
    envelope.created_at = timestamp;
    Ok(envelope)
}

fn ack(timestamp: i64) -> anyhow::Result<ramflux_protocol::Ack> {
    Ok(serde_json::from_value(serde_json::json!({
        "schema":"ramflux.ack.v1","version":1,"domain":"ramflux.ack.v1",
        "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
        "ack_id":"ijson-ack","envelope_id":"ijson-envelope",
        "receiver_device_id":"receiver","received_at":timestamp,
        "ext":{"x_probe":"v","inbox_seq":1}
    }))?)
}

fn nack(timestamp: i64) -> anyhow::Result<ramflux_protocol::Nack> {
    Ok(serde_json::from_value(serde_json::json!({
        "schema":"ramflux.nack.v1","version":1,"domain":"ramflux.nack.v1",
        "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
        "nack_id":"ijson-nack","envelope_id":"ijson-envelope",
        "receiver_device_id":"receiver","reason":"expired","received_at":timestamp,
        "ext":{"x_probe":"v","inbox_seq":1}
    }))?)
}

fn with_duplicate_extension(body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let text = String::from_utf8(body)?;
    let duplicate = text.replacen(r#""x_probe":"v""#, r#""x_probe":"v","x_probe":"v""#, 1);
    anyhow::ensure!(duplicate != text, "fixture extension was not found");
    Ok(duplicate.into_bytes())
}

fn with_timestamp(row: Row, body: Vec<u8>, timestamp: i64) -> anyhow::Result<Vec<u8>> {
    let text = String::from_utf8(body)?;
    let field = row.timestamp_key();
    let marker = format!("\"{field}\":42");
    let replacement = format!("\"{field}\":{timestamp}");
    let updated = text.replacen(&marker, &replacement, 1);
    anyhow::ensure!(updated != text, "fixture timestamp was not found");
    Ok(updated.into_bytes())
}

struct FakeRouter {
    client: crate::RouterMeshClient,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    wake: SocketAddr,
    exited: std::sync::mpsc::Receiver<Result<(), String>>,
    task: std::thread::JoinHandle<()>,
    cert_root: ramflux_test_support::TestPath,
}

impl FakeRouter {
    /// Stops the blocking accept loop and waits at most 10 s for the router thread to exit.
    fn finish(self) -> anyhow::Result<()> {
        self.stop.store(true, Ordering::Release);
        // A blocking accept returns only for a connection, so wake it after raising the flag.
        let _ = TcpStream::connect(self.wake);
        let result = self
            .exited
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| anyhow::anyhow!("fake router did not stop within 10 s"))?;
        self.task.join().map_err(|_| anyhow::anyhow!("fake router thread panicked"))?;
        result.map_err(anyhow::Error::msg)?;
        std::fs::remove_dir_all(&self.cert_root)?;
        Ok(())
    }
}

fn fake_router() -> anyhow::Result<FakeRouter> {
    let cert_root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "ramflux-gateway-ijson-router-{}",
            ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8])
        ));
    std::fs::create_dir(&cert_root)?;
    let certificate = rcgen::generate_simple_self_signed(vec![
        "ramflux-router".into(),
        "ramflux-gateway".into(),
    ])?;
    let cert_pem = certificate.cert.pem();
    let key_pem = certificate.signing_key.serialize_pem();
    let router_tls = ramflux_transport::MeshTlsConfig {
        ca_cert: cert_root.join("ca.pem"),
        service_cert: cert_root.join("router.pem"),
        service_key: cert_root.join("router-key.pem"),
    };
    let client_tls = ramflux_transport::MeshTlsConfig {
        ca_cert: router_tls.ca_cert.clone(),
        service_cert: cert_root.join("gateway.pem"),
        service_key: cert_root.join("gateway-key.pem"),
    };
    std::fs::write(&router_tls.ca_cert, &cert_pem)?;
    std::fs::write(&router_tls.service_cert, &cert_pem)?;
    std::fs::write(&router_tls.service_key, &key_pem)?;
    std::fs::write(&client_tls.service_cert, &cert_pem)?;
    std::fs::write(&client_tls.service_key, &key_pem)?;
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &router_tls)?;
    let wake = server.local_addr()?;
    let endpoint = wake.to_string();
    let client = crate::RouterMeshClient {
        endpoint,
        server_name: "ramflux-router".into(),
        tls: client_tls,
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: None,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = Arc::clone(&calls);
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let gateway_ca = cert_pem;
    let server_tls = router_tls.clone();
    let (exited_tx, exited) = std::sync::mpsc::channel();
    let task = std::thread::spawn(move || {
        let result = (|| -> Result<(), String> {
            while !server_stop.load(Ordering::Acquire) {
                // Blocking accept: the stop path wakes it with a connection and then exits.
                if let Ok(mut accepted) = server.accept_authenticated_with_pem_roots(
                    &server_tls,
                    std::slice::from_ref(&gateway_ca),
                ) {
                    // The stop wake-up connection is not a router request.
                    if server_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let request = ramflux_transport::read_mesh_http_request(&mut accepted.stream)
                        .map_err(|error| error.to_string())?
                        .ok_or("missing gateway request")?;
                    server_calls.fetch_add(1, Ordering::AcqRel);
                    let response = match request.path.as_str() {
                        "/mvp0/envelope" => serde_json::json!({
                            "outcome":"accepted","target_delivery_id":"target",
                            "inbox_seq":null,"cursor":null
                        }),
                        "/mvp0/ack" => serde_json::json!({"reason":"ack_backpressure_retry"}),
                        "/mvp0/nack" => serde_json::json!({
                            "target_delivery_id":"target","inbox_seq":0,
                            "last_envelope_id":null,"acked_envelope_ids":[],"nacked_envelope_ids":{}
                        }),
                        "/mvp10/own-devices/fanout" => serde_json::json!({
                            "principal_id":"principal","source_device_id":"source-device","delivered":[]
                        }),
                        path => return Err(format!("unexpected gateway route {path}")),
                    };
                    ramflux_transport::write_mesh_json_response(
                        &mut accepted.stream,
                        "200 OK",
                        &response,
                    )
                    .map_err(|error| error.to_string())?;
                    ramflux_transport::close_mesh_server_stream(&mut accepted.stream)
                        .map_err(|error| error.to_string())?;
                }
            }
            Ok(())
        })();
        let _ = exited_tx.send(result);
    });
    Ok(FakeRouter { client, calls, stop, wake, exited, task, cert_root })
}

fn http_request(
    router: &crate::RouterMeshClient,
    path: &str,
    body: Vec<u8>,
) -> anyhow::Result<(String, Vec<u8>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    client.set_read_timeout(Some(Duration::from_secs(15)))?;
    let (mut server, _) = listener.accept()?;
    let request = ramflux_node_core::NodeHttpRequest {
        method: "POST".into(),
        path: path.into(),
        body,
        keep_alive: false,
        source_ip_hash: None,
        pre_auth_cookie: None,
        pre_auth_now: None,
        forwarded_proto: None,
        forwarded_for: None,
    };
    crate::itest_http::dispatch_protected_itest_request(
        &mut server,
        router,
        &request,
        "ramflux-gateway",
    )?;
    drop(server);
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    let text = String::from_utf8(response)?;
    let (headers, body) =
        text.split_once("\r\n\r\n").ok_or_else(|| anyhow::anyhow!("missing HTTP body"))?;
    let status =
        headers.lines().next().ok_or_else(|| anyhow::anyhow!("missing HTTP status"))?.to_owned();
    Ok((status, body.as_bytes().to_vec()))
}

fn http_rows_refuse_before_router(
    router: &crate::RouterMeshClient,
    calls: &AtomicUsize,
) -> anyhow::Result<()> {
    for row in Row::ALL {
        let baseline = calls.load(Ordering::Acquire);
        let nested = with_duplicate_extension(row.body(42)?)?;
        let (status, body) = http_request(router, row.path(), nested)?;
        assert_eq!(
            calls.load(Ordering::Acquire),
            baseline,
            "router call on {} duplicate",
            row.path()
        );
        assert_eq!(status, "HTTP/1.1 400 Bad Request", "nested duplicate at {}", row.path());
        assert_eq!(body, EXPECTED_HTTP_BODY, "nested duplicate at {}", row.path());

        let unsafe_integer = with_timestamp(row, row.body(42)?, 9_007_199_254_740_992)?;
        let (status, body) = http_request(router, row.path(), unsafe_integer)?;
        assert_eq!(
            calls.load(Ordering::Acquire),
            baseline,
            "router call on {} unsafe integer",
            row.path()
        );
        assert_eq!(status, "HTTP/1.1 400 Bad Request", "unsafe integer at {}", row.path());
        assert_eq!(body, EXPECTED_HTTP_BODY, "unsafe integer at {}", row.path());

        let control = with_timestamp(row, row.body(42)?, 9_007_199_254_740_991)?;
        let (status, body) = http_request(router, row.path(), control)?;
        assert_eq!(status, "HTTP/1.1 200 OK", "safe endpoint at {}", row.path());
        assert!(!body.windows(b"i_json_rejected".len()).any(|window| window == b"i_json_rejected"));
        assert_eq!(
            calls.load(Ordering::Acquire),
            baseline + 1,
            "safe endpoint did not reach router at {}",
            row.path()
        );
    }
    Ok(())
}

fn session_frame(timestamp: i64) -> anyhow::Result<Vec<u8>> {
    let runtime = crate::session::submit_fixtures::test_runtime()?;
    let mut submit = crate::session::submit_fixtures::signed_submit(&runtime, 42)?;
    submit.envelope.created_at = timestamp;
    submit.envelope.ext.ext.insert("x_probe".into(), serde_json::json!("v"));
    Ok(serde_json::to_vec(&ramflux_node_core::GatewayClientFrame::Submit { submit })?)
}

/// Gateway context whose router is the counting fake, so every refusal can be checked for zero calls.
fn context_with_router(
    router: &crate::RouterMeshClient,
) -> anyhow::Result<(ramflux_test_support::TestPath, crate::GatewayQuicContext)> {
    let (_fixture_directory_0, fixture_value_0) = crate::session::tests::test_gateway_context()?;
    let mut context = fixture_value_0;
    context.router = router.clone();
    Ok((_fixture_directory_0, context))
}

fn open_frame() -> anyhow::Result<ramflux_node_core::GatewayOpenFrame> {
    Ok(serde_json::from_value(serde_json::json!({
        "protocol_version":ramflux_node_core::GATEWAY_SESSION_PROTOCOL_VERSION,"transport_kind":"quic_quinn","client_instance_id":"client","device_id":"device","target_delivery_id":"target","stream_nonce":"nonce","previous_session_id":null,"resume_token_hash":null,"last_seen_inbox_seq":null,"max_inflight_downstream":4,"max_inflight_upstream":4,"pre_auth_cookie":null,"pre_auth_now":null,"source_ip_hash":null
    }))?)
}

/// Auth frame whose nested `device_epoch` token is supplied verbatim, so the fixture can carry
/// a duplicate key or an unsafe integer.
fn auth_frame_bytes(device_epoch: &str) -> Vec<u8> {
    format!(
        r#"{{"frame_type":"auth","auth":{{"signed_request":{{"schema":"ramflux.signed_request.v1","version":1,"domain":"ramflux.signed_request.v1","ext":{{}},"signing_key_id":"device","signature_alg":"ed25519","signature":"unused","source_device_id":"device","request_id":"auth","method":"POST","path":"/gateway/session/auth","device_proof_hash":"unused","body_hash":"unused","nonce":"nonce","created_at":1,"expires_at":2}},"device_proof":{{"schema":"ramflux.device_proof.v1","version":1,"domain":"ramflux.device_proof.v1","ext":{{}},"signing_key_id":"device","signature_alg":"ed25519","signature":"unused","principal_id":"alice","device_id":"device","device_epoch":{device_epoch},"branch_proof_hash":"unused","capability_scope":["gateway.session"],"nonce":"nonce","expires_at":2}}}}}}"#
    )
    .into_bytes()
}

type Future<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;

struct QueueSource(VecDeque<Vec<u8>>);

impl GatewaySessionFrameSource for QueueSource {
    fn recv_frame(&mut self) -> Future<'_, Vec<u8>> {
        let next = self.0.pop_front();
        Box::pin(async move {
            next.ok_or_else(|| {
                TransportError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            })
        })
    }
}

struct RecordingSink(Arc<Mutex<Vec<Vec<u8>>>>);

impl GatewaySessionFrameSink for RecordingSink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }

    fn send_frame<'a>(&'a mut self, body: &'a [u8]) -> Future<'a, ()> {
        Box::pin(async move {
            self.0.lock().map_err(|_| TransportError::LockPoisoned)?.push(body.to_vec());
            Ok(())
        })
    }
}

/// Auth frames after a valid Open: the I-JSON refusal must write the exact Nack and end the
/// session cleanly, with no router call. The 2^53-1 control must pass I-JSON and reach auth
/// source admission, which refuses it without router IO because the fixture has no source root.
async fn auth_frame_rows_refuse_i_json(
    router: &crate::RouterMeshClient,
    calls: &AtomicUsize,
) -> anyhow::Result<()> {
    let refused = [
        ("nested duplicate device_epoch", auth_frame_bytes("1,\"device_epoch\":1")),
        ("unsafe integer device_epoch", auth_frame_bytes("9007199254740992")),
    ];
    for (label, body) in refused {
        let baseline = calls.load(Ordering::Acquire);
        let frames = Arc::new(Mutex::new(Vec::new()));
        // Assert on the Nack before propagating the session result, so a regressed fix fails on
        // the exact-Nack assertion rather than on the propagated I-JSON error.
        let (_context_directory, context) = context_with_router(router)?;
        let outcome = crate::session::handle_gateway_session_transport(
            Box::new(RecordingSink(Arc::clone(&frames))),
            Box::new(QueueSource(VecDeque::from([body]))),
            context,
            ramflux_node_core::GatewayClientFrame::Open { open: open_frame()? },
        )
        .await;
        let frames = frames.lock().map_err(|_| anyhow::anyhow!("frame mutex"))?;
        assert_eq!(frames.len(), 1, "{label}: exactly one Nack frame expected");
        assert_eq!(frames[0], EXPECTED_SESSION_NACK, "{label}: exact I-JSON Nack expected");
        assert_eq!(calls.load(Ordering::Acquire), baseline, "{label}: router call");
        outcome?;
    }

    let baseline = calls.load(Ordering::Acquire);
    let frames = Arc::new(Mutex::new(Vec::new()));
    let (_context_directory, context) = context_with_router(router)?;
    crate::session::handle_gateway_session_transport(
        Box::new(RecordingSink(Arc::clone(&frames))),
        Box::new(QueueSource(VecDeque::from([auth_frame_bytes("9007199254740991")]))),
        context,
        ramflux_node_core::GatewayClientFrame::Open { open: open_frame()? },
    )
    .await?;
    let frames = frames.lock().map_err(|_| anyhow::anyhow!("frame mutex"))?;
    assert_eq!(frames.len(), 1, "safe auth control: exactly one Nack frame expected");
    assert_eq!(
        serde_json::from_slice::<ramflux_node_core::GatewayServerFrame>(&frames[0])?,
        ramflux_node_core::GatewayServerFrame::Nack {
            reason: "gateway_auth_source_rejected".into()
        },
        "safe auth control must reach auth source admission"
    );
    assert_eq!(calls.load(Ordering::Acquire), baseline, "safe auth control router call");
    Ok(())
}

async fn tcp_session_frames_refuse_i_json(
    router: &crate::RouterMeshClient,
    calls: &AtomicUsize,
) -> anyhow::Result<()> {
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "ramflux-gateway-ijson-session-{}",
            ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8])
        ));
    std::fs::create_dir(&root)?;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: root.join("ca.pem"),
        service_cert: root.join("public.pem"),
        service_key: root.join("public.key"),
    };
    std::fs::write(&tls.ca_cert, cert.cert.pem())?;
    std::fs::write(&tls.service_cert, cert.cert.pem())?;
    std::fs::write(&tls.service_key, cert.signing_key.serialize_pem())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (_context_directory, context) = context_with_router(router)?;
    let listener_context = crate::serve::GatewayListenerContext {
        custody: context.custody,
        node_id: context.node_id,
        gateway_id: context.gateway_id,
        peers: context.peers,
        router: context.router,
        notify: context.notify,
        #[cfg(feature = "itest-local-mint")]
        relay_service_key: context.relay_service_key,
        state: context.state,
        store: context.store,
        hub: context.hub,
    };
    let task = tokio::spawn(crate::serve::serve_gateway_tcp_listener(
        listener,
        ramflux_transport::tcp_gateway_server_config(&tls)?,
        listener_context,
    ));
    for (body, refused) in [
        (with_duplicate_extension(session_frame(42)?)?, true),
        (session_frame(9_007_199_254_740_992)?, true),
        (session_frame(9_007_199_254_740_991)?, false),
    ] {
        let baseline = calls.load(Ordering::Acquire);
        let (_, mut stream) = ramflux_transport::TcpTlsGatewayClient::connect(
            "127.0.0.1:0".parse()?,
            address,
            "localhost",
            &tls.ca_cert,
            Duration::from_secs(15),
        )
        .await?;
        ramflux_transport::GatewaySessionFrameSink::send_frame(&mut stream, &body).await?;
        let received = tokio::time::timeout(
            Duration::from_secs(15),
            ramflux_transport::GatewaySessionFrameSource::recv_frame(&mut stream),
        )
        .await;
        assert!(received.is_ok(), "gateway TCP session fixture timed out after 15 s");
        // Read the Nack before the connection can close; a closed stream then fails the exact-Nack
        // assertion below rather than surfacing as a bare TLS error.
        let frame = match received {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => format!("stream closed without a frame: {error}").into_bytes(),
            Err(_elapsed) => Vec::new(),
        };
        assert_eq!(calls.load(Ordering::Acquire), baseline, "router call on session frame");
        if refused {
            assert_eq!(
                frame, EXPECTED_SESSION_NACK,
                "refused session frame must receive the exact Nack"
            );
        } else {
            assert_ne!(frame, EXPECTED_SESSION_NACK, "safe frame must pass initial I-JSON decode");
            let response: ramflux_node_core::GatewayServerFrame = serde_json::from_slice(&frame)?;
            anyhow::ensure!(
                matches!(response, ramflux_node_core::GatewayServerFrame::Nack { reason } if reason == ramflux_protocol::GATEWAY_FIRST_FRAME_NACK_REASON),
                "safe Submit frame should reach first-frame handling"
            );
        }
    }
    task.abort();
    let _ = task.await;
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[tokio::test]
async fn gateway_ijson_ingress_refuses_unsafe_integer() -> anyhow::Result<()> {
    let fake = fake_router()?;
    let router = fake.client.clone();
    let calls = Arc::clone(&fake.calls);
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        let http_router = router.clone();
        let http_calls = Arc::clone(&calls);
        tokio::task::spawn_blocking(move || {
            http_rows_refuse_before_router(&http_router, &http_calls)
        })
        .await
        .map_err(|error| anyhow::anyhow!("HTTP fixture panicked: {error}"))??;
        auth_frame_rows_refuse_i_json(&router, &calls).await?;
        tcp_session_frames_refuse_i_json(&router, &calls).await?;
        Ok::<(), anyhow::Error>(())
    })
    .await;
    // Always stop the fake router, even when a fixture failed, so no thread outlives the test.
    let stopped = fake.finish();
    assert!(outcome.is_ok(), "gateway I-JSON fixtures timed out after 30 s");
    outcome.map_err(anyhow::Error::from)??;
    stopped?;
    Ok(())
}
