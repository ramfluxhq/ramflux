// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

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
        "ext":{"x_probe":"v"}
    }))?)
}

fn nack(timestamp: i64) -> anyhow::Result<ramflux_protocol::Nack> {
    Ok(serde_json::from_value(serde_json::json!({
        "schema":"ramflux.nack.v1","version":1,"domain":"ramflux.nack.v1",
        "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
        "nack_id":"ijson-nack","envelope_id":"ijson-envelope",
        "receiver_device_id":"receiver","reason":"expired","received_at":timestamp,
        "ext":{"x_probe":"v"}
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
    task: std::thread::JoinHandle<Result<(), String>>,
    cert_root: std::path::PathBuf,
}

fn fake_router() -> anyhow::Result<FakeRouter> {
    let cert_root = std::env::temp_dir().join(format!(
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
    server.set_nonblocking(true)?;
    let endpoint = server.local_addr()?.to_string();
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
    let task = std::thread::spawn(move || -> Result<(), String> {
        while !server_stop.load(Ordering::Acquire) {
            match server
                .accept_authenticated_with_pem_roots(&server_tls, std::slice::from_ref(&gateway_ca))
            {
                Ok(mut accepted) => {
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
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        Ok(())
    });
    Ok(FakeRouter { client, calls, stop, task, cert_root })
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
    };
    crate::itest_http::dispatch_protected_itest_request(&mut server, router, &request)?;
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

fn http_rows_refuse_before_router() -> anyhow::Result<()> {
    let fake = fake_router()?;
    for row in Row::ALL {
        let baseline = fake.calls.load(Ordering::Acquire);
        let nested = with_duplicate_extension(row.body(42)?)?;
        let (status, body) = http_request(&fake.client, row.path(), nested)?;
        assert_eq!(
            fake.calls.load(Ordering::Acquire),
            baseline,
            "router call on {} duplicate",
            row.path()
        );
        assert_eq!(status, "HTTP/1.1 400 Bad Request", "nested duplicate at {}", row.path());
        assert_eq!(body, EXPECTED_HTTP_BODY, "nested duplicate at {}", row.path());

        let unsafe_integer = with_timestamp(row, row.body(42)?, 9_007_199_254_740_992)?;
        let (status, body) = http_request(&fake.client, row.path(), unsafe_integer)?;
        assert_eq!(
            fake.calls.load(Ordering::Acquire),
            baseline,
            "router call on {} unsafe integer",
            row.path()
        );
        assert_eq!(status, "HTTP/1.1 400 Bad Request", "unsafe integer at {}", row.path());
        assert_eq!(body, EXPECTED_HTTP_BODY, "unsafe integer at {}", row.path());

        let control = with_timestamp(row, row.body(42)?, 9_007_199_254_740_991)?;
        let (status, body) = http_request(&fake.client, row.path(), control)?;
        assert_eq!(status, "HTTP/1.1 200 OK", "safe endpoint at {}", row.path());
        assert!(!body.windows(b"i_json_rejected".len()).any(|window| window == b"i_json_rejected"));
        assert_eq!(
            fake.calls.load(Ordering::Acquire),
            baseline + 1,
            "safe endpoint did not reach router at {}",
            row.path()
        );
    }
    fake.stop.store(true, Ordering::Release);
    fake.task
        .join()
        .map_err(|_| anyhow::anyhow!("fake router thread panicked"))?
        .map_err(anyhow::Error::msg)?;
    std::fs::remove_dir_all(fake.cert_root)?;
    Ok(())
}

fn session_frame(timestamp: i64) -> anyhow::Result<Vec<u8>> {
    let runtime = crate::session::submit_fixtures::test_runtime()?;
    let mut submit = crate::session::submit_fixtures::signed_submit(&runtime, 42)?;
    submit.envelope.created_at = timestamp;
    submit.envelope.ext.ext.insert("x_probe".into(), serde_json::json!("v"));
    Ok(serde_json::to_vec(&ramflux_node_core::GatewayClientFrame::Submit { submit })?)
}

async fn tcp_session_frames_refuse_i_json() -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!(
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
    let context = crate::session::tests::test_gateway_context()?;
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
        let frame = received.map_err(anyhow::Error::from)??;
        if refused {
            assert_eq!(frame, EXPECTED_SESSION_NACK);
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
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::task::spawn_blocking(http_rows_refuse_before_router)
            .await
            .map_err(|error| anyhow::anyhow!("HTTP fixture panicked: {error}"))??;
        tcp_session_frames_refuse_i_json().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await;
    assert!(outcome.is_ok(), "gateway I-JSON fixtures timed out after 30 s");
    outcome.map_err(anyhow::Error::from)??;
    Ok(())
}
