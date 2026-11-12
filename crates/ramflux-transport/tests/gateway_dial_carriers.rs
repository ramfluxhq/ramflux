// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The gateway dial against real loopback peers: UDP dropped, QUIC available, the WebSocket
//! carrier, and the HTTP CONNECT tunnel. Every case checks the TLS exporter on both ends of
//! the winning connection, because the device binding depends on it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ramflux_transport::{
    CarrierKind, DialInputs, DialPlan, GatewayDialTarget, GatewaySessionFrameSink,
    GatewaySessionFrameSource, GatewayTcpTlsStream, MeshTlsConfig, WebSocketDialTarget,
    custody_tcp_exporter, dial_gateway,
};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const NONCE: [u8; 32] = [7; 32];
const FRAME: &[u8] = br#"{"frame_type":"heartbeat","now":1}"#;

/// A self-signed gateway identity on disk, removed on drop.
struct Identity {
    root: PathBuf,
    tls: MeshTlsConfig,
}

impl Identity {
    fn new(label: &str) -> TestResult<Self> {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir()
            .join(format!("ramflux-dial-{label}-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&root)?;
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls = MeshTlsConfig {
            ca_cert: root.join("ca.pem"),
            service_cert: root.join("server.pem"),
            service_key: root.join("server.key"),
        };
        std::fs::write(&tls.ca_cert, generated.cert.pem())?;
        std::fs::write(&tls.service_cert, generated.cert.pem())?;
        std::fs::write(&tls.service_key, generated.signing_key.serialize_pem())?;
        Ok(Self { root, tls })
    }

    fn acceptor(&self) -> TestResult<tokio_rustls::TlsAcceptor> {
        Ok(tokio_rustls::TlsAcceptor::from(Arc::new(ramflux_transport::tcp_gateway_server_config(
            &self.tls,
        )?)))
    }

    fn target(&self, quic_addr: SocketAddr, tcp_addr: SocketAddr) -> GatewayDialTarget {
        GatewayDialTarget {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            quic_addr,
            tcp_addr,
            server_name: "localhost".to_owned(),
            ca_cert: self.tls.ca_cert.clone(),
            handshake_timeout: Duration::from_secs(5),
            session_timeout: Duration::from_secs(5),
            websocket: None,
            #[cfg(all(feature = "http-connect-proxy", not(windows)))]
            http_proxy: None,
        }
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A UDP socket that receives and never answers: QUIC to it is silently dropped.
fn udp_blackhole() -> TestResult<(std::net::UdpSocket, SocketAddr)> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    socket.set_nonblocking(true)?;
    let addr = socket.local_addr()?;
    Ok((socket, addr))
}

/// A TCP + TLS gateway that echoes one length-prefixed frame and reports its exporter.
async fn tcp_tls_echo_gateway(
    identity: &Identity,
    handshakes: Arc<AtomicUsize>,
) -> TestResult<(SocketAddr, tokio::task::JoinHandle<TestResult<[u8; 32]>>)> {
    let acceptor = identity.acceptor()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let mut stream = GatewayTcpTlsStream::Server(acceptor.accept(socket).await?);
        handshakes.fetch_add(1, Ordering::SeqCst);
        let exporter = custody_tcp_exporter(&stream, &NONCE)?;
        let mut len = [0_u8; 4];
        stream.read_exact(&mut len).await?;
        let mut body = vec![0_u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).await?;
        stream.write_all(&len).await?;
        stream.write_all(&body).await?;
        stream.flush().await?;
        Ok(exporter)
    });
    Ok((addr, server))
}

#[tokio::test]
async fn with_udp_dropped_tcp_tls_wins_the_race_with_the_same_exporter_on_both_ends() -> TestResult {
    let identity = Identity::new("udp-dropped")?;
    let (_blackhole, quic_addr) = udp_blackhole()?;
    let handshakes = Arc::new(AtomicUsize::new(0));
    let (tcp_addr, server) = tcp_tls_echo_gateway(&identity, Arc::clone(&handshakes)).await?;

    let plan = DialPlan::auto(DialInputs::default());
    let started = Instant::now();
    let dialed = dial_gateway(identity.target(quic_addr, tcp_addr), &plan).await?;
    // The stream carrier starts 300 ms in and must not wait out the QUIC handshake deadline.
    assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    assert_eq!(dialed.carrier(), CarrierKind::TcpTls);

    let (quic_client, mut stream) = dialed.into_parts();
    assert!(quic_client.is_none());
    let client_exporter = stream.custody_exporter(&NONCE)?;
    stream.send_frame(FRAME).await?;
    assert_eq!(stream.recv_frame().await?, FRAME);
    assert_eq!(server.await??, client_exporter);
    assert_eq!(handshakes.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn quic_wins_when_udp_works_and_no_second_connection_is_left_open() -> TestResult {
    let identity = Identity::new("quic-wins")?;
    let endpoint = quinn::Endpoint::server(
        ramflux_transport::quic_gateway_server_config(&identity.tls)?,
        "127.0.0.1:0".parse()?,
    )?;
    let quic_addr = endpoint.local_addr()?;
    let quic_server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("QUIC endpoint closed")?;
        let connection = incoming.await?;
        // Hold the connection until the client is done; bounded in case the close is lost.
        let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let handshakes = Arc::new(AtomicUsize::new(0));
    let (tcp_addr, tcp_server) = tcp_tls_echo_gateway(&identity, Arc::clone(&handshakes)).await?;

    let plan = DialPlan::auto(DialInputs::default());
    let dialed = dial_gateway(identity.target(quic_addr, tcp_addr), &plan).await?;
    assert_eq!(dialed.carrier(), CarrierKind::Quic);
    let (quic_client, stream) = dialed.into_parts();
    assert!(quic_client.is_some());
    assert!(stream.custody_exporter(&NONCE).is_ok());

    // Past the stagger: the losing TCP + TLS leg was aborted, so the gateway saw no handshake.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(handshakes.load(Ordering::SeqCst), 0);
    tcp_server.abort();
    drop(stream);
    drop(quic_client);
    quic_server.await??;
    Ok(())
}

async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> TestResult<String> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            return Err("request head too large".into());
        }
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    Ok(String::from_utf8(head)?)
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then_some(value.trim())
    })
}

/// Read one client frame and return its opcode, unmasked payload and whether it was masked.
async fn read_client_frame<S: AsyncRead + Unpin>(stream: &mut S) -> TestResult<(u8, Vec<u8>, bool)> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await?;
    let masked = header[1] & 0x80 != 0;
    let mut len = usize::from(header[1] & 0x7F);
    if len == 126 {
        let mut extended = [0_u8; 2];
        stream.read_exact(&mut extended).await?;
        len = usize::from(u16::from_be_bytes(extended));
    } else if len == 127 {
        return Err("unexpected 64-bit frame length".into());
    }
    let mut mask = [0_u8; 4];
    if masked {
        stream.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload).await?;
    for (byte, key) in payload.iter_mut().zip(mask.iter().cycle()) {
        *byte ^= key;
    }
    Ok((header[0], payload, masked))
}

struct WebSocketServerReport {
    request_head: String,
    exporter: [u8; 32],
    frames: Vec<(u8, Vec<u8>, bool)>,
}

/// A minimal WebSocket gateway: upgrade, one Ping, one fragmented binary message, then it
/// collects the client's Pong and binary frame.
async fn websocket_gateway(
    identity: &Identity,
) -> TestResult<(SocketAddr, tokio::task::JoinHandle<TestResult<WebSocketServerReport>>)> {
    let acceptor = identity.acceptor()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let mut stream = GatewayTcpTlsStream::Server(acceptor.accept(socket).await?);
        let exporter = custody_tcp_exporter(&stream, &NONCE)?;
        let request_head = read_http_head(&mut stream).await?;
        let key = header_value(&request_head, "sec-websocket-key").ok_or("no websocket key")?;
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             Sec-WebSocket-Protocol: {}\r\n\r\n",
            ramflux_transport::GATEWAY_WEBSOCKET_SUBPROTOCOL
        );
        stream.write_all(response.as_bytes()).await?;
        // Ping "p", then the frame body split across a binary and a continuation frame.
        let (first, second) = FRAME.split_at(FRAME.len() / 2);
        stream.write_all(&[0x89, 0x01, b'p']).await?;
        stream.write_all(&[0x02, u8::try_from(first.len())?]).await?;
        stream.write_all(first).await?;
        stream.write_all(&[0x80, u8::try_from(second.len())?]).await?;
        stream.write_all(second).await?;
        stream.flush().await?;
        let mut frames = Vec::new();
        for _ in 0..2 {
            frames.push(read_client_frame(&mut stream).await?);
        }
        Ok(WebSocketServerReport { request_head, exporter, frames })
    });
    Ok((addr, server))
}

#[tokio::test]
async fn websocket_carrier_keeps_the_native_binding_and_one_message_per_frame() -> TestResult {
    let identity = Identity::new("websocket")?;
    let (addr, server) = websocket_gateway(&identity).await?;
    let (_blackhole, unused) = udp_blackhole()?;
    let mut target = identity.target(unused, addr);
    target.websocket = Some(WebSocketDialTarget { addr, authority: "localhost".to_owned() });

    let dialed = dial_gateway(target, &DialPlan::single(CarrierKind::WebSocketTls)).await?;
    assert_eq!(dialed.carrier(), CarrierKind::WebSocketTls);
    let (_, mut stream) = dialed.into_parts();
    let client_exporter = stream.custody_exporter(&NONCE)?;
    // The fragmented server message arrives as exactly one frame body.
    assert_eq!(stream.recv_frame().await?, FRAME);
    stream.send_frame(FRAME).await?;

    let report = server.await??;
    // Native binding: both ends derive the same exporter from this TLS session.
    assert_eq!(report.exporter, client_exporter);
    let head = report.request_head.to_ascii_lowercase();
    assert!(head.starts_with("get /v1/session http/1.1\r\n"), "{head}");
    assert_eq!(header_value(&report.request_head, "sec-websocket-protocol"), Some("ramflux.gateway_session.v1"));
    for forbidden in ["origin", "cookie", "authorization", "sec-websocket-extensions"] {
        assert_eq!(header_value(&report.request_head, forbidden), None, "{forbidden}");
    }
    // The Pong answers the Ping, then one masked binary frame carries the body unprefixed.
    assert_eq!(report.frames.len(), 2);
    assert_eq!(report.frames[0], (0x8A, b"p".to_vec(), true));
    assert_eq!(report.frames[1], (0x82, FRAME.to_vec(), true));
    Ok(())
}

#[cfg(all(feature = "http-connect-proxy", not(windows)))]
#[tokio::test]
async fn http_proxy_tunnels_tcp_tls_end_to_end_and_quic_is_never_sent() -> TestResult {
    let identity = Identity::new("proxy")?;
    let (blackhole, quic_addr) = udp_blackhole()?;
    let handshakes = Arc::new(AtomicUsize::new(0));
    let (tcp_addr, server) = tcp_tls_echo_gateway(&identity, Arc::clone(&handshakes)).await?;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;
    let proxy = tokio::spawn(async move {
        let (mut client, _) = proxy_listener.accept().await?;
        let head = read_http_head(&mut client).await?;
        let mut upstream = tokio::net::TcpStream::connect(tcp_addr).await?;
        client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
        // The tunnel moves ciphertext only; it ends when either side closes.
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        Ok::<String, Box<dyn std::error::Error + Send + Sync>>(head)
    });

    let mut target = identity.target(quic_addr, tcp_addr);
    target.http_proxy = Some(ramflux_transport::HttpConnectProxy {
        proxy_addr,
        credentials: Some(ramflux_transport::ProxyCredentials::new(
            "alice".to_owned(),
            "s3cret-value".to_owned(),
        )?),
    });
    let plan = DialPlan::auto(DialInputs { http_proxy: true, ..DialInputs::default() });
    assert!(!plan.contains(CarrierKind::Quic));
    let dialed = dial_gateway(target, &plan).await?;
    assert_eq!(dialed.carrier(), CarrierKind::TcpTls);
    let (_, mut stream) = dialed.into_parts();
    let client_exporter = stream.custody_exporter(&NONCE)?;
    stream.send_frame(FRAME).await?;
    assert_eq!(stream.recv_frame().await?, FRAME);
    // TLS ran end to end through the tunnel: the gateway, not the proxy, holds the exporter.
    assert_eq!(server.await??, client_exporter);
    drop(stream);

    let head = proxy.await??;
    assert!(head.starts_with(&format!("CONNECT {tcp_addr} HTTP/1.1\r\n")), "{head}");
    assert_eq!(header_value(&head, "proxy-authorization"), Some("Basic YWxpY2U6czNjcmV0LXZhbHVl"));
    // Nothing was sent to the QUIC address.
    let mut datagram = [0_u8; 1500];
    assert!(blackhole.recv_from(&mut datagram).is_err());
    Ok(())
}
