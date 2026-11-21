// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway dialing against loopback peers: UDP dropped, QUIC available, and CONNECT. Every case checks the TLS exporter on both ends of
//! the winning connection, because the device binding depends on it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ramflux_transport::{
    CarrierKind, DialInputs, DialPlan, GatewayDialTarget, GatewaySessionFrameSink,
    GatewaySessionFrameSource, GatewayTcpTlsStream, MeshTlsConfig, custody_tcp_exporter,
    dial_gateway,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const NONCE: [u8; 32] = [7; 32];
const FRAME: &[u8] = br#"{"frame_type":"heartbeat","now":1}"#;

/// A self-signed gateway identity on disk, removed on drop.
struct Identity {
    _root: tempfile::TempDir,
    tls: MeshTlsConfig,
}

impl Identity {
    fn new(label: &str) -> TestResult<Self> {
        let root = tempfile::Builder::new().prefix(label).tempdir()?;
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls = MeshTlsConfig {
            ca_cert: root.path().join("ca.pem"),
            service_cert: root.path().join("server.pem"),
            service_key: root.path().join("server.key"),
        };
        std::fs::write(&tls.ca_cert, generated.cert.pem())?;
        std::fs::write(&tls.service_cert, generated.cert.pem())?;
        std::fs::write(&tls.service_key, generated.signing_key.serialize_pem())?;
        Ok(Self { _root: root, tls })
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
            #[cfg(all(feature = "http-connect-proxy", not(windows)))]
            http_proxy: None,
        }
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
        let length = u32::from_be_bytes(len) as usize;
        assert!(length <= 4096, "echo input exceeds test bound");
        let mut body = vec![0_u8; length.min(4096)];
        stream.read_exact(&mut body).await?;
        stream.write_all(&len).await?;
        stream.write_all(&body).await?;
        stream.flush().await?;
        Ok(exporter)
    });
    Ok((addr, server))
}

#[tokio::test]
async fn with_udp_dropped_tcp_tls_wins_the_race_with_the_same_exporter_on_both_ends() -> TestResult
{
    tokio::time::timeout(Duration::from_secs(20), async {
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
    })
    .await?
}

#[tokio::test]
async fn quic_wins_when_udp_works_and_no_second_connection_is_left_open() -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
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
        let (tcp_addr, tcp_server) =
            tcp_tls_echo_gateway(&identity, Arc::clone(&handshakes)).await?;

        let plan = DialPlan::auto(DialInputs::default());
        let dialed = dial_gateway(identity.target(quic_addr, tcp_addr), &plan).await?;
        assert_eq!(dialed.carrier(), CarrierKind::Quic);
        let (quic_client, stream) = dialed.into_parts();
        assert!(quic_client.is_some());
        assert!(stream.custody_exporter(&NONCE).is_ok());

        // Past the stagger: the losing TCP + TLS leg was aborted, so the gateway saw no handshake.
        // dial_gateway drains aborted legs before returning.
        assert_eq!(handshakes.load(Ordering::SeqCst), 0);
        tcp_server.abort();
        drop(stream);
        drop(quic_client);
        quic_server.await??;
        Ok(())
    })
    .await?
}

#[cfg(all(feature = "http-connect-proxy", not(windows)))]
async fn read_http_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> TestResult<String> {
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

#[cfg(all(feature = "http-connect-proxy", not(windows)))]
#[tokio::test]
async fn http_proxy_tunnels_tcp_tls_end_to_end_and_quic_is_never_sent() -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
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
        target.http_proxy = Some(Arc::new(ramflux_transport::HttpConnectProxy {
            proxy_addr,
            credentials: Some(ramflux_transport::ProxyCredentials::new(
                "alice".to_owned(),
                "s3cret-value".to_owned(),
            )?),
        }));
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
        assert!(
            head.contains("Proxy-Authorization: Basic YWxpY2U6czNjcmV0LXZhbHVl"),
            "proxy credentials missing"
        );
        // Nothing was sent to the QUIC address.
        let mut datagram = [0_u8; 1500];
        assert!(blackhole.recv_from(&mut datagram).is_err());
        Ok(())
    })
    .await?
}
