// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit proxy policy precedes every SDK transport-selection branch.

use super::{ConnectionRace, GatewaySessionConfig, GatewaySessionTransportKind};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Case = Result<(), Box<dyn std::error::Error>>;

async fn refuse_requests(
    proxy: tokio::net::TcpListener,
    configured_target: std::net::SocketAddr,
    observed: Arc<std::sync::atomic::AtomicUsize>,
) -> Result<(), std::io::Error> {
    for _ in 0..5 {
        let (mut client, _) = proxy.accept().await?;
        observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= 8192 {
                return Err(std::io::Error::other("proxy request too large"));
            }
            head.push(client.read_u8().await?);
        }
        let expected = format!("CONNECT {configured_target} HTTP/1.1\r\n");
        if !head.starts_with(expected.as_bytes()) {
            return Err(std::io::Error::other(
                "proxy received the wrong configured gateway address",
            ));
        }
        client.write_all(b"HTTP/1.1 407 Refused\r\n\r\n").await?;
    }
    Ok::<(), std::io::Error>(())
}

#[tokio::test]
async fn refusing_proxy_fails_closed_for_auto_serial_raced_and_explicit_kinds() -> Case {
    tokio::time::timeout(Duration::from_secs(20), async {
        let dir = tempfile::tempdir()?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls = ramflux_transport::MeshTlsConfig {
            ca_cert: dir.path().join("ca.pem"),
            service_cert: dir.path().join("server.pem"),
            service_key: dir.path().join("server.key"),
        };
        std::fs::write(&tls.ca_cert, cert.cert.pem())?;
        std::fs::write(&tls.service_cert, cert.cert.pem())?;
        std::fs::write(&tls.service_key, cert.signing_key.serialize_pem())?;
        // A working QUIC endpoint and a listening TCP gateway are both available.
        // Policy must not attempt either of them directly, even after proxy refusal.
        let udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
        udp.set_nonblocking(true)?;
        let udp_observer = udp.try_clone()?;
        let runtime = quinn::default_runtime().ok_or("missing Tokio QUIC runtime")?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(ramflux_transport::quic_gateway_server_config(&tls)?),
            udp,
            runtime,
        )?;
        let direct = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = proxy.local_addr()?;
        let configured_target = direct.local_addr()?;
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&accepted);
        let server = tokio::spawn(refuse_requests(proxy, configured_target, observed));
        let base = GatewaySessionConfig::auto(super::GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse()?,
            gateway_addr: endpoint.local_addr()?,
            server_name: "localhost".into(),
            ca_cert: tls.ca_cert,
            principal_id: "host-principal".into(),
            device_id: "host-device".into(),
            target_delivery_id: "host-target".into(),
            prekey_http_url: None,
        }).with_tcp_gateway_addr(configured_target).with_http_proxy(ramflux_transport::HttpConnectProxy {
            proxy_addr, credentials: None,
        });
        for (kind, race) in [
            (GatewaySessionTransportKind::Auto, ConnectionRace::Serial),
            (GatewaySessionTransportKind::Auto, ConnectionRace::Raced),
            (GatewaySessionTransportKind::TcpTls, ConnectionRace::Serial),
            (GatewaySessionTransportKind::Quic, ConnectionRace::Raced),
        ] {
            let mut config = base.clone();
            config.transport_kind = kind;
            config.connection_race = race;
            let result = super::engine::open_gateway_session_transport(&config).await;
            match result {
                Err(crate::SdkError::Transport(ramflux_transport::TransportError::UnsupportedOperation { .. })) if kind == GatewaySessionTransportKind::Quic => {},
                Err(crate::SdkError::Transport(ramflux_transport::TransportError::HttpStatus { status: 407, .. })) if kind != GatewaySessionTransportKind::Quic => {},
                _ => return Err("proxy policy bypassed or lost the refusal".into()),
            }
        }
        let directory = crate::prekey::sdk_gateway_get_json::<serde_json::Value>(&base, "/mvp1/device-manifest/host").await;
        assert!(matches!(directory, Err(crate::SdkError::Transport(ramflux_transport::TransportError::HttpStatus { status: 407, .. }))), "pre-admission directory reads must also fail closed at the configured proxy");
        let proof = super::auto_dial::open_native_tcp(&base).await;
        assert!(matches!(proof, Err(crate::SdkError::Transport(ramflux_transport::TransportError::HttpStatus { status: 407, .. }))), "fresh native proof transport must obey the same proxy policy");
        server.await??;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), 5, "explicit QUIC must be refused before contacting even the proxy");
        // The dial-entry observer in gateway_dial's unit test independently checks both
        // direct dial functions remain untouched, before any packet could be produced.
        let mut datagram = [0; 1500];
        assert!(matches!(udp_observer.recv_from(&mut datagram), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock), "proxy policy emitted a direct UDP packet");
        assert!(tokio::time::timeout(Duration::from_millis(1), endpoint.accept()).await.is_err(), "a direct QUIC attempt reached the available gateway");
        assert!(tokio::time::timeout(Duration::from_millis(1), direct.accept()).await.is_err(), "proxy refusal caused a direct TCP fallback");
        endpoint.close(0_u32.into(), b"test complete");
        Ok(())
    }).await?
}
