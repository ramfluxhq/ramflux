// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Network callbacks retire the real resident manager and delivery continues over fresh TLS.

use super::*;
use crate::bus::connection_manager::ConnectionEvent;
use crate::{NetworkChangeKind, NetworkKey, NetworkMonitor};
use ramflux_transport::GatewayTcpTlsStream;
use tokio::time::Instant;

type Case<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn tls(root: &std::path::Path) -> Case<(tokio_rustls::TlsAcceptor, std::path::PathBuf)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let config = ramflux_transport::MeshTlsConfig {
        ca_cert: root.join("ca.pem"),
        service_cert: root.join("server.pem"),
        service_key: root.join("server.key"),
    };
    std::fs::write(&config.ca_cert, cert.cert.pem())?;
    std::fs::write(&config.service_cert, cert.cert.pem())?;
    std::fs::write(&config.service_key, cert.signing_key.serialize_pem())?;
    Ok((
        tokio_rustls::TlsAcceptor::from(Arc::new(ramflux_transport::tcp_gateway_server_config(
            &config,
        )?)),
        config.ca_cert,
    ))
}

async fn establish(stream: &mut GatewayTcpTlsStream, resumed: bool) -> Result<(), SdkError> {
    let frame: GatewayClientFrame = ramflux_transport::read_gateway_session_json(stream).await?;
    let GatewayClientFrame::Open { open } = frame else {
        return Err(SdkError::LocalBus("missing real session Open".into()));
    };
    assert_eq!(
        open.transport_kind, "tcp_tls",
        "Auto is a policy, never the negotiated wire carrier"
    );
    assert_eq!(
        open.previous_session_id.is_some(),
        resumed,
        "the replacement must use the manager's resume checkpoint"
    );
    let frame: GatewayClientFrame = ramflux_transport::read_gateway_session_json(stream).await?;
    if !matches!(frame, GatewayClientFrame::Auth { .. }) {
        return Err(SdkError::LocalBus("missing signed session Auth".into()));
    }
    ramflux_transport::write_gateway_session_json(
        stream,
        &GatewayServerFrame::SessionEstablished {
            session: crate::GatewaySessionEstablishedFrame {
                session_id: if resumed { "second-session" } else { "first-session" }.into(),
                gateway_id: "test-gateway".into(),
                accepted_cursor: None,
                resume_token: "test-resume".into(),
                resume_window_seconds: 60,
                call_session_generation: None,
            },
        },
    )
    .await?;
    Ok(())
}

async fn cursor_reply(stream: &mut GatewayTcpTlsStream) -> Result<(), SdkError> {
    let call: GatewayClientFrame = ramflux_transport::read_gateway_session_json(stream).await?;
    if !matches!(call, GatewayClientFrame::Cursor { .. }) {
        return Err(SdkError::LocalBus("expected cursor barrier".into()));
    }
    ramflux_transport::write_gateway_session_json(
        stream,
        &GatewayServerFrame::Cursor { cursor: None },
    )
    .await?;
    Ok(())
}

async fn serve_network_change(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) -> Result<(), SdkError> {
    use tokio::io::AsyncReadExt;
    let (socket, _) = listener.accept().await?;
    let mut first = GatewayTcpTlsStream::Server(acceptor.accept(socket).await?);
    establish(&mut first, false).await?;
    cursor_reply(&mut first).await?;
    // The callback must close the first connection before opening its replacement.
    let mut byte = [0; 1];
    match first.read(&mut byte).await {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) => {}
        _ => return Err(SdkError::LocalBus("retired connection remained active".into())),
    }
    let (socket, _) = listener.accept().await?;
    let mut second = GatewayTcpTlsStream::Server(acceptor.accept(socket).await?);
    establish(&mut second, true).await?;
    // Hold delivery until the new generation's subscriber has been installed.
    let call: GatewayClientFrame =
        ramflux_transport::read_gateway_session_json(&mut second).await?;
    if !matches!(call, GatewayClientFrame::Cursor { .. }) {
        return Err(SdkError::LocalBus("expected second cursor barrier".into()));
    }
    let delivery = super::entry("after-network-change", 2)?;
    ramflux_transport::write_gateway_session_json(
        &mut second,
        &GatewayServerFrame::Deliver { entry: delivery },
    )
    .await?;
    ramflux_transport::write_gateway_session_json(
        &mut second,
        &GatewayServerFrame::Cursor { cursor: None },
    )
    .await?;
    // Keep the new connection alive until the manager is explicitly stopped.
    let _ = second.read(&mut byte).await;
    Ok::<(), SdkError>(())
}

#[tokio::test]
async fn network_change_while_connected_redials_and_delivery_continues() -> Case {
    tokio::time::timeout(Duration::from_secs(20), async {
        use crate::bus::connection_manager::subscriptions::SessionEvent;
        use crate::gateway::frame_dispatch::FrameKind;
        let root = tempfile::tempdir()?;
        let (acceptor, ca) = tls(root.path())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(serve_network_change(listener, acceptor));
        let monitor = NetworkMonitor::new();
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let mut cfg = config()?.with_network_monitor(monitor.clone())
            .with_connection_race(crate::ConnectionRace::Raced);
        cfg.transport_kind = crate::GatewaySessionTransportKind::Auto;
        cfg.gateway_addr = blackhole.local_addr()?;
        cfg.tcp_gateway_addr = Some(address);
        cfg.ca_cert = ca;
        let limits = limits();
        let connector = Arc::new(crate::bus::connection_manager::GatewayConnector { timeouts: limits.clone() });
        let handle = ConnectionHandle::start_with(cfg, None, limits, connector, None, None);
        handle.require_live(Duration::from_secs(5)).await?;
        handle.call(|e| Box::pin(e.cursor()), Instant::now() + Duration::from_secs(5)).await?;
        let generation = handle.generation();
        let mut events = handle.events();
        monitor.on_network_changed(NetworkChangeKind::Changed(NetworkKey::from_host_label(b"cell:2")));
        loop {
            if let ConnectionEvent::Connected { generation: next, .. } = events.recv().await? {
                assert_ne!(next, generation, "a network callback must replace the retired session generation");
                break;
            }
        }
        assert_eq!(handle.metadata().ok_or("missing live metadata")?.config.transport_kind,
            crate::GatewaySessionTransportKind::Auto, "reconnection must preserve Auto rather than pinning the previous winner");
        assert_eq!(handle.snapshot().active_transport_kind, Some(crate::GatewaySessionTransportKind::TcpTls), "snapshot must expose the actual winning carrier");
        let mut deliveries = handle.subscribe([FrameKind::Deliver]);
        handle.call(|e| Box::pin(e.cursor()), Instant::now() + Duration::from_secs(5)).await?;
        let delivered = deliveries.recv().await.ok_or("delivery subscription closed")?;
        assert!(matches!(delivered, SessionEvent::Frame { frame, .. } if matches!(&*frame, GatewayServerFrame::Deliver { entry } if entry.inbox_seq == 2)), "delivery must continue through the real reader after the network redial");
        handle.stop().await;
        server.await??;
        Ok(())
    }).await?
}

#[tokio::test(start_paused = true)]
async fn lost_network_waits_for_available_before_dialing() -> Case {
    tokio::time::timeout(Duration::from_secs(10), async {
        let monitor = NetworkMonitor::new();
        monitor.on_network_changed(NetworkChangeKind::Lost);
        let cfg = config()?.with_network_monitor(monitor.clone());
        let (sessions, mut attempts) = mpsc::channel(8);
        let handle = ConnectionHandle::start_with(
            cfg,
            None,
            limits(),
            Arc::new(Connector { sessions, frame: Duration::from_secs(600) }),
            None,
            None,
        );
        // A queued call is bounded by its own deadline even while offline.
        let call =
            handle.call(|e| Box::pin(e.cursor()), Instant::now() + Duration::from_millis(10));
        assert!(call.await.is_err(), "offline calls must remain bounded");
        assert!(
            matches!(attempts.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "Lost must prevent all connection attempts"
        );
        monitor.on_network_changed(NetworkChangeKind::Available(NetworkKey::from_host_label(
            b"wifi:1",
        )));
        let _io = attempts.recv().await.ok_or("Available did not start a connection")?;
        handle.require_live(Duration::from_secs(5)).await?;
        handle.stop().await;
        Ok(())
    })
    .await?
}
