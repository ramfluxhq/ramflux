// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A real TLS transport retains a proven half-read frame when its host admits a concurrent call.

use super::*;
use crate::bus::connection_manager::subscriptions::SessionEvent;
use crate::gateway::frame_dispatch::FrameKind;
use std::sync::atomic::Ordering;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
    time::Instant,
};

type Case<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[derive(Default)]
struct Barrier {
    requested: Notify,
    release: Notify,
}
fn tls(root: &std::path::Path) -> Case<(tokio_rustls::TlsAcceptor, std::path::PathBuf)> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let config = ramflux_transport::MeshTlsConfig {
        ca_cert: root.join("ca.pem"),
        service_cert: root.join("server.pem"),
        service_key: root.join("server.key"),
    };
    std::fs::write(&config.ca_cert, certificate.cert.pem())?;
    std::fs::write(&config.service_cert, certificate.cert.pem())?;
    std::fs::write(&config.service_key, certificate.signing_key.serialize_pem())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        ramflux_transport::tcp_gateway_server_config(&config)?,
    ));
    Ok((acceptor, config.ca_cert))
}
async fn serve(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    frame: Vec<u8>,
    barrier: Arc<Barrier>,
) -> Result<(), SdkError> {
    let (socket, _) = listener.accept().await?;
    let stream = acceptor.accept(socket).await?;
    let mut stream = ramflux_transport::GatewayTcpTlsStream::Server(stream);
    let half = frame.len() / 2;
    let length = u32::try_from(frame.len()).map_err(|e| SdkError::LocalBus(e.to_string()))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&frame[..half]).await?;
    stream.flush().await?;
    let call: GatewayClientFrame =
        ramflux_transport::read_gateway_session_json(&mut stream).await?;
    if !matches!(call, GatewayClientFrame::Cursor { .. }) {
        return Err(SdkError::LocalBus("expected the concurrent cursor call".into()));
    }
    barrier.requested.notify_one();
    barrier.release.notified().await;
    stream.write_all(&frame[half..]).await?;
    ramflux_transport::write_gateway_session_json(
        &mut stream,
        &GatewayServerFrame::Cursor {
            cursor: Some(crate::GatewayCursor {
                target_delivery_id: "host-target".into(),
                inbox_seq: 42,
                last_envelope_id: None,
                acked_envelope_ids: Vec::new(),
                nacked_envelope_ids: std::collections::BTreeMap::new(),
            }),
        },
    )
    .await?;
    let mut closed = [0];
    match stream.read(&mut closed).await {
        Ok(0) => Ok(()),
        Ok(_) => Err(SdkError::LocalBus("unexpected second client call".into())),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}
#[tokio::test]
async fn session_host_concurrent_call_resumes_a_proven_partial_tls_idle_frame() -> Case {
    watchdog(Box::pin(case())).await
}
async fn case() -> Case {
    let root = tempfile::tempdir()?;
    let (acceptor, ca) = tls(root.path())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let frame = serde_json::to_vec(&GatewayServerFrame::Deliver { entry: entry("partial", 1)? })?;
    let expected_progress = 4 + frame.len() / 2;
    let barrier = Arc::new(Barrier::default());
    let server = tokio::spawn(serve(listener, acceptor, frame, Arc::clone(&barrier)));
    let (_client, mut stream) = ramflux_transport::TcpTlsGatewayClient::connect(
        "127.0.0.1:0".parse()?,
        address,
        "localhost",
        &ca,
        Duration::from_secs(600),
    )
    .await?;
    let progress = stream.frame_progress_for_test();
    let mut config = config()?;
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    let mut engine = GatewaySessionEngine::with_test_transport(config.clone(), Box::new(stream));
    engine.frame_timeout = Duration::from_secs(600);
    let (sessions, mut reconnects) = mpsc::channel(8);
    let handle = ConnectionHandle::start_with(
        config,
        Some(engine),
        limits(),
        Arc::new(Connector { sessions, frame: Duration::from_secs(600) }),
        None,
    );
    handle.require_live(Duration::from_secs(600)).await?;
    let mut first = handle.subscribe([FrameKind::Deliver]);
    let mut second = handle.subscribe([FrameKind::Deliver]);
    tokio::time::timeout(Duration::from_secs(10), async {
        while progress.load(Ordering::Acquire) != expected_progress {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let owner = handle.clone();
    let call = tokio::spawn(async move {
        owner
            .call(|engine| Box::pin(engine.cursor()), Instant::now() + Duration::from_secs(600))
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), barrier.requested.notified()).await?;
    assert!(!call.is_finished(), "the reply remains held behind the partial unsolicited frame");
    assert_eq!(progress.load(Ordering::Acquire), expected_progress);
    let released_at = std::time::Instant::now();
    barrier.release.notify_one();
    let cursor = tokio::time::timeout(Duration::from_secs(1), call).await???;
    assert_eq!(cursor.ok_or("cursor reply missing")?.inbox_seq, 42);
    assert!(released_at.elapsed() < Duration::from_secs(1));
    for subscriber in [&mut first, &mut second] {
        let event = tokio::time::timeout(Duration::from_secs(1), subscriber.recv()).await?;
        assert!(
            matches!(event, Some(SessionEvent::Frame { frame, .. }) if matches!(&*frame, GatewayServerFrame::Deliver {entry} if entry.envelope.envelope_id == "partial"))
        );
    }
    assert!(reconnects.try_recv().is_err(), "partial idle cancellation must preserve the session");
    handle.stop().await;
    server.await??;
    Ok(())
}
