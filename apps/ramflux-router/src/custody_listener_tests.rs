// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public direct-listener handshake deadlines protect pre-authentication holders.
use super::*;
struct Cleanup(ramflux_test_support::TestPath);
#[tokio::test]
async fn direct_custody_slow_tls_peer_loses_its_holder_after_five_seconds() -> anyhow::Result<()> {
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "ramflux-custody-public-tls-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
    std::fs::create_dir(&root)?;
    let _cleanup = Cleanup(root.clone());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: root.join("ca.pem"),
        service_cert: root.join("public.pem"),
        service_key: root.join("public.key"),
    };
    std::fs::write(&tls.ca_cert, cert.cert.pem())?;
    std::fs::write(&tls.service_cert, cert.cert.pem())?;
    std::fs::write(&tls.service_key, cert.signing_key.serialize_pem())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        ramflux_transport::tcp_gateway_server_config(&tls)?,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let client = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
    let (socket, _) = listener.accept().await?;
    let started = tokio::time::Instant::now();
    let result =
        tokio::time::timeout(Duration::from_secs(10), accept_tls(&acceptor, socket)).await?;
    assert!(result.is_err());
    assert!(started.elapsed() >= Duration::from_secs(5));
    drop(client);
    Ok(())
}

#[tokio::test]
async fn direct_full_handshake_pool_closes_newcomer_and_deadline_makes_slot_reusable()
-> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let limiter = ramflux_node_core::CustodyIngressLimiter::with_pools(
            1,
            Some(1),
            4,
            Duration::from_millis(100),
        );
        let held = limiter.acquire("192.0.2.1".parse()?, None, std::time::Instant::now())?;
        let server = async {
            let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
            let (_socket, _peer, permit) =
                ramflux_node_core::custody_accept_tcp(&listener, &limiter, &mut backoff).await;
            assert!(!permit.is_revoked());
            Ok::<_, anyhow::Error>(())
        };
        let client = async {
            let mut rejected = tokio::net::TcpStream::connect(address).await?;
            assert_eq!(rejected.read(&mut [0]).await?, 0);
            assert!(!held.is_revoked());
            tokio::time::sleep(Duration::from_millis(110)).await;
            let _fresh = tokio::net::TcpStream::connect(address).await?;
            Ok::<_, anyhow::Error>(())
        };
        let (s, c) = tokio::join!(server, client);
        s?;
        c?;
        assert!(held.is_revoked());
        assert!(held.mark_authenticated("late").is_err());
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn disconnect_cleanup_waits_off_listener_thread_and_revokes_immediately() -> anyhow::Result<()>
{
    let limiter = ramflux_node_core::CustodyIngressLimiter::with_authenticated_limit(256, 1);
    let permit =
        Arc::new(limiter.acquire("192.0.2.1".parse()?, None, std::time::Instant::now())?);
    permit.mark_authenticated("one")?;
    let listener_thread = std::thread::current().id();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let cleanup = Disconnect {
        permit: Arc::clone(&permit),
        cleanup: Some(move || {
            let thread = std::thread::current().id();
            let _ = started_tx.send(thread);
            // A watchdog bounds even a mutation that runs this on the listener thread.
            let released = release_rx.recv_timeout(Duration::from_secs(5)).is_ok();
            let _ = done_tx.send(released);
        }),
    };
    drop(cleanup);
    assert!(permit.is_revoked(), "holder revocation must remain synchronous");
    let replacement = limiter.acquire("192.0.2.1".parse()?, None, std::time::Instant::now())?;
    replacement.mark_authenticated("two")?;
    let cleanup_thread = tokio::time::timeout(Duration::from_secs(2), started_rx).await??;
    let separate_thread = cleanup_thread != listener_thread;
    // This timer must progress while service cleanup is parked.
    tokio::time::sleep(Duration::from_millis(10)).await;
    let _ = release_tx.send(());
    let released = tokio::time::timeout(Duration::from_secs(2), done_rx).await??;
    assert!(separate_thread, "disconnect took the service admission lock on the listener thread");
    assert!(released, "listener could not progress while disconnect cleanup waited");
    Ok(())
}
