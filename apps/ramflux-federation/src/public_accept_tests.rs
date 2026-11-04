// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[test]
fn reset_after_connect_does_not_delay_the_next_public_accept()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::test_certificates::temp_cert_root("public-reset-accept")?;
    let admin = crate::http_listener_tests::context(&root)?;
    let context = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let connections = ramflux_node_core::ConnectionSet::new(8);
    let limits = crate::http_limits::defaults(true);
    let source_limits = PublicSourceLimits::new(PublicSourceLimitConfig::configured(8)?);
    let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
    let started = Instant::now();
    for _ in 0..3 {
        let reset = TcpStream::connect(address)?;
        socket2::SockRef::from(&reset).set_linger(Some(Duration::ZERO))?;
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        drop(reset);
        // Wait for the RST, rather than racing its arrival with getpeername.
        assert!(stream.read(&mut [0]).is_err());
        // Exercise the real lookup failure (ENOTCONN on Linux, often EINVAL on BSD).
        if stream.peer_addr().is_err() {
            let result = spawn_public_connection(
                stream.try_clone()?,
                context.clone(),
                &connections,
                limits,
                &source_limits,
            );
            assert!(matches!(result, Err(PublicConnectionError::Peer(_))));
            finish_public_accept(result, &mut backoff);
        }
        // Inject ENOTCONN through the production admission path on every platform.
        // BSD can retain the peer address or return EINVAL after the reset instead.
        let result = spawn_public_connection_with_peer(
            stream,
            Err(std::io::Error::from(std::io::ErrorKind::NotConnected)),
            context.clone(),
            &connections,
            limits,
            &source_limits,
        );
        assert!(matches!(result, Err(PublicConnectionError::Peer(_))));
        finish_public_accept(result, &mut backoff);
    }
    let mut healthy = TcpStream::connect(address)?;
    healthy.set_read_timeout(Some(Duration::from_secs(2)))?;
    healthy.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let (stream, _) = listener.accept()?;
    let result = spawn_public_connection(stream, context, &connections, limits, &source_limits);
    assert!(matches!(result, Ok(true)), "healthy connection must be admitted");
    finish_public_accept(result, &mut backoff);
    let mut response = String::new();
    healthy.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "reset burst delayed next public accept by {:?}",
        started.elapsed()
    );
    crate::http_connections::TestWorker::from_connections(connections).join()?;
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn whole_public_listener_serves_concurrent_client_after_reset_burst()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::test_certificates::temp_cert_root("public-whole-reset")?;
    let admin = crate::http_listener_tests::context(&root)?;
    let context = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let connections = ramflux_node_core::ConnectionSet::new(8);
    let worker_connections = Arc::clone(&connections);
    let source_limits = PublicSourceLimits::new(PublicSourceLimitConfig::configured(8)?);
    let shutdown = tokio_util::sync::CancellationToken::new();
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let server = scope.spawn(|| {
            run_public_http_listener(
                &listener,
                &context,
                &worker_connections,
                crate::http_limits::defaults(true),
                &source_limits,
                &shutdown,
            );
        });
        // The listener accepts independently while the reset burst and healthy client connect.
        let response = (|| -> Result<_, Box<dyn std::error::Error>> {
            for _ in 0..3 {
                let reset = TcpStream::connect(address)?;
                socket2::SockRef::from(&reset).set_linger(Some(Duration::ZERO))?;
                drop(reset);
            }
            let started = Instant::now();
            let mut healthy = TcpStream::connect(address)?;
            healthy.set_read_timeout(Some(Duration::from_secs(2)))?;
            healthy.write_all(
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            let mut response = String::new();
            healthy.read_to_string(&mut response)?;
            Ok((response, started.elapsed()))
        })();
        shutdown.cancel();
        server.join().map_err(|_| "public listener panicked")?;
        let (response, elapsed) = response?;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(elapsed < Duration::from_millis(100), "reset burst delayed client by {elapsed:?}");
        Ok(())
    })?;
    crate::http_connections::TestWorker::from_connections(connections).join()?;
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
