// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native regressions for bounded federation response and admin worker lifetimes.
use crate::{
    admin_http::{handle_admin_connection_with_limits, spawn_admin_connection},
    public_http::{FederationPublicHttpContext, handle_public_connection_with_limits},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn oversized_headers_receive_a_bounded_413_or_reset_on_both_listeners() -> TestResult {
    let root = crate::test_certificates::temp_cert_root("http-complete-413")?;
    let context = crate::http_listener_tests::context(&root)?;
    for public in [true, false] {
        let limits = crate::http_limits::defaults(public);
        for length in [limits.max_header_bytes + 1, limits.max_header_bytes + 808, 10 * 1024 * 1024]
        {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let mut client = TcpStream::connect(listener.local_addr()?)?;
            client.set_read_timeout(Some(Duration::from_secs(5)))?;
            client.set_write_timeout(Some(Duration::from_secs(5)))?;
            let (mut server, _) = listener.accept()?;
            let admin = context.clone();
            let worker = std::thread::spawn(move || {
                let accepted_at = Instant::now();
                if public {
                    let context = FederationPublicHttpContext {
                        router: admin.router,
                        discovery: admin.discovery,
                    };
                    handle_public_connection_with_limits(
                        &mut server,
                        &context,
                        limits,
                        accepted_at,
                    );
                } else {
                    handle_admin_connection_with_limits(&mut server, &admin, limits, accepted_at);
                }
            });
            let mut writer = client.try_clone()?;
            let sender = std::thread::spawn(move || {
                let mut header = b"GET /healthz HTTP/1.1\r\nX-Padding: ".to_vec();
                header.resize(length, b'x');
                let _ = writer.write_all(&header);
                let _ = writer.shutdown(std::net::Shutdown::Write);
            });
            let mut response = String::new();
            let read_result = client.read_to_string(&mut response);
            sender.join().map_err(|_| "header writer panicked")?;
            worker.join().map_err(|_| "HTTP worker panicked")?;
            if let Err(error) = &read_result
                && length == 10 * 1024 * 1024
                && matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                )
            {
                continue;
            }
            read_result?;
            assert!(
                response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
                "{public}/{length}: {response}"
            );
            let (header, body) = response.split_once("\r\n\r\n").ok_or("missing response body")?;
            let declared: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .ok_or("missing length")?
                .parse()?;
            assert_eq!(declared, body.len());
            assert_ne!(body, "");
        }
    }
    drop(context);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn admin_worker_cap_refuses_excess_and_releases_slots_after_success_rejection_and_timeout()
-> TestResult {
    let root = crate::test_certificates::temp_cert_root("admin-worker-cap")?;
    let context = crate::http_listener_tests::context(&root)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let active = Arc::new(AtomicUsize::new(0));
    let limits = ramflux_node_core::HttpRequestLimits {
        request_timeout: Duration::from_secs(2),
        ..crate::http_limits::defaults(false)
    };
    for raw in [b"GET /healthz HTTP/1.1\r\n\r\n".as_slice(), b"bad\r\n\r\n", b"G"] {
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(10)))?;
        let (server, _) = listener.accept()?;
        let worker = spawn_admin_connection(server, context.clone(), active.clone(), 1, limits)
            .ok_or("first connection refused")?;
        assert_eq!(active.load(Ordering::Acquire), 1);
        let mut excess = TcpStream::connect(listener.local_addr()?)?;
        excess.set_read_timeout(Some(Duration::from_secs(3)))?;
        let (server, _) = listener.accept()?;
        assert!(
            spawn_admin_connection(server, context.clone(), active.clone(), 1, limits).is_none()
        );
        assert_eq!(active.load(Ordering::Acquire), 1);
        let mut refused = String::new();
        excess.read_to_string(&mut refused)?;
        assert!(refused.starts_with("HTTP/1.1 503 Service Unavailable"));
        client.write_all(raw)?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        worker.join().map_err(|_| "admin worker panicked")?;
        let status = if raw == b"G" {
            "408"
        } else if raw == b"bad\r\n\r\n" {
            "400"
        } else {
            "200"
        };
        assert!(response.starts_with(&format!("HTTP/1.1 {status}")), "{response}");
        assert_eq!(active.load(Ordering::Acquire), 0);
    }
    drop(context);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn a_nonreading_response_peer_releases_its_worker_permit() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let _client = TcpStream::connect(listener.local_addr()?)?;
    let (server, _) = listener.accept()?;
    let active = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = std::sync::mpsc::channel();
    let response = crate::http_response::HttpResponse::json(&serde_json::json!({
        "large": "x".repeat(32 * 1024 * 1024)
    }))?;
    let worker = crate::http_connections::spawn_connection(
        server,
        active.clone(),
        1,
        Instant::now(),
        move |stream, _| {
            let limits = ramflux_node_core::HttpRequestLimits {
                request_timeout: Duration::from_millis(100),
                ..crate::http_limits::defaults(true)
            };
            let result = response.write(stream, limits, Instant::now());
            let _ = tx.send(result.is_err());
        },
    )
    .ok_or("connection refused")?;
    assert!(rx.recv_timeout(Duration::from_secs(5))?);
    worker.join().map_err(|_| "response worker panicked")?;
    assert_eq!(active.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn a_slow_reading_response_peer_releases_its_worker_permit_at_the_write_cap() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    client.set_read_timeout(Some(Duration::from_millis(250)))?;
    let shutdown = client.try_clone()?;
    let (server, _) = listener.accept()?;
    let active = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let reader_stop = Arc::clone(&stop);
    let reader = std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while !reader_stop.load(Ordering::Acquire) {
            match client.read(&mut chunk) {
                Ok(0) => break,
                Ok(_) => std::thread::sleep(Duration::from_millis(5)),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let response = crate::http_response::HttpResponse::json(&serde_json::json!({
        "large": "x".repeat(32 * 1024 * 1024)
    }))?;
    let started = Instant::now();
    let worker = crate::http_connections::spawn_connection(
        server,
        active.clone(),
        1,
        Instant::now(),
        move |stream, _| {
            let limits = ramflux_node_core::HttpRequestLimits {
                request_timeout: Duration::from_secs(3600),
                ..crate::http_limits::defaults(true)
            };
            let result = response.write(stream, limits, Instant::now());
            let _ = tx.send((result.is_err(), started.elapsed()));
        },
    )
    .ok_or("connection refused")?;
    let (failed, elapsed) = rx.recv_timeout(Duration::from_secs(8))?;
    worker.join().map_err(|_| "response worker panicked")?;
    stop.store(true, Ordering::Release);
    let _ = shutdown.shutdown(std::net::Shutdown::Both);
    reader.join().map_err(|_| "slow reader panicked")?;
    assert!(failed);
    assert!(elapsed < Duration::from_secs(7), "slow reader held worker for {elapsed:?}");
    assert_eq!(active.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn expired_admin_response_reports_an_explicit_unknown_outcome() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    let (mut server, _) = listener.accept()?;
    let limits = ramflux_node_core::HttpRequestLimits {
        request_timeout: Duration::from_secs(1),
        ..crate::http_limits::defaults(false)
    };
    let accepted_at = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .ok_or("test clock cannot represent expired request")?;
    crate::http_response::HttpResponse::text("200 OK", "mutation completed").write_admin(
        &mut server,
        limits,
        accepted_at,
    )?;
    drop(server);
    let mut response = String::new();
    client.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"));
    assert!(response.ends_with(
        "\r\n\r\nadmin operation completed after its response deadline; outcome unknown"
    ));
    Ok(())
}
