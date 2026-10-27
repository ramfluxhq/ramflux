// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Anonymous request framing and slow-client bounds on the real public worker path.
use crate::public_http::{
    FederationPublicHttpContext, handle_public_connection_with_limits, spawn_public_connection,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn exchange(
    raw: &[u8],
    context: FederationPublicHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut client = TcpStream::connect(listener.local_addr()?)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        handle_public_connection_with_limits(&mut stream, &context, limits, Instant::now());
        Ok(())
    });
    client.write_all(raw)?;
    let mut response = String::new();
    client.read_to_string(&mut response)?;
    worker.join().map_err(|_| "public worker panicked")??;
    Ok(response)
}
#[test]
fn oversized_and_malformed_requests_are_rejected_and_public_service_stays_alive() -> TestResult {
    let root = crate::test_certificates::temp_cert_root("request-limits")?;
    let admin = crate::http_listener_tests::context(&root)?;
    let context = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    let limits = crate::http_limits::defaults(true);
    for (length, status) in [
        ("18446744073709551615", "413"),
        ("9223372036854775000", "413"),
        ("99999999999999999999999999999", "413"),
        ("65537", "413"),
        ("-1", "400"),
        ("bad", "400"),
        ("+1", "400"),
        ("", "400"),
    ] {
        let raw = format!("GET /healthz HTTP/1.1\r\nContent-Length: {length}\r\n\r\n");
        let response = exchange(raw.as_bytes(), context.clone(), limits)?;
        assert!(response.starts_with(&format!("HTTP/1.1 {status}")), "{response}");
    }
    let mut header = b"GET /healthz HTTP/1.1\r\nX-Padding: ".to_vec();
    header.resize(limits.max_header_bytes, b'a');
    assert!(exchange(&header, context.clone(), limits)?.starts_with("HTTP/1.1 413"));
    for raw in [
        b"GET /healthz HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"GET /healthz HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    ] {
        assert!(exchange(raw, context.clone(), limits)?.starts_with("HTTP/1.1 400"));
    }
    assert!(
        exchange(b"GET /healthz HTTP/1.1\r\n\r\n", context, limits)?.starts_with("HTTP/1.1 200")
    );
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn sixty_four_header_and_body_tricklers_release_slots_at_whole_request_deadline() -> TestResult {
    let root = crate::test_certificates::temp_cert_root("trickle-deadline")?;
    let admin = crate::http_listener_tests::context(&root)?;
    let context = FederationPublicHttpContext {
        router: admin.router.clone(),
        discovery: admin.discovery.clone(),
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let active = Arc::new(AtomicUsize::new(0));
    let limits = ramflux_node_core::HttpRequestLimits {
        request_timeout: Duration::from_secs(2),
        ..crate::http_limits::defaults(true)
    };
    let mut clients = Vec::new();
    let mut workers = Vec::new();
    for index in 0..64 {
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        client.set_write_timeout(Some(Duration::from_millis(100)))?;
        if index % 2 == 0 {
            client.write_all(b"G")?;
        } else {
            client.write_all(b"GET /healthz HTTP/1.1\r\nContent-Length: 65536\r\n\r\n")?;
        }
        let (stream, _) = listener.accept()?;
        workers.push(
            spawn_public_connection(stream, context.clone(), active.clone(), 64, limits)
                .ok_or("unexpected connection refusal")?,
        );
        clients.push(client);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let writer_stop = stop.clone();
    let writer = std::thread::spawn(move || {
        while !writer_stop.load(Ordering::Acquire) {
            for client in &mut clients {
                let _ = client.write_all(b"x");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let joiner = std::thread::spawn(move || {
        let mut success = true;
        for worker in workers {
            if worker.join().is_err() {
                success = false;
            }
        }
        let _ = done_tx.send(success);
    });
    let done = done_rx.recv_timeout(Duration::from_secs(8));
    stop.store(true, Ordering::Release);
    writer.join().map_err(|_| "trickle writer panicked")?;
    joiner.join().map_err(|_| "trickle joiner panicked")?;
    assert_eq!(done.ok(), Some(true), "tricklers must time out while they are still sending");
    assert_eq!(active.load(Ordering::Acquire), 0);
    let mut normal = TcpStream::connect(listener.local_addr()?)?;
    normal.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (stream, _) = listener.accept()?;
    let worker = spawn_public_connection(stream, context, active.clone(), 64, limits)
        .ok_or("normal request refused after deadline")?;
    normal.write_all(b"GET /healthz HTTP/1.1\r\n\r\n")?;
    let mut response = String::new();
    normal.read_to_string(&mut response)?;
    worker.join().map_err(|_| "normal worker panicked")?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    drop(admin);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
