// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Socket-level bounds for HTTP response delivery and rejection cleanup.
use crate::{finish_http_response, write_http_response_with_deadline};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn pair() -> Result<(TcpStream, TcpStream), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let client = TcpStream::connect(listener.local_addr()?)?;
    let (server, _) = listener.accept()?;
    Ok((client, server))
}

#[test]
fn http_response_expired_deadline_writes_no_partial_status() -> TestResult {
    let (mut client, mut server) = pair()?;
    let result = write_http_response_with_deadline(
        &mut server,
        "200 OK",
        "text/plain",
        b"secret",
        Instant::now(),
    );
    assert!(result.is_err());
    drop(server);
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    assert!(response.is_empty());
    Ok(())
}

#[test]
fn http_response_nonreading_client_cannot_hold_the_writer_past_its_deadline() -> TestResult {
    let (mut client, mut server) = pair()?;
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    let body = vec![b'x'; 32 * 1024 * 1024];
    let start = Instant::now();
    assert!(
        write_http_response_with_deadline(
            &mut server,
            "200 OK",
            "text/plain",
            &body,
            start + Duration::from_millis(100)
        )
        .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    // Prove the writer actually reached the socket before it stalled, rather than expiring
    // during response construction on a loaded machine.
    let mut sent = [0u8; 64];
    assert!(client.read(&mut sent)? > 0);
    Ok(())
}

#[test]
fn http_response_close_drains_unread_bytes_and_sends_the_complete_rejection() -> TestResult {
    let (mut client, mut server) = pair()?;
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    client.write_all(&vec![b'x'; 9000])?;
    client.shutdown(std::net::Shutdown::Write)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    write_http_response_with_deadline(
        &mut server,
        "413 Payload Too Large",
        "text/plain",
        b"request rejected",
        deadline,
    )?;
    finish_http_response(&mut server, deadline)?;
    drop(server);
    let mut response = String::new();
    client.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("\r\n\r\nrequest rejected"));
    Ok(())
}

#[test]
fn http_response_drain_is_bounded_when_the_peer_keeps_its_write_half_open() -> TestResult {
    let (_client, mut server) = pair()?;
    let start = Instant::now();
    finish_http_response(&mut server, start + Duration::from_secs(30))?;
    assert!(start.elapsed() < Duration::from_secs(3));
    Ok(())
}
