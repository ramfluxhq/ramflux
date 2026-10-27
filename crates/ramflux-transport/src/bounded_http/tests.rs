// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Oversized declarations and trickle responses cannot extend the exchange or allocate their claim.
use super::*;
#[test]
fn malformed_lengths_and_oversized_headers_fail_before_body_reads() {
    for value in ["18446744073709551615", "999999999999999999999999999999", "-1", "+1", "17"] {
        let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\n");
        assert!(read_response(&mut std::io::Cursor::new(input), 16).is_err());
    }
    let input = format!("HTTP/1.1 200 OK\r\nX-Long: {}", "a".repeat(HEADER_LIMIT));
    assert!(read_response(&mut std::io::Cursor::new(input), 16).is_err());
    assert!(
        read_response(
            &mut std::io::Cursor::new(
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
            ),
            16
        )
        .is_err()
    );
}
#[test]
fn bounded_response_preserves_complete_original_bytes() -> Result<(), TransportError> {
    let input = b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\r\n{\"n\":1}";
    assert_eq!(read_response(&mut std::io::Cursor::new(input), 16)?, b"{\"n\":1}");
    Ok(())
}
#[test]
fn trickle_body_does_not_reset_the_whole_exchange_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let peer = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut input = [0; 1024];
        let _ = stream.read(&mut input)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")?;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(5));
            if stream.write_all(b"x").is_err() {
                break;
            }
        }
        Ok(())
    });
    let response = bounded_http_post(BoundedHttpPost {
        endpoint: &endpoint,
        path: "/control",
        body: b"{}",
        tls: None,
        deadline: Instant::now() + Duration::from_millis(100),
        max_bytes: 1024,
    });
    assert!(response.is_err());
    peer.join().map_err(|_| "peer panicked")??;
    Ok(())
}
