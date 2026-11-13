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

#[test]
fn cr_discovery_get_has_no_body_and_preserves_original_document() -> Result<(), TransportError> {
    struct Capture {
        response: std::io::Cursor<&'static [u8]>,
        written: Vec<u8>,
    }
    impl Read for Capture {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.response.read(bytes)
        }
    }
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut stream = Capture {
        response: std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"n\":1}"),
        written: Vec::new(),
    };
    let request = BoundedHttpPost {
        endpoint: "https://node.example",
        path: "/.well-known/ramflux/client",
        body: &[],
        tls: None,
        deadline: Instant::now() + Duration::from_secs(1),
        max_bytes: 16,
    };
    let document = exchange(&mut stream, "node.example", &request, "GET")?;
    assert_eq!(
        document, b"{\"n\":1}",
        "discovery must return original document bytes, not a reserialized body"
    );
    assert_eq!(stream.written, b"GET /.well-known/ramflux/client HTTP/1.1\r\nHost: node.example\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "the local discovery read must have a body-free exact HTTP request");
    Ok(())
}

#[test]
fn cr_public_mesh_requires_exact_node_and_federation_service() {
    assert!(
        federation_identity(Some("spiffe://peer.example/ramflux-federation"), "peer.example"),
        "the discovered node's authenticated federation service is a valid peer"
    );
    for uri in [
        "spiffe://other.example/ramflux-federation",
        "spiffe://peer.example/ramflux-router",
        "spiffe://peer.example/ramflux-federation/one",
        "spiffe://peer.example/ramflux-federation/one/extra",
        "spiffe://peer.example/ramflux-federation/",
    ] {
        assert!(
            !federation_identity(Some(uri), "peer.example"),
            "a valid CA signature cannot substitute node/service/instance identity: {uri}"
        );
    }
    assert!(
        !federation_identity(None, "peer.example"),
        "a missing SPIFFE identity cannot enter public federation"
    );
}
