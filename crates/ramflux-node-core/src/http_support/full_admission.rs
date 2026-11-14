// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-data body expansion requires a caller-owned authenticated budget permit first.
use super::{
    HttpRequestLimits, NodeCoreError, NodeHttpRequest, classify_request_line,
    finish_http_request_with_capacity, read_classified_headers, rejected,
};

/// A parsed body and the allocation permit that must follow it into the relay owner.
pub struct AdmittedHttpRequest<P> {
    pub request: NodeHttpRequest,
    pub permit: Option<P>,
}

/// Read headers under the old cap, then authenticate and reserve the complete full-data body.
/// The trusted callback checks the original role token and reserves the node's byte/slot budget;
/// it returns an owned guard, which stays with the body until consumed or dropped. A missing
/// permit retains the ordinary 16-KiB pairing cap. No larger body is read before this callback.
/// This reader alone does not enable a full-data route or admit a lease.
/// # Errors
/// Refuses bad headers, failed authentication/quota, excess bytes, EOF and expired deadlines.
pub fn read_http_request_with_full_admission<P>(
    stream: &mut std::net::TcpStream,
    ordinary: HttpRequestLimits,
    mut pairing: HttpRequestLimits,
    is_pairing: impl Fn(&str, &str) -> bool,
    accepted_at: std::time::Instant,
    admit: impl FnOnce(&str, &str, &str, usize) -> Result<Option<P>, NodeCoreError>,
) -> Result<Option<AdmittedHttpRequest<P>>, NodeCoreError> {
    pairing.max_header_bytes =
        pairing.max_header_bytes.min(crate::pairing_relay::PAIRING_MAX_HEADER_BYTES);
    pairing.max_body_bytes =
        pairing.max_body_bytes.min(ramflux_protocol::custody::pairing::full_transfer::PACKET_BYTES);
    pairing.request_timeout =
        pairing.request_timeout.min(crate::pairing_relay::PAIRING_REQUEST_TIMEOUT);
    pairing.read_timeout = pairing.read_timeout.min(pairing.request_timeout);
    let Some((line, limits)) =
        classify_request_line(stream, ordinary, pairing, is_pairing, accepted_at)?
    else {
        return Ok(None);
    };
    let pairing_route = line.pairing_route;
    let Some(classified) = read_classified_headers(stream, limits, accepted_at, line)? else {
        return Ok(None);
    };
    let permit = if pairing_route {
        let header = std::str::from_utf8(&classified.raw[..classified.header_end])
            .map_err(|_| rejected("400 Bad Request"))?;
        let permit = admit(&classified.method, &classified.path, header, classified.parsed.length)?;
        if permit.is_none()
            && classified.parsed.length > crate::pairing_relay::PAIRING_MAX_BODY_BYTES
        {
            return Err(rejected("413 Payload Too Large"));
        }
        permit
    } else {
        None
    };
    let request = finish_http_request_with_capacity(
        stream,
        limits,
        accepted_at,
        classified,
        permit.is_some(),
    )?;
    Ok(request.map(|request| AdmittedHttpRequest { request, permit }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    struct Permit(Arc<AtomicUsize>);
    impl Drop for Permit {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn sockets() -> Result<(TcpStream, TcpStream), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;
        Ok((client, server))
    }
    fn full_limits() -> HttpRequestLimits {
        HttpRequestLimits { max_body_bytes: 524_288, ..crate::pairing_relay::pairing_http_limits() }
    }
    #[test]
    fn full_http_body_without_authentication_retains_old_cap_before_body_read() -> TestResult {
        let (mut client, mut server) = sockets()?;
        // No body is sent: an incorrect read-before-admission path reaches the HTTP deadline.
        write!(client, "POST /client/pairing/v1/send HTTP/1.1\r\nContent-Length: 60000\r\n\r\n")?;
        let calls = AtomicUsize::new(0);
        let result = read_http_request_with_full_admission::<Permit>(
            &mut server,
            HttpRequestLimits::default(),
            full_limits(),
            |_, _| true,
            std::time::Instant::now(),
            |_, _, _, length| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(length, 60_000);
                Ok(None)
            },
        );
        assert!(matches!(
            result,
            Err(NodeCoreError::HttpRequestRejected { status: "413 Payload Too Large" })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        Ok(())
    }
    #[test]
    fn full_http_authenticated_body_keeps_one_charged_allocation_and_owned_permit() -> TestResult {
        let (mut client, mut server) = sockets()?;
        let drops = Arc::new(AtomicUsize::new(0));
        let worker = std::thread::spawn(move || -> std::io::Result<()> {
            write!(
                client,
                "POST /client/pairing/v1/send HTTP/1.1\r\nContent-Length: 60000\r\nX-Full-Test: role-bound\r\n\r\n"
            )?;
            client.write_all(&vec![b'x'; 60_000])
        });
        let AdmittedHttpRequest { request, permit } = read_http_request_with_full_admission(
            &mut server,
            HttpRequestLimits::default(),
            full_limits(),
            |_, _| true,
            std::time::Instant::now(),
            |method, path, headers, length| {
                assert_eq!(method, "POST");
                assert_eq!(path, "/client/pairing/v1/send");
                assert!(headers.contains("X-Full-Test: role-bound"));
                assert_eq!(length, 60_000);
                Ok(Some(Permit(Arc::clone(&drops))))
            },
        )?
        .ok_or("missing request")?;
        worker.join().map_err(|_| "sender failed")??;
        assert_eq!(request.body.len(), 60_000);
        assert_eq!(request.body.capacity(), 60_000);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(permit);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }
    #[test]
    fn full_http_failed_body_releases_precharged_permit() -> TestResult {
        let (mut client, mut server) = sockets()?;
        write!(client, "POST /client/pairing/v1/send HTTP/1.1\r\nContent-Length: 60000\r\n\r\nx")?;
        client.shutdown(std::net::Shutdown::Write)?;
        let drops = Arc::new(AtomicUsize::new(0));
        let result = read_http_request_with_full_admission(
            &mut server,
            HttpRequestLimits::default(),
            full_limits(),
            |_, _| true,
            std::time::Instant::now(),
            |_, _, _, _| Ok(Some(Permit(Arc::clone(&drops)))),
        );
        assert!(matches!(
            result,
            Err(NodeCoreError::HttpRequestRejected { status: "400 Bad Request" })
        ));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }
}
