// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full pairing uses raw bounded bodies; no JSON/base64 wrapper or pooled implicit retry.
use super::{
    Instant, MeshHttpClient, MeshHttpClientRequest, MeshHttpTimeouts, MeshTlsConfig, Read,
    TransportError, Write, close_mesh_client_connection, new_mesh_http_connection,
    normalized_endpoint, record_mesh_client_exchange, record_mesh_client_request,
};
use zeroize::Zeroizing;
const HEADER_BYTES: usize = 4096;
const MAX_BODY: usize = ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES;

/// Headers borrow their erasing secret owner. No Debug/serde, including on errors.
pub struct RawMeshPost<'a> {
    pub endpoint: &'a str,
    pub path: &'a str,
    pub tls: &'a MeshTlsConfig,
    pub server_name: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
    pub max_response_bytes: usize,
    pub deadline: Instant,
}
pub struct RawMeshResponse {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
}
impl MeshHttpClient {
    /// One exact raw POST with an absolute connect/handshake/read/write deadline.
    /// Header and body are written separately, preserving the caller's charged allocation.
    /// A caller retries only according to the pairing arm's explicit retry contract.
    /// # Errors
    /// Refuses malformed/injected/oversized headers, TLS/I/O/deadline or reply framing errors.
    pub fn post_raw(&self, request: &RawMeshPost<'_>) -> Result<RawMeshResponse, TransportError> {
        let header = encode_header(request)?;
        let endpoint = normalized_endpoint(request.endpoint);
        let timeouts = MeshHttpTimeouts::DEFAULT.with_deadline(request.deadline);
        let connection_request = MeshHttpClientRequest {
            method: "POST",
            endpoint,
            path: request.path,
            tls: request.tls,
            server_name: request.server_name,
            peer_ca_pems: None,
            body: None,
            timeouts,
            resolver: self.resolver.as_ref(),
            resolver_pool: self.resolver_pool.as_ref(),
        };
        record_mesh_client_request();
        let mut connection = new_mesh_http_connection(endpoint, &connection_request)?;
        let started = Instant::now();
        let result = (|| {
            connection.stream.sock.install(timeouts);
            connection.stream.write_all(&header)?;
            connection.stream.write_all(request.body)?;
            connection.stream.flush()?;
            read_reply(&mut connection.stream, request.max_response_bytes)
        })();
        record_mesh_client_exchange(started.elapsed());
        close_mesh_client_connection(connection);
        result
    }
}
fn encode_header(request: &RawMeshPost<'_>) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let endpoint = normalized_endpoint(request.endpoint);
    if request.body.len() > MAX_BODY
        || request.max_response_bytes > MAX_BODY
        || !request.path.starts_with('/')
        || request.headers.len() > 16
        || request.path.bytes().chain(endpoint.bytes()).any(|byte| !byte.is_ascii_graphic())
    {
        return Err(invalid());
    }
    let mut length = 200_usize
        .checked_add(request.path.len())
        .and_then(|n| n.checked_add(endpoint.len()))
        .ok_or_else(invalid)?;
    for (name, value) in request.headers {
        if name.is_empty()
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
            || ["content-length", "transfer-encoding", "connection", "host", "content-type"]
                .iter()
                .any(|reserved| name.eq_ignore_ascii_case(reserved))
        {
            return Err(invalid());
        }
        length = length
            .checked_add(name.len())
            .and_then(|n| n.checked_add(value.len()))
            .and_then(|n| n.checked_add(4))
            .ok_or_else(invalid)?;
    }
    if length > HEADER_BYTES {
        return Err(invalid());
    }
    let mut header = Zeroizing::new(Vec::with_capacity(length));
    write!(&mut *header, "POST {} HTTP/1.1\r\nHost: {endpoint}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
        request.path, request.body.len()).map_err(|_| invalid())?;
    for (name, value) in request.headers {
        write!(&mut *header, "{name}: {value}\r\n").map_err(|_| invalid())?;
    }
    header.extend_from_slice(b"\r\n");
    Ok(header)
}
fn read_reply(reader: &mut impl Read, cap: usize) -> Result<RawMeshResponse, TransportError> {
    let mut raw = Zeroizing::new(Vec::with_capacity(HEADER_BYTES));
    while !raw.ends_with(b"\r\n\r\n") {
        if raw.len() == HEADER_BYTES {
            return Err(invalid());
        }
        let mut byte = [0];
        reader.read_exact(&mut byte).map_err(|_| invalid())?;
        raw.push(byte[0]);
    }
    let header = std::str::from_utf8(&raw).map_err(|_| invalid())?;
    let mut lines = header.split("\r\n");
    let mut status = lines.next().ok_or_else(invalid)?.split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(invalid());
    }
    let status = status
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|code| (100..600).contains(code))
        .ok_or_else(invalid)?;
    let mut length = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) {
            return Err(invalid());
        }
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        if name.trim() != name || name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim_matches([' ', '\t']);
            if length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid());
            }
            let n = value.parse::<usize>().map_err(|_| invalid())?;
            if n > cap {
                return Err(invalid());
            }
            length = Some(n);
        }
    }
    let length = length.ok_or_else(invalid)?;
    let mut body = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut body).map_err(|_| invalid())?;
    Ok(RawMeshResponse { status, body })
}
fn invalid() -> TransportError {
    TransportError::Http("invalid bounded raw mesh exchange".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn raw_reply_cap_framing_and_errors_do_not_echo_secret_bytes() -> Result {
        let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz";
        let parsed = read_reply(&mut reply.as_slice(), 3)?;
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body.as_slice(), b"xyz");
        assert_eq!(parsed.body.capacity(), 3);
        for headers in [
            "Content-Length: 3",
            "Content-Length: 2\r\nContent-Length: 2",
            "Content-Length: 2\r\nTransfer-Encoding: chunked",
            "Content-Length: +2",
        ] {
            let bytes = Zeroizing::new(format!(
                "HTTP/1.1 200 OK\r\n{headers}\r\nX-Test: secret-marker\r\n\r\nxx"
            ));
            let error = read_reply(&mut bytes.as_bytes(), 2).err().ok_or("bad reply accepted")?;
            assert!(!format!("{error:?} {error}").contains("secret-marker"));
        }
        // An error status body stays in its erasing owner, never in TransportError text.
        let bytes = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 13\r\n\r\nsecret-marker";
        let denied = read_reply(&mut bytes.as_slice(), 32)?;
        assert_eq!(denied.status, 403);
        Ok(())
    }
}
