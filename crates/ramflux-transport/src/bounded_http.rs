// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh HTTP exchanges share one queue/DNS/connect/TLS/header/body deadline and strict byte caps.
use crate::{MeshTlsConfig, TransportError};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};
const HEADER_LIMIT: usize = 16 * 1024;
/// Prevalidated mutual-TLS identity and independent server trust roots.
#[derive(Clone)]
pub struct BoundedHttpTls {
    config: Arc<rustls::ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
    expected_mesh_uri: Option<String>,
}
impl BoundedHttpTls {
    /// Load local service credentials and either local-node roots or explicitly pinned peer roots.
    /// # Errors
    /// Rejects invalid credentials, an empty independent root set or an invalid server name.
    pub fn new(
        tls: &MeshTlsConfig,
        server_name: &str,
        peer_ca_pems: Option<&[String]>,
    ) -> Result<Self, TransportError> {
        let config = match peer_ca_pems {
            Some([]) => return Err(error("empty pinned HTTP peer roots")),
            Some(pems) => crate::tls_config::mesh_client_config_with_pem_roots(tls, pems)?,
            None => crate::tls_config::mesh_client_config(tls)?,
        };
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
            .map_err(|e| TransportError::InvalidDnsName(e.to_string()))?;
        Ok(Self { config: Arc::new(config), server_name, expected_mesh_uri: None })
    }
    /// Require this exact node/service SPIFFE SAN in addition to CA and DNS authentication.
    /// Node/service identities here intentionally exclude gateway instance identities.
    /// # Errors
    /// Refuses malformed node/service segments.
    pub fn with_mesh_peer(mut self, node: &str, service: &str) -> Result<Self, TransportError> {
        if node.is_empty()
            || node.len() > 253
            || service.is_empty()
            || service.len() > 128
            || node
                .bytes()
                .chain(service.bytes())
                .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'))
        {
            return Err(error("invalid bounded HTTP mesh identity"));
        }
        self.expected_mesh_uri = Some(format!("spiffe://{node}/{service}"));
        Ok(self)
    }
}
/// A caller-supplied absolute deadline includes resolver queueing and every socket operation.
#[derive(Clone, Copy)]
pub struct BoundedHttpPost<'a> {
    pub endpoint: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
    pub tls: Option<&'a BoundedHttpTls>,
    pub deadline: Instant,
    pub max_bytes: usize,
}
/// Exchange bounded original JSON bytes without retries, pooling or per-read timeout resets.
/// Plain HTTP requires an explicit http:// endpoint and is intended for a locally authorized hop.
/// # Errors
/// Rejects expired deadlines, malformed/oversized frames, wrong TLS identities and failed IO.
pub fn bounded_http_post(request: BoundedHttpPost<'_>) -> Result<Vec<u8>, TransportError> {
    bounded_exchange(request, "POST")
}

/// A body-free document read with the same bounded transport contract as POST.
#[derive(Clone, Copy)]
pub struct BoundedHttpGet<'a> {
    pub endpoint: &'a str,
    pub path: &'a str,
    pub tls: Option<&'a BoundedHttpTls>,
    pub deadline: Instant,
    pub max_bytes: usize,
}
/// Read a bounded original document using the same absolute DNS/connect/TLS/body deadline.
/// This uses configured local-node or independently pinned TLS credentials, without redirects.
/// # Errors
/// Rejects expired deadlines, excessive responses and failed authentication/IO.
pub fn bounded_http_get(request: BoundedHttpGet<'_>) -> Result<Vec<u8>, TransportError> {
    bounded_exchange(
        BoundedHttpPost {
            endpoint: request.endpoint,
            path: request.path,
            body: &[],
            tls: request.tls,
            deadline: request.deadline,
            max_bytes: request.max_bytes,
        },
        "GET",
    )
}

fn bounded_exchange(request: BoundedHttpPost<'_>, method: &str) -> Result<Vec<u8>, TransportError> {
    if request.max_bytes == 0
        || request.body.len() > request.max_bytes
        || request.endpoint.len() > 2048
        || !request.path.starts_with('/')
        || request.path.bytes().any(|byte| byte <= b' ' || byte == 127)
    {
        return Err(error("invalid bounded HTTP request"));
    }
    remaining(request.deadline)?;
    let endpoint = if request.tls.is_none() {
        request
            .endpoint
            .strip_prefix("http://")
            .ok_or_else(|| error("plain HTTP requires explicit local hop"))?
    } else {
        if request.endpoint.starts_with("http://") {
            return Err(error("TLS request has plain HTTP endpoint"));
        }
        request.endpoint.strip_prefix("https://").unwrap_or(request.endpoint)
    };
    if endpoint.bytes().any(|byte| byte <= b' ' || byte == b'/' || byte == 127) {
        return Err(error("invalid HTTP endpoint"));
    }
    let addresses = crate::bounded_http_dns::resolve(endpoint, request.deadline)?;
    let mut connected = None;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, remaining(request.deadline)?) {
            connected = Some(stream);
            break;
        }
    }
    let stream = connected.ok_or_else(|| error("bounded HTTP connect failed"))?;
    stream.set_nodelay(true)?;
    let stream = DeadlineTcp { stream, deadline: request.deadline };
    match request.tls {
        None => exchange(stream, endpoint, &request, method),
        Some(tls) => {
            let connection =
                rustls::ClientConnection::new(tls.config.clone(), tls.server_name.clone())
                    .map_err(|e| TransportError::Tls(e.to_string()))?;
            let mut stream = rustls::StreamOwned::new(connection, stream);
            while stream.conn.is_handshaking() {
                stream.conn.complete_io(&mut stream.sock)?;
            }
            if let Some(expected) = &tls.expected_mesh_uri {
                let actual = stream
                    .conn
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .map(crate::extract_spiffe_uri_from_certificate)
                    .transpose()?
                    .flatten();
                if actual.as_deref() != Some(expected.as_str()) {
                    return Err(error("bounded HTTP mesh identity mismatch"));
                }
            }
            exchange(stream, endpoint, &request, method)
        }
    }
}
struct DeadlineTcp {
    stream: TcpStream,
    deadline: Instant,
}
impl Read for DeadlineTcp {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(io_remaining(self.deadline)?))?;
        self.stream.read(buffer)
    }
}
impl Write for DeadlineTcp {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(io_remaining(self.deadline)?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        io_remaining(self.deadline)?;
        self.stream.flush()
    }
}
fn io_remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP exchange deadline exceeded")
    })
}
fn remaining(deadline: Instant) -> Result<Duration, TransportError> {
    io_remaining(deadline).map_err(TransportError::Io)
}
fn error(message: &str) -> TransportError {
    TransportError::Http(message.into())
}
fn exchange<S: Read + Write>(
    mut stream: S,
    endpoint: &str,
    request: &BoundedHttpPost<'_>,
    method: &str,
) -> Result<Vec<u8>, TransportError> {
    let headers = format!(
        "{method} {} HTTP/1.1\r\nHost: {endpoint}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request.path,
        request.body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(request.body)?;
    stream.flush()?;
    read_response(&mut BufReader::new(stream), request.max_bytes)
}
pub(crate) fn line<R: BufRead>(
    reader: &mut R,
    budget: &mut usize,
) -> Result<Vec<u8>, TransportError> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Err(error("HTTP header ended before newline"));
        }
        let size = buffer.iter().position(|b| *b == b'\n').map_or(buffer.len(), |p| p + 1);
        if size > *budget {
            return Err(error("HTTP headers exceed budget"));
        }
        let complete = buffer[size - 1] == b'\n';
        line.extend_from_slice(&buffer[..size]);
        reader.consume(size);
        *budget -= size;
        if complete {
            return Ok(line);
        }
    }
}
fn read_response<R: BufRead>(reader: &mut R, cap: usize) -> Result<Vec<u8>, TransportError> {
    let mut budget = HEADER_LIMIT;
    let status_line = line(reader, &mut budget)?;
    let status_line =
        std::str::from_utf8(&status_line).map_err(|_| error("invalid HTTP status"))?;
    let mut fields = status_line.split_whitespace();
    if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(error("invalid HTTP version"));
    }
    let status = fields
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|s| (100..600).contains(s))
        .ok_or_else(|| error("invalid HTTP status"))?;
    let mut length = None;
    loop {
        let header = line(reader, &mut budget)?;
        if header == b"\r\n" || header == b"\n" {
            break;
        }
        let header = std::str::from_utf8(&header).map_err(|_| error("invalid HTTP header"))?;
        let (name, value) =
            header.trim_end().split_once(':').ok_or_else(|| error("invalid HTTP header"))?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(error("HTTP transfer encoding is unsupported"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(error("duplicate HTTP content length"));
            }
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(error("invalid HTTP content length"));
            }
            let size = value.parse::<usize>().map_err(|_| error("invalid HTTP content length"))?;
            if size > cap {
                return Err(error("HTTP body exceeds budget"));
            }
            length = Some(size);
        }
    }
    let mut left = length.ok_or_else(|| error("missing HTTP content length"))?;
    let mut body = Vec::new();
    let mut buffer = [0; 8192];
    while left != 0 {
        let size = left.min(buffer.len());
        let read = reader.read(&mut buffer[..size])?;
        if read == 0 {
            return Err(error("HTTP body ended early"));
        }
        body.extend_from_slice(&buffer[..read]);
        left -= read;
    }
    if (200..300).contains(&status) {
        Ok(body)
    } else {
        Err(TransportError::HttpStatus {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }
}

pub(crate) fn public_mesh_post(
    target: &crate::contact_egress::PublicTarget,
    request: crate::contact_egress::PublicMeshPost<'_>,
) -> Result<Vec<u8>, TransportError> {
    use crate::contact_egress::public_address;
    if !matches!(
        request.path,
        ramflux_protocol::contact_reach::PEER_QUERY_PATH
            | "/contact/reach/cost/v1"
            | "/s8/federation/envelope"
    ) || request.max_bytes == 0
        || request.max_bytes > 5 * 1024 * 1024
        || request.body.len() > 5 * 1024 * 1024
        || request.peer_ca_pems.is_empty()
        || request.peer_ca_pems.len() > 4
        || request.peer_ca_pems.iter().any(|pem| pem.is_empty() || pem.len() > 64 * 1024)
        || target.addresses().is_empty()
        || target
            .addresses()
            .iter()
            .any(|address| address.port() != 443 || !public_address(address.ip()))
    {
        return Err(error("invalid public mesh exchange"));
    }
    remaining(request.deadline)?;
    let mut anchors = 0_usize;
    for pem in request.peer_ca_pems {
        for certificate in rustls_pemfile::certs(&mut std::io::Cursor::new(pem.as_bytes())) {
            let _certificate = certificate?;
            anchors += 1;
            if anchors > 4 {
                return Err(error("public mesh CA certificate budget"));
            }
        }
    }
    let tls = BoundedHttpTls::new(request.tls, "ramflux-federation", Some(request.peer_ca_pems))?;
    let mut connected = None;
    for address in target.addresses() {
        if let Ok(stream) = TcpStream::connect_timeout(address, remaining(request.deadline)?) {
            connected = Some(stream);
            break;
        }
    }
    let stream = connected.ok_or_else(|| error("public mesh connection failed"))?;
    stream.set_nodelay(true)?;
    let stream = DeadlineTcp { stream, deadline: request.deadline };
    let connection = rustls::ClientConnection::new(tls.config, tls.server_name)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    let certificates = stream
        .conn
        .peer_certificates()
        .ok_or_else(|| error("public mesh server certificate missing"))?;
    if certificates.len() > 4
        || certificates
            .iter()
            .try_fold(0_usize, |total, cert| total.checked_add(cert.len()))
            .is_none_or(|total| total > 64 * 1024)
    {
        return Err(error("public mesh server certificate-chain budget"));
    }
    let uri = stream
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(crate::extract_spiffe_uri_from_certificate)
        .transpose()?
        .flatten();
    if !federation_identity(uri.as_deref(), target.host()) {
        return Err(error("public mesh federation identity mismatch"));
    }
    exchange(
        stream,
        target.host(),
        &BoundedHttpPost {
            endpoint: target.host(),
            path: request.path,
            body: request.body,
            tls: None,
            deadline: request.deadline,
            max_bytes: request.max_bytes,
        },
        "POST",
    )
}
fn federation_identity(uri: Option<&str>, node: &str) -> bool {
    uri.is_some_and(|uri| uri == format!("spiffe://{node}/ramflux-federation"))
}

#[cfg(test)]
mod tests;
