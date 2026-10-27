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
        Ok(Self { config: Arc::new(config), server_name })
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
        None => exchange(stream, endpoint, &request),
        Some(tls) => {
            let connection =
                rustls::ClientConnection::new(tls.config.clone(), tls.server_name.clone())
                    .map_err(|e| TransportError::Tls(e.to_string()))?;
            let mut stream = rustls::StreamOwned::new(connection, stream);
            while stream.conn.is_handshaking() {
                stream.conn.complete_io(&mut stream.sock)?;
            }
            exchange(stream, endpoint, &request)
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
) -> Result<Vec<u8>, TransportError> {
    let headers = format!(
        "POST {} HTTP/1.1\r\nHost: {endpoint}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
#[cfg(test)]
mod tests;
