// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{NodeCoreError, source_ip_hash};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct NodeHttpRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    pub keep_alive: bool,
    pub source_ip_hash: Option<String>,
    pub pre_auth_cookie: Option<String>,
    pub pre_auth_now: Option<u64>,
}

pub struct NodeHttpResponse {
    pub status_line: String,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

impl NodeHttpResponse {
    #[must_use]
    pub fn status_is_success(&self) -> bool {
        self.status_line.starts_with("HTTP/1.1 2") || self.status_line.starts_with("HTTP/1.0 2")
    }
}

/// Resource limits applied before allocation and across every request read.
#[derive(Clone, Copy)]
pub struct HttpRequestLimits {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub read_timeout: Duration,
    pub request_timeout: Duration,
}
impl Default for HttpRequestLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 1024 * 1024,
            read_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
        }
    }
}
/// # Errors
/// Rejects malformed, oversized or timed-out requests without allocating their declared size.
pub fn read_itest_http_request(
    stream: &mut TcpStream,
) -> Result<Option<NodeHttpRequest>, NodeCoreError> {
    read_itest_http_request_with_timeout(stream, Duration::from_secs(5))
}
/// # Errors
/// Rejects malformed, oversized or timed-out requests; the timeout is per read.
pub fn read_itest_http_request_with_timeout(
    stream: &mut TcpStream,
    read_timeout: Duration,
) -> Result<Option<NodeHttpRequest>, NodeCoreError> {
    match read_http_request_with_limits(
        stream,
        HttpRequestLimits { read_timeout, ..HttpRequestLimits::default() },
        std::time::Instant::now(),
    ) {
        Err(NodeCoreError::HttpRequestRejected { status: "408 Request Timeout" }) => Ok(None),
        other => other,
    }
}
fn rejected(status: &'static str) -> NodeCoreError {
    NodeCoreError::HttpRequestRejected { status }
}
/// Read a bounded request with a whole-request deadline measured from acceptance.
/// # Errors
/// Returns 400 for invalid framing, 413 for limits, 408 for timeouts, or a socket error.
pub fn read_http_request_with_limits(
    stream: &mut TcpStream,
    limits: HttpRequestLimits,
    accepted_at: std::time::Instant,
) -> Result<Option<NodeHttpRequest>, NodeCoreError> {
    let deadline = accepted_at
        .checked_add(limits.request_timeout)
        .ok_or_else(|| rejected("400 Bad Request"))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 512];
    let header_end = loop {
        if let Some(end) = find_http_header_end(&raw) {
            if end + http_header_separator_len(&raw, end) > limits.max_header_bytes {
                return Err(rejected("413 Payload Too Large"));
            }
            break end;
        }
        let space = limits.max_header_bytes.saturating_sub(raw.len()).min(chunk.len());
        if space == 0 {
            return Err(rejected("413 Payload Too Large"));
        }
        let bytes = request_read(stream, &mut chunk[..space], limits.read_timeout, deadline)?;
        if bytes == 0 {
            return if raw.is_empty() { Ok(None) } else { Err(rejected("400 Bad Request")) };
        }
        raw.extend_from_slice(&chunk[..bytes]);
    };
    let header =
        std::str::from_utf8(&raw[..header_end]).map_err(|_| rejected("400 Bad Request"))?;
    let mut lines = header.lines();
    let mut parts = lines.next().ok_or_else(|| rejected("400 Bad Request"))?.split_whitespace();
    let method = parts.next().ok_or_else(|| rejected("400 Bad Request"))?.to_owned();
    let path = parts.next().ok_or_else(|| rejected("400 Bad Request"))?.to_owned();
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) || parts.next().is_some() {
        return Err(rejected("400 Bad Request"));
    }
    let mut content_length = None;
    let mut keep_alive = false;
    let mut pre_auth_cookie = None;
    let mut pre_auth_now = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| rejected("400 Bad Request"))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(rejected("400 Bad Request"));
            }
            let length: u64 = value.parse().map_err(|_| rejected("413 Payload Too Large"))?;
            if length > limits.max_body_bytes as u64 {
                return Err(rejected("413 Payload Too Large"));
            }
            content_length =
                Some(usize::try_from(length).map_err(|_| rejected("413 Payload Too Large"))?);
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(rejected("400 Bad Request"));
        } else if name.eq_ignore_ascii_case("Connection") {
            keep_alive = connection_header_requests_keep_alive(value);
        } else if name.eq_ignore_ascii_case("X-Ramflux-PreAuth-Cookie") {
            pre_auth_cookie = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("X-Ramflux-PreAuth-Now") {
            pre_auth_now = Some(value.parse().map_err(|_| rejected("400 Bad Request"))?);
        }
    }
    let length = content_length.unwrap_or(0);
    let body_start = header_end + http_header_separator_len(&raw, header_end);
    let mut body = raw[body_start..].iter().take(length).copied().collect::<Vec<_>>();
    while body.len() < length {
        let remaining = (length - body.len()).min(chunk.len());
        let bytes = request_read(stream, &mut chunk[..remaining], limits.read_timeout, deadline)?;
        if bytes == 0 {
            return Err(rejected("400 Bad Request"));
        }
        body.extend_from_slice(&chunk[..bytes]);
    }
    if std::time::Instant::now() >= deadline {
        return Err(rejected("408 Request Timeout"));
    }
    Ok(Some(NodeHttpRequest {
        method,
        path,
        body,
        keep_alive,
        source_ip_hash: stream.peer_addr().ok().map(|addr| source_ip_hash(&addr.ip().to_string())),
        pre_auth_cookie,
        pre_auth_now,
    }))
}
fn request_read(
    stream: &mut TcpStream,
    chunk: &mut [u8],
    timeout: Duration,
    deadline: std::time::Instant,
) -> Result<usize, NodeCoreError> {
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| rejected("408 Request Timeout"))?;
    stream
        .set_read_timeout(Some(timeout.min(remaining)))
        .map_err(|error| NodeCoreError::ItestHttp(error.to_string()))?;
    match stream.read(chunk) {
        Ok(bytes) => Ok(bytes),
        Err(error) if is_read_timeout(&error) => Err(rejected("408 Request Timeout")),
        Err(error) => Err(NodeCoreError::ItestHttp(error.to_string())),
    }
}

fn read_until_http_header_end(
    stream: &mut TcpStream,
    raw: &mut Vec<u8>,
) -> Result<Option<usize>, NodeCoreError> {
    let mut chunk = [0_u8; 512];
    loop {
        if let Some(header_end) = find_http_header_end(raw) {
            return Ok(Some(header_end));
        }
        if raw.len() > 64 * 1024 {
            return Err(NodeCoreError::ItestHttp("request header too large".to_owned()));
        }
        let bytes = match stream.read(&mut chunk) {
            Ok(bytes) => bytes,
            Err(error) if is_read_timeout(&error) => return Ok(None),
            Err(error) => return Err(NodeCoreError::ItestHttp(error.to_string())),
        };
        if bytes == 0 {
            return if raw.is_empty() {
                Ok(None)
            } else {
                Err(NodeCoreError::ItestHttp("incomplete request header".to_owned()))
            };
        }
        raw.extend_from_slice(&chunk[..bytes]);
    }
}

fn is_read_timeout(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

fn find_http_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|window| window == b"\n\n"))
}

fn http_header_separator_len(raw: &[u8], header_end: usize) -> usize {
    if raw.get(header_end..header_end + 4) == Some(b"\r\n\r\n") { 4 } else { 2 }
}

/// # Errors
/// Returns an error when the response is malformed or the declared body cannot be read.
pub fn read_http_response_by_content_length(
    stream: &mut TcpStream,
) -> Result<NodeHttpResponse, NodeCoreError> {
    let mut raw = Vec::new();
    let Some(header_end) = read_until_http_header_end(stream, &mut raw)? else {
        return Err(NodeCoreError::ItestHttp("missing response header".to_owned()));
    };
    let header = std::str::from_utf8(&raw[..header_end]).map_err(|source| {
        NodeCoreError::ItestHttp(format!("bad response header utf8: {source}"))
    })?;
    let mut lines = header.lines();
    let status_line =
        lines.next().ok_or_else(|| NodeCoreError::ItestHttp("missing status line".to_owned()))?;
    let mut content_length = None;
    let mut keep_alive = false;
    for line in lines {
        let Some((name, value)) = line.trim_end().split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = Some(value.trim().parse::<usize>().map_err(|source| {
                NodeCoreError::ItestHttp(format!("bad response content length: {source}"))
            })?);
        } else if name.eq_ignore_ascii_case("Connection") {
            keep_alive = connection_header_requests_keep_alive(value.trim());
        }
    }
    let content_length = content_length
        .ok_or_else(|| NodeCoreError::ItestHttp("response missing Content-Length".to_owned()))?;
    let body_start = header_end + http_header_separator_len(&raw, header_end);
    let mut body = raw.get(body_start..).unwrap_or_default().to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0; content_length - body.len()];
        let bytes = match stream.read(&mut chunk) {
            Ok(bytes) => bytes,
            Err(error) if is_read_timeout(&error) => {
                return Err(NodeCoreError::ItestHttp("timed out reading response body".to_owned()));
            }
            Err(error) => return Err(NodeCoreError::ItestHttp(error.to_string())),
        };
        if bytes == 0 {
            return Err(NodeCoreError::ItestHttp("incomplete response body".to_owned()));
        }
        body.extend_from_slice(&chunk[..bytes]);
    }
    body.truncate(content_length);
    Ok(NodeHttpResponse { status_line: status_line.to_owned(), body, keep_alive })
}

fn connection_header_requests_keep_alive(value: &str) -> bool {
    let mut has_keep_alive = false;
    for part in value.split(',') {
        let part = part.trim();
        if part.eq_ignore_ascii_case("close") {
            return false;
        }
        if part.eq_ignore_ascii_case("keep-alive") {
            has_keep_alive = true;
        }
    }
    has_keep_alive
}

/// # Errors
/// Returns an error when response serialization or socket writes fail.
pub fn write_itest_json_response<T: Serialize>(
    stream: &mut TcpStream,
    status: &str,
    value: &T,
) -> Result<(), NodeCoreError> {
    write_itest_json_response_with_connection(stream, status, value, false)
}

/// # Errors
/// Returns an error when response serialization or socket writes fail.
pub fn write_itest_json_response_with_connection<T: Serialize>(
    stream: &mut TcpStream,
    status: &str,
    value: &T,
    keep_alive: bool,
) -> Result<(), NodeCoreError> {
    let body =
        serde_json::to_vec(value).map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    write_itest_response(stream, status, "application/json", &body, keep_alive)
}

/// # Errors
/// Returns an error when socket writes fail.
pub fn write_itest_text_response(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
) -> Result<(), NodeCoreError> {
    write_itest_text_response_with_connection(stream, status, body, false)
}

/// # Errors
/// Returns an error when socket writes fail.
pub fn write_itest_text_response_with_connection(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
    keep_alive: bool,
) -> Result<(), NodeCoreError> {
    write_itest_response(stream, status, "text/plain; charset=utf-8", body.as_bytes(), keep_alive)
}

fn write_itest_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    keep_alive: bool,
) -> Result<(), NodeCoreError> {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
        body.len()
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    stream.write_all(body).map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    stream.flush().map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

/// Write one close-delimited HTTP response within an absolute deadline.
/// Each socket write is also limited to five seconds; partial progress cannot renew the deadline.
/// # Errors
/// Returns an error on an expired deadline, a stalled peer, or a failed socket write.
pub fn write_http_response_with_deadline(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    deadline: std::time::Instant,
) -> Result<(), NodeCoreError> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut response = Vec::with_capacity(header.len() + body.len());
    response.extend_from_slice(header.as_bytes());
    response.extend_from_slice(body);
    let write_deadline = deadline.min(std::time::Instant::now() + Duration::from_secs(5));
    let mut remaining = response.as_slice();
    while !remaining.is_empty() {
        let timeout = write_deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| NodeCoreError::ItestHttp("response write deadline expired".into()))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| NodeCoreError::ItestHttp(error.to_string()))?;
        match stream.write(remaining) {
            Ok(0) => return Err(NodeCoreError::ItestHttp("response write returned zero".into())),
            Ok(count) => remaining = &remaining[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(NodeCoreError::ItestHttp(error.to_string())),
        }
    }
    Ok(())
}

/// Send FIN after a completed response, then briefly drain unread request bytes.
/// The drain uses constant memory and ends at the earlier of 100 ms or the supplied deadline.
/// # Errors
/// Returns an error if the write half cannot be shut down.
pub fn finish_http_response(
    stream: &mut TcpStream,
    deadline: std::time::Instant,
) -> Result<(), NodeCoreError> {
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| NodeCoreError::ItestHttp(error.to_string()))?;
    let deadline = deadline.min(std::time::Instant::now() + Duration::from_millis(100));
    let mut chunk = [0u8; 4096];
    while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    Ok(())
}

/// # Errors
/// Returns an error when the URL is unsupported, the connection fails, or JSON parsing fails.
pub fn itest_http_post_json<T: Serialize, R: serde::de::DeserializeOwned>(
    url: &str,
    value: &T,
) -> Result<R, NodeCoreError> {
    itest_http_json_request("POST", url, Some(value))
}

/// # Errors
/// Returns an error when the URL is unsupported, the connection fails, or JSON parsing fails.
pub fn itest_http_get_json<R: serde::de::DeserializeOwned>(url: &str) -> Result<R, NodeCoreError> {
    itest_http_json_request::<(), R>("GET", url, None)
}

fn itest_http_json_request<T: Serialize, R: serde::de::DeserializeOwned>(
    method: &str,
    url: &str,
    value: Option<&T>,
) -> Result<R, NodeCoreError> {
    let (host_port, path) = parse_http_url(url)?;
    let body = match value {
        Some(value) => serde_json::to_vec(value)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?,
        None => Vec::new(),
    };
    let addr = host_port
        .to_socket_addrs()
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?
        .next()
        .ok_or_else(|| NodeCoreError::ItestHttp(format!("cannot resolve {host_port}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    stream.write_all(&body).map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;

    let response = read_http_response_by_content_length(&mut stream)?;
    parse_json_response(&response)
}

fn parse_http_url(url: &str) -> Result<(&str, &str), NodeCoreError> {
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(NodeCoreError::ItestHttp(format!("unsupported url {url}")));
    };
    let Some((host_port, path)) = rest.split_once('/') else {
        return Ok((rest, "/"));
    };
    Ok((host_port, &url[url.len() - path.len() - 1..]))
}

fn parse_json_response<R: serde::de::DeserializeOwned>(
    response: &NodeHttpResponse,
) -> Result<R, NodeCoreError> {
    if !response.status_is_success() {
        let body = String::from_utf8_lossy(&response.body);
        return Err(NodeCoreError::ItestHttp(format!(
            "non-success response: {} body={body}",
            response.status_line
        )));
    }
    serde_json::from_slice(&response.body)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn itest_http_client_reads_content_length_without_waiting_for_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}/stub", listener.local_addr()?);
        let (response_written_tx, response_written_rx) = mpsc::channel();
        let (release_server_tx, release_server_rx) = mpsc::channel();
        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|source| source.to_string())?;
            let Some(request) =
                read_itest_http_request(&mut stream).map_err(|source| source.to_string())?
            else {
                return Err("missing stub request".to_owned());
            };
            if request.path != "/stub" {
                return Err(format!("unexpected path {}", request.path));
            }
            write_itest_json_response(
                &mut stream,
                "200 OK",
                &serde_json::json!({"accepted": true}),
            )
            .map_err(|source| source.to_string())?;
            response_written_tx.send(()).map_err(|source| source.to_string())?;
            let _ = release_server_rx.recv_timeout(Duration::from_secs(2));
            Ok(())
        });
        let (client_tx, client_rx) = mpsc::channel();
        thread::spawn(move || {
            let result: Result<serde_json::Value, NodeCoreError> =
                itest_http_post_json(&url, &serde_json::json!({"hello": "world"}));
            let _ = client_tx.send(result.map_err(|source| source.to_string()));
        });
        response_written_rx.recv_timeout(Duration::from_secs(2))?;
        let value = if let Ok(result) = client_rx.recv_timeout(Duration::from_millis(500)) {
            result.map_err(|source| -> Box<dyn std::error::Error> { source.into() })?
        } else {
            let _ = release_server_tx.send(());
            let _ = join_stub_server(server);
            return Err("itest HTTP client waited for EOF after Content-Length".into());
        };
        release_server_tx.send(())?;
        join_stub_server(server)?;
        assert_eq!(value.get("accepted").and_then(serde_json::Value::as_bool), Some(true));
        Ok(())
    }

    #[test]
    fn request_limits_reject_huge_lengths_and_read_actual_body_incrementally()
    -> Result<(), Box<dyn std::error::Error>> {
        for (length, expected) in [
            ("18446744073709551615", "413 Payload Too Large"),
            ("9223372036854775000", "413 Payload Too Large"),
            ("invalid", "400 Bad Request"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let mut client = TcpStream::connect(listener.local_addr()?)?;
            let (mut server, _) = listener.accept()?;
            write!(client, "POST /test HTTP/1.1\r\nContent-Length: {length}\r\n\r\n")?;
            let result = read_itest_http_request(&mut server);
            assert!(
                matches!(result, Err(NodeCoreError::HttpRequestRejected { status }) if status == expected)
            );
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        let (mut server, _) = listener.accept()?;
        let payload = vec![b'x'; 4097];
        write!(client, "POST /test HTTP/1.1\r\nContent-Length: {}\r\n\r\n", payload.len())?;
        client.write_all(&payload)?;
        let limits = HttpRequestLimits {
            max_header_bytes: 128,
            max_body_bytes: payload.len(),
            ..HttpRequestLimits::default()
        };
        let request =
            read_http_request_with_limits(&mut server, limits, std::time::Instant::now())?
                .ok_or("request missing")?;
        assert_eq!(request.body, payload);
        Ok(())
    }

    fn join_stub_server(
        server: thread::JoinHandle<Result<(), String>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match server.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(source.into()),
            Err(_) => Err("stub server panicked".into()),
        }
    }
}
