// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::perf_metrics::{
    record_mesh_client_connect, record_mesh_client_exchange, record_mesh_client_pool_hit,
    record_mesh_client_pool_idle_eviction, record_mesh_client_pool_miss,
    record_mesh_client_request, record_mesh_client_tls_handshake,
};
use crate::tls_config::{mesh_client_config, mesh_client_config_with_pem_roots};
use crate::{MeshHttpRequest, MeshTlsConfig, MeshTlsServerStream, TransportError};

#[derive(Clone, Copy)]
struct MeshHttpTimeouts {
    connect: Duration,
    total: Duration,
}

impl MeshHttpTimeouts {
    const DEFAULT: Self = Self { connect: Duration::from_secs(5), total: Duration::from_secs(30) };
}

#[derive(Clone, Copy)]
struct MeshHttpClientRequest<'a> {
    method: &'a str,
    endpoint: &'a str,
    path: &'a str,
    tls: &'a MeshTlsConfig,
    server_name: &'a str,
    peer_ca_pems: Option<&'a [String]>,
    body: Option<&'a [u8]>,
    timeouts: MeshHttpTimeouts,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MeshHttpPoolKey {
    endpoint: String,
    server_name: String,
    tls_identity_fingerprint: String,
    root_mode: String,
}

struct MeshHttpPooledConnection {
    stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    created_at: Instant,
}

#[derive(Clone)]
pub struct MeshHttpClient {
    pool: Arc<Mutex<HashMap<MeshHttpPoolKey, Vec<MeshHttpPooledConnection>>>>,
    max_idle_per_peer: usize,
    max_lifetime: Duration,
}

const DEFAULT_MAX_IDLE_PER_PEER: usize = 128;
const DEFAULT_MAX_LIFETIME: Duration = Duration::from_mins(5);

impl Default for MeshHttpClient {
    fn default() -> Self {
        Self {
            pool: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_peer: configured_max_idle_per_peer(),
            max_lifetime: DEFAULT_MAX_LIFETIME,
        }
    }
}

impl MeshHttpClient {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// Returns an error when the JSON request cannot be encoded, the TLS/HTTP
    /// exchange fails, or the response cannot be decoded.
    pub fn post_json<T, R>(
        &self,
        endpoint: &str,
        path: &str,
        tls: &MeshTlsConfig,
        server_name: &str,
        value: &T,
    ) -> Result<R, TransportError>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let body = serde_json::to_vec(value)?;
        let response = self.json_request(MeshHttpClientRequest {
            method: "POST",
            endpoint,
            path,
            tls,
            server_name,
            peer_ca_pems: None,
            body: Some(&body),
            timeouts: MeshHttpTimeouts::DEFAULT,
        })?;
        Ok(serde_json::from_slice(&response)?)
    }

    /// # Errors
    /// Returns an error when the TLS/HTTP exchange or JSON codec fails.
    pub fn get_json<R>(
        &self,
        endpoint: &str,
        path: &str,
        tls: &MeshTlsConfig,
        server_name: &str,
    ) -> Result<R, TransportError>
    where
        R: serde::de::DeserializeOwned,
    {
        let response = self.json_request(MeshHttpClientRequest {
            method: "GET",
            endpoint,
            path,
            tls,
            server_name,
            peer_ca_pems: None,
            body: None,
            timeouts: MeshHttpTimeouts::DEFAULT,
        })?;
        Ok(serde_json::from_slice(&response)?)
    }

    /// # Errors
    /// Returns an error when the JSON request cannot be encoded, the peer CA root cannot be loaded,
    /// the TLS/HTTP exchange fails, or the response cannot be decoded.
    #[allow(clippy::too_many_arguments)]
    pub fn post_json_with_peer_ca_pems<T, R>(
        &self,
        endpoint: &str,
        path: &str,
        tls: &MeshTlsConfig,
        server_name: &str,
        peer_ca_pems: &[String],
        value: &T,
    ) -> Result<R, TransportError>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let body = serde_json::to_vec(value)?;
        let response = self.json_request(MeshHttpClientRequest {
            method: "POST",
            endpoint,
            path,
            tls,
            server_name,
            peer_ca_pems: Some(peer_ca_pems),
            body: Some(&body),
            timeouts: MeshHttpTimeouts::DEFAULT,
        })?;
        Ok(serde_json::from_slice(&response)?)
    }

    fn json_request(&self, request: MeshHttpClientRequest<'_>) -> Result<Vec<u8>, TransportError> {
        let endpoint = normalized_endpoint(request.endpoint);
        record_mesh_client_request();
        let key =
            mesh_http_pool_key(endpoint, request.server_name, request.tls, request.peer_ca_pems);
        let request_bytes =
            mesh_http_request_bytes(request.method, endpoint, request.path, request.body, true)?;
        let (mut connection, reused) = match self.checkout(&key) {
            Some(connection) => (connection, true),
            None => (new_mesh_http_connection(endpoint, &request)?, false),
        };
        let exchange = timed_mesh_http_exchange(&mut connection, &request_bytes);
        match exchange {
            Ok(body) => {
                self.checkin(key, connection);
                Ok(body)
            }
            Err(_error) if reused => {
                close_mesh_client_connection(connection);
                let mut retry = new_mesh_http_connection(endpoint, &request)?;
                let body = timed_mesh_http_exchange(&mut retry, &request_bytes)?;
                self.checkin(key, retry);
                Ok(body)
            }
            Err(error) => {
                close_mesh_client_connection(connection);
                Err(error)
            }
        }
    }

    fn checkout(&self, key: &MeshHttpPoolKey) -> Option<MeshHttpPooledConnection> {
        let mut pool = self.pool.lock().ok()?;
        let Some(connections) = pool.get_mut(key) else {
            record_mesh_client_pool_miss();
            return None;
        };
        let now = Instant::now();
        while let Some(connection) = connections.pop() {
            if now.duration_since(connection.created_at) <= self.max_lifetime {
                record_mesh_client_pool_hit();
                return Some(connection);
            }
            close_mesh_client_connection(connection);
        }
        record_mesh_client_pool_miss();
        None
    }

    fn checkin(&self, key: MeshHttpPoolKey, connection: MeshHttpPooledConnection) {
        let Ok(mut pool) = self.pool.lock() else {
            close_mesh_client_connection(connection);
            return;
        };
        let connections = pool.entry(key).or_default();
        if connections.len() < self.max_idle_per_peer {
            connections.push(connection);
        } else {
            record_mesh_client_pool_idle_eviction();
            close_mesh_client_connection(connection);
        }
    }
}

fn configured_max_idle_per_peer() -> usize {
    std::env::var("RAMFLUX_MESH_HTTP_MAX_IDLE_PER_PEER")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_IDLE_PER_PEER)
}

fn mesh_http_exchange(
    connection: &mut MeshHttpPooledConnection,
    request_bytes: &[u8],
) -> Result<Vec<u8>, TransportError> {
    connection.stream.write_all(request_bytes)?;
    connection.stream.flush()?;
    read_mesh_http_response(&mut connection.stream)
}

fn timed_mesh_http_exchange(
    connection: &mut MeshHttpPooledConnection,
    request_bytes: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let started = Instant::now();
    let result = mesh_http_exchange(connection, request_bytes);
    record_mesh_client_exchange(started.elapsed());
    result
}

fn mesh_http_json_request(
    method: &str,
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    body: Option<&[u8]>,
) -> Result<Vec<u8>, TransportError> {
    mesh_http_json_request_with_timeouts(MeshHttpClientRequest {
        method,
        endpoint,
        path,
        tls,
        server_name,
        peer_ca_pems: None,
        body,
        timeouts: MeshHttpTimeouts::DEFAULT,
    })
}

fn mesh_http_json_request_with_timeouts(
    request: MeshHttpClientRequest<'_>,
) -> Result<Vec<u8>, TransportError> {
    let endpoint = normalized_endpoint(request.endpoint);
    record_mesh_client_request();
    let mut connection = new_mesh_http_connection(endpoint, &request)?;
    let request_bytes =
        mesh_http_request_bytes(request.method, endpoint, request.path, request.body, false)?;
    let response = timed_mesh_http_exchange(&mut connection, &request_bytes);
    close_mesh_client_connection(connection);
    response
}

fn new_mesh_http_connection(
    endpoint: &str,
    request: &MeshHttpClientRequest<'_>,
) -> Result<MeshHttpPooledConnection, TransportError> {
    let connect_started = Instant::now();
    let tcp = connect_mesh_tcp(endpoint, request.timeouts)?;
    record_mesh_client_connect(connect_started.elapsed());
    let tls_server_name = rustls::pki_types::ServerName::try_from(request.server_name.to_owned())
        .map_err(|error| TransportError::InvalidDnsName(error.to_string()))?;
    let client_config = match request.peer_ca_pems {
        Some(root_pems) => mesh_client_config_with_pem_roots(request.tls, root_pems)?,
        None => mesh_client_config(request.tls)?,
    };
    let connection = rustls::ClientConnection::new(Arc::new(client_config), tls_server_name)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    record_mesh_client_tls_handshake();
    Ok(MeshHttpPooledConnection { stream, created_at: Instant::now() })
}

fn close_mesh_client_connection(mut connection: MeshHttpPooledConnection) {
    connection.stream.conn.send_close_notify();
    let _result = connection.stream.flush();
}

fn mesh_http_pool_key(
    endpoint: &str,
    server_name: &str,
    tls: &MeshTlsConfig,
    peer_ca_pems: Option<&[String]>,
) -> MeshHttpPoolKey {
    let root_mode = match peer_ca_pems {
        Some(pems) => format!("peer_ca:{}", stable_hash(&pems.join("\n"))),
        None => format!("local_ca:{}", tls.ca_cert.display()),
    };
    MeshHttpPoolKey {
        endpoint: endpoint.to_owned(),
        server_name: server_name.to_owned(),
        tls_identity_fingerprint: format!(
            "cert={};key={}",
            tls.service_cert.display(),
            tls.service_key.display()
        ),
        root_mode,
    }
}

fn stable_hash(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn write_mesh_response(
    stream: &mut MeshTlsServerStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), TransportError> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

/// # Errors
/// Returns an error when the TLS close notification cannot be flushed.
pub fn close_mesh_server_stream(stream: &mut MeshTlsServerStream) -> Result<(), TransportError> {
    stream.conn.send_close_notify();
    stream.flush()?;
    Ok(())
}

/// # Errors
/// Returns an error when the JSON request cannot be encoded, the TLS/HTTP
/// exchange fails, or the response cannot be decoded.
pub fn mesh_http_post_json<T, R>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    value: &T,
) -> Result<R, TransportError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let body = serde_json::to_vec(value)?;
    let response = mesh_http_json_request("POST", endpoint, path, tls, server_name, Some(&body))?;
    Ok(serde_json::from_slice(&response)?)
}

/// # Errors
/// Returns an error when the JSON request cannot be encoded, the peer CA root cannot be loaded,
/// the TLS/HTTP exchange fails, or the response cannot be decoded.
pub fn mesh_http_post_json_with_peer_ca_pems<T, R>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
    peer_ca_pems: &[String],
    value: &T,
) -> Result<R, TransportError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let body = serde_json::to_vec(value)?;
    let response = mesh_http_json_request_with_timeouts(MeshHttpClientRequest {
        method: "POST",
        endpoint,
        path,
        tls,
        server_name,
        peer_ca_pems: Some(peer_ca_pems),
        body: Some(&body),
        timeouts: MeshHttpTimeouts::DEFAULT,
    })?;
    Ok(serde_json::from_slice(&response)?)
}

fn endpoint_host_port(endpoint: &str) -> Result<(&str, u16), TransportError> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| TransportError::Http(format!("bad endpoint {endpoint}: missing port")))?;
    if host.is_empty() {
        return Err(TransportError::Http(format!("bad endpoint {endpoint}: missing host")));
    }
    let port = port
        .parse::<u16>()
        .map_err(|source| TransportError::Http(format!("bad endpoint {endpoint}: {source}")))?;
    Ok((host, port))
}

fn normalized_endpoint(endpoint: &str) -> &str {
    endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint)
}

fn connect_mesh_tcp(
    endpoint: &str,
    timeouts: MeshHttpTimeouts,
) -> Result<TcpStream, TransportError> {
    let mut last_error = None;
    for addr in endpoint
        .to_socket_addrs()
        .map_err(|source| TransportError::Http(format!("bad endpoint {endpoint}: {source}")))?
    {
        match TcpStream::connect_timeout(&addr, timeouts.connect) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                stream.set_read_timeout(Some(timeouts.total))?;
                stream.set_write_timeout(Some(timeouts.total))?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.map_or_else(
        || TransportError::Http(format!("bad endpoint {endpoint}: no addresses")),
        TransportError::Io,
    ))
}

fn mesh_http_request_bytes(
    method: &str,
    endpoint: &str,
    path: &str,
    body: Option<&[u8]>,
    keep_alive: bool,
) -> Result<Vec<u8>, TransportError> {
    if !path.starts_with('/') {
        return Err(TransportError::Http(format!("bad mesh path {path}: missing leading slash")));
    }
    let (host, port) = endpoint_host_port(endpoint)?;
    let body = body.unwrap_or_default();
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let headers = match method {
        "GET" => format!(
            "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nConnection: {connection}\r\n\r\n"
        ),
        "POST" => format!(
            "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
            body.len()
        ),
        other => return Err(TransportError::Http(format!("unsupported HTTP method {other}"))),
    };
    let mut request = headers.into_bytes();
    request.extend_from_slice(body);
    Ok(request)
}

fn read_mesh_http_response(
    stream: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
) -> Result<Vec<u8>, TransportError> {
    let mut reader = BufReader::new(stream);
    read_mesh_http_response_from_reader(&mut reader)
}

fn read_mesh_http_response_from_reader<R: BufRead>(
    reader: &mut R,
) -> Result<Vec<u8>, TransportError> {
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let mut parts = status_line.split_whitespace();
    let _version =
        parts.next().ok_or_else(|| TransportError::Http("missing HTTP version".to_owned()))?;
    let status_code =
        parts.next().ok_or_else(|| TransportError::Http("missing HTTP status code".to_owned()))?;
    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            content_length =
                Some(value.trim().parse::<usize>().map_err(|source| {
                    TransportError::Http(format!("bad content length: {source}"))
                })?);
        }
    }
    let Some(content_length) = content_length else {
        return Err(TransportError::Http("missing response content length".to_owned()));
    };
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body)?;
    if status_code.starts_with('2') {
        Ok(body)
    } else {
        Err(TransportError::Http(format!("HTTP {status_code}: {}", String::from_utf8_lossy(&body))))
    }
}

/// # Errors
/// Returns an error when the TLS connection, HTTP exchange, or JSON codec fails.
pub fn mesh_http_get_json<R>(
    endpoint: &str,
    path: &str,
    tls: &MeshTlsConfig,
    server_name: &str,
) -> Result<R, TransportError>
where
    R: serde::de::DeserializeOwned,
{
    let response = mesh_http_json_request("GET", endpoint, path, tls, server_name, None)?;
    Ok(serde_json::from_slice(&response)?)
}

/// # Errors
/// Returns an error when the stream cannot be read or the request is malformed.
pub fn read_mesh_http_request<R: Read>(
    reader: &mut R,
) -> Result<Option<MeshHttpRequest>, TransportError> {
    let mut reader = BufReader::new(reader);
    let mut request_line = String::new();
    let bytes = reader.read_line(&mut request_line)?;
    if bytes == 0 {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method =
        parts.next().ok_or_else(|| TransportError::Http("missing method".to_owned()))?.to_owned();
    let path =
        parts.next().ok_or_else(|| TransportError::Http("missing path".to_owned()))?.to_owned();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            content_length = value
                .trim()
                .parse()
                .map_err(|source| TransportError::Http(format!("bad content length: {source}")))?;
        }
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body)?;
    Ok(Some(MeshHttpRequest { method, path, body }))
}

/// # Errors
/// Returns an error when response serialization or socket writes fail.
pub fn write_mesh_json_response<T: serde::Serialize>(
    stream: &mut MeshTlsServerStream,
    status: &str,
    value: &T,
) -> Result<(), TransportError> {
    let body = serde_json::to_vec(value)?;
    write_mesh_response(stream, status, "application/json", &body)
}

/// # Errors
/// Returns an error when socket writes fail.
pub fn write_mesh_text_response(
    stream: &mut MeshTlsServerStream,
    status: &str,
    body: &str,
) -> Result<(), TransportError> {
    write_mesh_response(stream, status, "text/plain; charset=utf-8", body.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use std::path::Path;
    use std::process::Command;

    use crate::{MeshTlsConfig, MeshTlsServer};

    use super::{
        MeshHttpClient, MeshHttpClientRequest, MeshHttpTimeouts, connect_mesh_tcp,
        mesh_http_get_json, mesh_http_json_request_with_timeouts, mesh_http_pool_key,
        mesh_http_post_json_with_peer_ca_pems, mesh_http_request_bytes, read_mesh_http_request,
        read_mesh_http_response_from_reader, write_mesh_json_response,
    };

    #[test]
    fn mesh_request_builder_preserves_endpoint_host_port() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = mesh_http_request_bytes(
            "POST",
            "ramflux-router:7443",
            "/mvp1/identity/register",
            Some(b"{}"),
            true,
        )?;
        let request = String::from_utf8(request)?;
        assert!(request.starts_with("POST /mvp1/identity/register HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: ramflux-router:7443\r\n"));
        assert!(request.contains("\r\nConnection: keep-alive\r\n"));
        Ok(())
    }

    #[test]
    fn mesh_endpoint_rejects_bad_port() {
        let rejected =
            mesh_http_request_bytes("GET", "ramflux-router:not-a-port", "/healthz", None, false);
        assert!(rejected.is_err());
    }

    #[test]
    fn mesh_tcp_client_connect_enables_nodelay() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?.to_string();
        let server = thread::spawn(move || {
            let _accepted = listener.accept();
        });
        let stream = connect_mesh_tcp(&endpoint, MeshHttpTimeouts::DEFAULT)?;
        assert!(stream.nodelay()?);
        drop(stream);
        server.join().map_err(|_| "server thread panicked")?;
        Ok(())
    }

    #[test]
    fn mesh_client_accepts_complete_body_without_tls_close_notify()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut response = std::io::Cursor::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}"
                .to_vec(),
        );
        let body = read_mesh_http_response_from_reader(&mut response)?;
        assert_eq!(body, br#"{"ok":true}"#);
        Ok(())
    }

    #[test]
    fn mesh_server_close_notify_and_client_read_complete_body()
    -> Result<(), Box<dyn std::error::Error>> {
        let server_tls = test_mesh_tls_config("router")?;
        let server = MeshTlsServer::bind("127.0.0.1:0", &server_tls)?;
        let endpoint = server.local_addr()?.to_string();
        let server_thread = thread::spawn(move || -> Result<(), String> {
            let mut accepted =
                server.accept_authenticated().map_err(|error| error.to_string())?.stream;
            let request = read_mesh_http_request(&mut accepted)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "missing request".to_owned())?;
            if request.method != "GET" || request.path != "/healthz" {
                return Err(format!("unexpected request {} {}", request.method, request.path));
            }
            write_mesh_json_response(&mut accepted, "200 OK", &serde_json::json!({"status":"ok"}))
                .map_err(|error| error.to_string())
        });
        let body: serde_json::Value = mesh_http_get_json(
            &endpoint,
            "/healthz",
            &test_mesh_tls_config("gateway")?,
            "ramflux-router",
        )?;
        assert_eq!(body["status"], "ok");
        server_thread.join().map_err(|_| "server thread panicked")??;
        Ok(())
    }

    #[test]
    fn pooled_mesh_client_reuses_same_peer_connection() -> Result<(), Box<dyn std::error::Error>> {
        let server_tls = test_mesh_tls_config("router")?;
        let server = MeshTlsServer::bind("127.0.0.1:0", &server_tls)?;
        let endpoint = server.local_addr()?.to_string();
        let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_accepts = Arc::clone(&accepts);
        let server_thread = thread::spawn(move || -> Result<(), String> {
            server_accepts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut accepted =
                server.accept_authenticated().map_err(|error| error.to_string())?.stream;
            for index in 0..2 {
                let request = read_mesh_http_request(&mut accepted)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "missing request".to_owned())?;
                if request.path != "/healthz" {
                    return Err(format!("unexpected request path {}", request.path));
                }
                write_mesh_json_response(
                    &mut accepted,
                    "200 OK",
                    &serde_json::json!({"status":"ok","index":index}),
                )
                .map_err(|error| error.to_string())?;
            }
            crate::close_mesh_server_stream(&mut accepted).map_err(|error| error.to_string())
        });
        let client = MeshHttpClient::new();
        let client_tls = test_mesh_tls_config("gateway")?;
        let first: serde_json::Value =
            client.get_json(&endpoint, "/healthz", &client_tls, "ramflux-router")?;
        let second: serde_json::Value =
            client.get_json(&endpoint, "/healthz", &client_tls, "ramflux-router")?;
        assert_eq!(first["index"], 0);
        assert_eq!(second["index"], 1);
        server_thread.join().map_err(|_| "server thread panicked")??;
        assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn mesh_pool_key_separates_server_name_and_peer_roots() -> Result<(), Box<dyn std::error::Error>>
    {
        let tls = test_mesh_tls_config("gateway")?;
        let local_router = mesh_http_pool_key("ramflux-router:7443", "ramflux-router", &tls, None);
        let local_federation =
            mesh_http_pool_key("ramflux-router:7443", "ramflux-federation", &tls, None);
        assert_ne!(local_router, local_federation);
        let peer_a =
            vec!["-----BEGIN CERTIFICATE-----\npeer-a\n-----END CERTIFICATE-----".to_owned()];
        let peer_b =
            vec!["-----BEGIN CERTIFICATE-----\npeer-b\n-----END CERTIFICATE-----".to_owned()];
        let pinned_a = mesh_http_pool_key("peer:7443", "ramflux-federation", &tls, Some(&peer_a));
        let pinned_b = mesh_http_pool_key("peer:7443", "ramflux-federation", &tls, Some(&peer_b));
        assert_ne!(pinned_a, pinned_b);
        assert_ne!(local_router, pinned_a);
        Ok(())
    }

    #[test]
    fn mesh_pool_default_idle_capacity_covers_mvp5_baseline_b_concurrency() {
        let client = MeshHttpClient::new();
        assert!(client.max_idle_per_peer >= 96);
    }

    #[test]
    fn pooled_mesh_client_rebuilds_stale_connection() -> Result<(), Box<dyn std::error::Error>> {
        let server_tls = test_mesh_tls_config("router")?;
        let server = MeshTlsServer::bind("127.0.0.1:0", &server_tls)?;
        let endpoint = server.local_addr()?.to_string();
        let server_thread = thread::spawn(move || -> Result<(), String> {
            for index in 0..2 {
                let mut accepted =
                    server.accept_authenticated().map_err(|error| error.to_string())?.stream;
                let request = read_mesh_http_request(&mut accepted)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "missing request".to_owned())?;
                if request.path != "/healthz" {
                    return Err(format!("unexpected request path {}", request.path));
                }
                write_mesh_json_response(
                    &mut accepted,
                    "200 OK",
                    &serde_json::json!({"status":"ok","index":index}),
                )
                .map_err(|error| error.to_string())?;
                crate::close_mesh_server_stream(&mut accepted)
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        });
        let client = MeshHttpClient::new();
        let client_tls = test_mesh_tls_config("gateway")?;
        let first: serde_json::Value =
            client.get_json(&endpoint, "/healthz", &client_tls, "ramflux-router")?;
        let second: serde_json::Value =
            client.get_json(&endpoint, "/healthz", &client_tls, "ramflux-router")?;
        assert_eq!(first["index"], 0);
        assert_eq!(second["index"], 1);
        server_thread.join().map_err(|_| "server thread panicked")??;
        Ok(())
    }

    #[test]
    fn federation_peer_mtls_uses_independent_pinned_ca_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("federation_peer_mtls_uses_independent_pinned_ca_roots")?;
        let node_a = issue_test_ca_and_service_cert(&root, "node-a")?;
        let node_b = issue_test_ca_and_service_cert(&root, "node-b")?;

        let server = MeshTlsServer::bind("127.0.0.1:0", &node_b.tls)?;
        let endpoint = server.local_addr()?.to_string();
        let trusted_client_ca = node_a.ca_pem.clone();
        let server_tls = node_b.tls.clone();
        let server_thread = thread::spawn(move || -> Result<(), String> {
            let mut accepted = server
                .accept_authenticated_with_pem_roots(&server_tls, &[trusted_client_ca])
                .map_err(|error| error.to_string())?
                .stream;
            let request = read_mesh_http_request(&mut accepted)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "missing federation request".to_owned())?;
            if request.path != "/s8/federation/envelope" {
                return Err(format!("unexpected path {}", request.path));
            }
            write_mesh_json_response(&mut accepted, "200 OK", &serde_json::json!({"accepted":true}))
                .map_err(|error| error.to_string())
        });
        let response: serde_json::Value = mesh_http_post_json_with_peer_ca_pems(
            &endpoint,
            "/s8/federation/envelope",
            &node_a.tls,
            "ramflux-federation",
            std::slice::from_ref(&node_b.ca_pem),
            &serde_json::json!({"source_node_id":"node-a","target_node_id":"node-b"}),
        )?;
        assert_eq!(response["accepted"], true);
        server_thread.join().map_err(|_| "server thread panicked")??;

        let wrong_client = issue_test_ca_and_service_cert(&root, "node-c")?;
        let rejecting_server = MeshTlsServer::bind("127.0.0.1:0", &node_b.tls)?;
        let rejecting_endpoint = rejecting_server.local_addr()?.to_string();
        let trusted_client_ca = node_a.ca_pem.clone();
        let server_tls = node_b.tls.clone();
        let reject_thread = thread::spawn(move || {
            rejecting_server
                .accept_authenticated_with_pem_roots(&server_tls, &[trusted_client_ca])
                .is_err()
        });
        let rejected = mesh_http_post_json_with_peer_ca_pems::<_, serde_json::Value>(
            &rejecting_endpoint,
            "/s8/federation/envelope",
            &wrong_client.tls,
            "ramflux-federation",
            &[node_b.ca_pem],
            &serde_json::json!({"source_node_id":"node-c","target_node_id":"node-b"}),
        );
        assert!(rejected.is_err());
        assert!(reject_thread.join().map_err(|_| "reject thread panicked")?);
        Ok(())
    }

    #[test]
    fn federation_server_reads_pinned_peer_roots_after_tcp_accept()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("federation_server_reads_pinned_peer_roots_after_tcp_accept")?;
        let node_a = issue_test_ca_and_service_cert(&root, "node-a")?;
        let node_b = issue_test_ca_and_service_cert(&root, "node-b")?;
        let runtime_roots = Arc::new(Mutex::new(Vec::<String>::new()));

        let server = MeshTlsServer::bind("127.0.0.1:0", &node_b.tls)?;
        let endpoint = server.local_addr()?.to_string();
        let server_tls = node_b.tls.clone();
        let server_roots = Arc::clone(&runtime_roots);
        let server_thread = thread::spawn(move || -> Result<(), String> {
            let mut accepted = server
                .accept_authenticated_with_pem_roots_provider(&server_tls, || {
                    server_roots
                        .lock()
                        .map(|roots| roots.clone())
                        .map_err(|error| crate::TransportError::Http(error.to_string()))
                })
                .map_err(|error| error.to_string())?
                .stream;
            let request = read_mesh_http_request(&mut accepted)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "missing federation request".to_owned())?;
            if request.path != "/s8/federation/envelope" {
                return Err(format!("unexpected path {}", request.path));
            }
            write_mesh_json_response(&mut accepted, "200 OK", &serde_json::json!({"accepted":true}))
                .map_err(|error| error.to_string())
        });

        runtime_roots.lock().map_err(|error| error.to_string())?.push(node_a.ca_pem.clone());
        let response: serde_json::Value = mesh_http_post_json_with_peer_ca_pems(
            &endpoint,
            "/s8/federation/envelope",
            &node_a.tls,
            "ramflux-federation",
            std::slice::from_ref(&node_b.ca_pem),
            &serde_json::json!({"source_node_id":"node-a","target_node_id":"node-b"}),
        )?;
        assert_eq!(response["accepted"], true);
        server_thread.join().map_err(|_| "server thread panicked")??;
        Ok(())
    }

    #[test]
    fn mesh_request_to_unresponsive_endpoint_times_out() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        std::thread::spawn(move || {
            if let Ok((_stream, _peer_addr)) = listener.accept() {
                std::thread::sleep(Duration::from_secs(2));
            }
        });
        let started = Instant::now();
        let tls = test_mesh_tls_config("gateway")?;
        let endpoint = addr.to_string();
        let rejected = mesh_http_json_request_with_timeouts(MeshHttpClientRequest {
            method: "GET",
            endpoint: &endpoint,
            path: "/healthz",
            tls: &tls,
            server_name: "ramflux-router",
            peer_ca_pems: None,
            body: None,
            timeouts: MeshHttpTimeouts {
                connect: Duration::from_millis(50),
                total: Duration::from_millis(100),
            },
        });
        assert!(rejected.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    /// Process-wide shared test CA directory, generated once on first use.
    ///
    /// Both the mesh server (`router`) and client (`gateway`) certificates are
    /// signed by this single CA so mutual TLS trust holds across separate
    /// `test_mesh_tls_config` calls without reading any on-disk deploy certs.
    fn shared_test_ca_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
        static CA_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
        let mut guard = CA_DIR.lock().map_err(|error| error.to_string())?;
        if let Some(dir) = guard.as_ref() {
            return Ok(dir.clone());
        }
        let dir = std::env::temp_dir()
            .join(format!("ramflux_transport_mesh_shared_ca_{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let ca_key = dir.join("ca-key.pem");
        let ca_cert = dir.join("ca.pem");
        if !ca_cert.exists() {
            run_openssl(&["genpkey", "-algorithm", "ED25519", "-out"], &ca_key)?;
            run_openssl(
                &[
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    path_str(&ca_key)?,
                    "-out",
                    path_str(&ca_cert)?,
                    "-days",
                    "30",
                    "-subj",
                    "/CN=Ramflux Test Mesh CA",
                ],
                Path::new(""),
            )?;
        }
        *guard = Some(dir.clone());
        Ok(dir)
    }

    /// Generate a mesh TLS config for `service` at runtime, signed by the shared
    /// process-wide CA so server (`router`) and client (`gateway`) interoperate.
    ///
    /// Layout-independent: requires no on-disk deploy certs, only `openssl`.
    fn test_mesh_tls_config(service: &str) -> Result<MeshTlsConfig, Box<dyn std::error::Error>> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let ca_dir = shared_test_ca_dir()?;
        let ca_cert = ca_dir.join("ca.pem");
        let ca_key = ca_dir.join("ca-key.pem");

        // Unique per-call subdir so concurrently running tests never race on the
        // same on-disk files; the shared CA above is what ties them together.
        let dir = ca_dir.join(format!("{service}_{seq}"));
        std::fs::create_dir_all(&dir)?;
        let service_key = dir.join(format!("{service}-key.pem"));
        let service_csr = dir.join(format!("{service}.csr"));
        let service_cert = dir.join(format!("{service}.pem"));
        let ext = dir.join(format!("{service}.ext"));

        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out"], &service_key)?;
        let subject = format!("/CN=ramflux-{service}");
        run_openssl(
            &[
                "req",
                "-new",
                "-key",
                path_str(&service_key)?,
                "-out",
                path_str(&service_csr)?,
                "-subj",
                &subject,
            ],
            Path::new(""),
        )?;
        std::fs::write(
            &ext,
            format!(
                "subjectAltName = DNS:ramflux-{service}, DNS:localhost\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
            ),
        )?;
        // Unique serial per cert avoids racing on a shared `-CAcreateserial` file.
        let serial = format!("0x{seq:032x}");
        run_openssl(
            &[
                "x509",
                "-req",
                "-in",
                path_str(&service_csr)?,
                "-CA",
                path_str(&ca_cert)?,
                "-CAkey",
                path_str(&ca_key)?,
                "-set_serial",
                &serial,
                "-out",
                path_str(&service_cert)?,
                "-days",
                "30",
                "-extfile",
                path_str(&ext)?,
            ],
            Path::new(""),
        )?;
        Ok(MeshTlsConfig { ca_cert, service_cert, service_key })
    }

    struct TestPeerCerts {
        tls: MeshTlsConfig,
        ca_pem: String,
    }

    fn temp_cert_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "ramflux_transport_{name}_{}_{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn issue_test_ca_and_service_cert(
        root: &Path,
        name: &str,
    ) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir)?;
        let ca_key = dir.join("ca-key.pem");
        let ca_cert = dir.join("ca.pem");
        let service_key = dir.join("federation-key.pem");
        let service_csr = dir.join("federation.csr");
        let service_cert = dir.join("federation.pem");
        let ext = dir.join("federation.ext");
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out"], &ca_key)?;
        run_openssl(
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                path_str(&ca_key)?,
                "-out",
                path_str(&ca_cert)?,
                "-days",
                "30",
                "-subj",
                "/CN=Ramflux Test Federation CA",
            ],
            Path::new(""),
        )?;
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out"], &service_key)?;
        run_openssl(
            &[
                "req",
                "-new",
                "-key",
                path_str(&service_key)?,
                "-out",
                path_str(&service_csr)?,
                "-subj",
                "/CN=ramflux-federation",
            ],
            Path::new(""),
        )?;
        std::fs::write(
            &ext,
            "subjectAltName = DNS:ramflux-federation, DNS:localhost\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n",
        )?;
        run_openssl(
            &[
                "x509",
                "-req",
                "-in",
                path_str(&service_csr)?,
                "-CA",
                path_str(&ca_cert)?,
                "-CAkey",
                path_str(&ca_key)?,
                "-CAcreateserial",
                "-out",
                path_str(&service_cert)?,
                "-days",
                "30",
                "-extfile",
                path_str(&ext)?,
            ],
            Path::new(""),
        )?;
        Ok(TestPeerCerts {
            tls: MeshTlsConfig { ca_cert: ca_cert.clone(), service_cert, service_key },
            ca_pem: std::fs::read_to_string(ca_cert)?,
        })
    }

    fn run_openssl(args: &[&str], output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new("openssl");
        command.args(args);
        if !output_path.as_os_str().is_empty() {
            command.arg(path_str(output_path)?);
        }
        let output = command.output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("openssl failed: {}", String::from_utf8_lossy(&output.stderr)).into())
        }
    }

    fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
        path.to_str().ok_or_else(|| format!("non-utf8 path {}", path.display()).into())
    }
}
