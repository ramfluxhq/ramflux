// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Loopback HTTP transport: base URL checks, the bearer token file, the deadline and the
//! response bound. The HTTP stack is the workspace's `reqwest` (same features as
//! `apps/ramflux-agent-host`).

use crate::error::{config, decode_api_error, protocol, PrxError};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue, IF_MATCH};
use reqwest::{Method, Url, redirect};
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use zeroize::Zeroizing;

/// Per-request deadline unless the caller sets another one.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Response body bound unless the caller sets another one.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
/// A token file larger than this is refused (a token is far smaller).
const MAX_TOKEN_FILE_BYTES: u64 = 4096;

/// Where the daemon is, where its token is, and the request limits.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Must be `http://127.0.0.1:<port>` or `http://[::1]:<port>`.
    pub base_url: String,
    /// File holding the bearer token. On Unix its mode must be exactly 0600.
    pub token_file: PathBuf,
    /// Per-request deadline.
    pub request_timeout: Duration,
    /// Largest response body accepted; a larger one is refused and discarded.
    pub max_body_bytes: usize,
}

impl ClientConfig {
    /// A configuration with the default deadline and body bound.
    pub fn new(base_url: impl Into<String>, token_file: impl Into<PathBuf>) -> Self {
        Self {
            base_url: base_url.into(),
            token_file: token_file.into(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Replaces the per-request deadline.
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Replaces the response body bound.
    #[must_use]
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }
}

/// A complete response: status and the bounded body.
pub(crate) struct Raw {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

/// The HTTP side of a client: one connection pool, one token, the limits.
pub(crate) struct Transport {
    http: reqwest::Client,
    base: Url,
    token_file: PathBuf,
    token: Mutex<Zeroizing<String>>,
    request_timeout: Duration,
    max_body_bytes: usize,
}

impl Transport {
    pub(crate) fn new(settings: &ClientConfig) -> Result<Self, PrxError> {
        let base = validate_base_url(&settings.base_url)?;
        let token = load_token(&settings.token_file)?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|_| config("HTTP client could not be built"))?;
        Ok(Self {
            http,
            base,
            token_file: settings.token_file.clone(),
            token: Mutex::new(token),
            request_timeout: settings.request_timeout,
            max_body_bytes: settings.max_body_bytes,
        })
    }

    /// Sends one request. A 401 re-reads the token file once and retries once (rotation).
    /// Returns the body of a 2xx answer; any other status becomes an error.
    pub(crate) async fn call(
        &self,
        method: Method,
        path: &str,
        if_match: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Raw, PrxError> {
        let mut raw = self.send_once(&method, path, if_match, body).await?;
        if raw.status == 401 {
            self.reload_token()?;
            raw = self.send_once(&method, path, if_match, body).await?;
        }
        if (200..300).contains(&raw.status) {
            Ok(raw)
        } else {
            Err(decode_api_error(raw.status, &raw.body))
        }
    }

    async fn send_once(
        &self,
        method: &Method,
        path: &str,
        if_match: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Raw, PrxError> {
        let url = self.base.join(path).map_err(|_| config("request path is invalid"))?;
        let mut request = self
            .http
            .request(method.clone(), url)
            .timeout(self.request_timeout)
            .header(AUTHORIZATION, self.authorization()?)
            .header(ACCEPT, "application/json");
        if let Some(revision) = if_match {
            let value = HeaderValue::from_str(revision)
                .map_err(|_| config("revision is not a header value"))?;
            request = request.header(IF_MATCH, value);
        }
        if let Some(payload) = body {
            let bytes = serde_json::to_vec(payload).map_err(|_| protocol("request body could not be encoded"))?;
            request = request.header(CONTENT_TYPE, "application/json").body(bytes);
        }
        let mut response = request.send().await.map_err(map_transport_error)?;
        let status = response.status().as_u16();
        let mut raw_body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_transport_error)? {
            if raw_body.len().saturating_add(chunk.len()) > self.max_body_bytes {
                return Err(protocol("response body exceeds the client bound"));
            }
            raw_body.extend_from_slice(&chunk);
        }
        Ok(Raw {
            status,
            body: raw_body,
        })
    }

    fn authorization(&self) -> Result<HeaderValue, PrxError> {
        let token = self.token.lock().map_err(|_| config("token lock is poisoned"))?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(7 + token.len()));
        bytes.extend_from_slice(b"Bearer ");
        bytes.extend_from_slice(token.as_bytes());
        let mut value = HeaderValue::from_bytes(&bytes).map_err(|_| config("token is not a valid header value"))?;
        value.set_sensitive(true);
        Ok(value)
    }

    fn reload_token(&self) -> Result<(), PrxError> {
        let fresh = load_token(&self.token_file)?;
        let mut slot = self.token.lock().map_err(|_| config("token lock is poisoned"))?;
        *slot = fresh;
        Ok(())
    }
}

fn map_transport_error(error: reqwest::Error) -> PrxError {
    if error.is_timeout() {
        PrxError::Timeout
    } else {
        PrxError::Unavailable
    }
}

/// Accepts only `http://127.0.0.1:<port>` or `http://[::1]:<port>`, with no path, query,
/// fragment or userinfo. Port 0 is refused.
pub(crate) fn validate_base_url(raw: &str) -> Result<Url, PrxError> {
    let url = Url::parse(raw).map_err(|_| config("base URL does not parse"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
    let plain = url.scheme() == "http"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && matches!(url.path(), "" | "/");
    let port_ok = url.port_or_known_default().is_some_and(|port| port != 0);
    if loopback && plain && port_ok {
        Ok(url)
    } else {
        Err(config("base URL must be http://127.0.0.1:<port> or http://[::1]:<port>"))
    }
}

/// Reads the bearer token. On Unix the file mode must be exactly 0600. The value is trimmed
/// and returned in `Zeroizing`.
pub(crate) fn load_token(path: &Path) -> Result<Zeroizing<String>, PrxError> {
    let metadata = std::fs::metadata(path).map_err(|_| config("token file is not readable"))?;
    if !metadata.is_file() {
        return Err(config("token path is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(config("token file mode must be 0600"));
        }
    }
    let file = File::open(path).map_err(|_| config("token file cannot be opened"))?;
    let mut limited = file.take(MAX_TOKEN_FILE_BYTES + 1);
    let mut raw = Zeroizing::new(Vec::new());
    limited
        .read_to_end(&mut raw)
        .map_err(|_| config("token file cannot be read"))?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_TOKEN_FILE_BYTES {
        return Err(config("token file is too large"));
    }
    let text = std::str::from_utf8(&raw).map_err(|_| config("token file is not UTF-8"))?;
    let token = text.trim();
    if token.is_empty() {
        return Err(config("token file is empty"));
    }
    Ok(Zeroizing::new(token.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ApiCode;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const CAPS_BODY: &str = r#"{"prx_version":"0.8.171","commit":"unknown","api":1,"capabilities":["agent_crud_v1"],"available":[]}"#;
    const MAX_TEST_HEAD: usize = 8192;

    fn write_token(path: &Path, content: &str) {
        std::fs::write(path, content).expect("test: write token file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("test: chmod token");
        }
    }

    async fn read_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut buf = [0_u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < MAX_TEST_HEAD {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => head.extend_from_slice(buf.get(..n).unwrap_or(&[])),
            }
        }
        String::from_utf8_lossy(&head).to_ascii_lowercase()
    }

    /// Answers `connections` requests; the handler sees the lowercased request head.
    async fn serve(handler: fn(&str) -> (u16, String), connections: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("test: bind loopback");
        let addr = listener.local_addr().expect("test: local addr");
        tokio::spawn(async move {
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let head = read_head(&mut stream).await;
                let (status, body) = handler(&head);
                let response = format!(
                    "HTTP/1.1 {status} TEST\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        addr
    }

    fn transport_at(addr: SocketAddr, token_file: &Path) -> Result<Transport, PrxError> {
        let settings = ClientConfig::new(format!("http://{addr}"), token_file)
            .with_request_timeout(Duration::from_secs(5));
        Transport::new(&settings)
    }

    #[test]
    fn base_url_accepts_only_loopback_literals() {
        for good in ["http://127.0.0.1:4141", "http://[::1]:4141"] {
            assert!(validate_base_url(good).is_ok(), "loopback literal must be accepted: {good}");
        }
        for bad in [
            "http://localhost:4141",
            "http://10.0.0.1:4141",
            "https://127.0.0.1:4141",
            "http://127.0.0.1:0",
            "http://user:pw@127.0.0.1:4141",
            "http://127.0.0.1:4141/api",
            "http://127.0.0.1:4141/?q=1",
            "not a url",
        ] {
            assert!(
                matches!(validate_base_url(bad), Err(PrxError::Config { .. })),
                "non-loopback or malformed base URL must be refused: {bad}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn token_file_mode_must_be_exactly_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let path = dir.path().join("token");
        std::fs::write(&path, "tok-value\n").expect("test: write token");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("test: chmod");
        assert!(matches!(load_token(&path), Err(PrxError::Config { .. })), "0644 must be refused");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("test: chmod");
        let token = load_token(&path).expect("test: 0600 token loads");
        assert_eq!(token.as_str(), "tok-value", "token is trimmed of the trailing newline");
    }

    #[test]
    fn empty_and_oversized_token_files_are_refused() {
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let path = dir.path().join("token");
        write_token(&path, " \n");
        assert!(matches!(load_token(&path), Err(PrxError::Config { .. })), "blank token must be refused");
        write_token(&path, &"x".repeat(usize::try_from(MAX_TOKEN_FILE_BYTES).unwrap_or(4096) + 1));
        assert!(matches!(load_token(&path), Err(PrxError::Config { .. })), "oversized token must be refused");
    }

    #[tokio::test]
    async fn response_over_the_bound_is_refused_and_discarded() {
        fn big(_: &str) -> (u16, String) {
            (200, "y".repeat(64))
        }
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let token = dir.path().join("token");
        write_token(&token, "tok");
        let addr = serve(big, 1).await;
        let settings = ClientConfig::new(format!("http://{addr}"), &token).with_max_body_bytes(16);
        let transport = Transport::new(&settings).expect("test: transport builds");
        let result = transport.call(Method::GET, "/api/capabilities", None, None).await;
        assert!(matches!(result, Err(PrxError::Protocol { .. })), "over-bound body must be a Protocol error");
    }

    #[tokio::test]
    async fn rotated_token_is_reread_once_after_a_401() {
        fn accept_new(head: &str) -> (u16, String) {
            if head.contains("authorization: bearer new") {
                (200, CAPS_BODY.to_owned())
            } else {
                (401, r#"{"error":{"code":"auth_failed","message":"bad bearer"}}"#.to_owned())
            }
        }
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let token = dir.path().join("token");
        write_token(&token, "old");
        let addr = serve(accept_new, 2).await;
        let transport = transport_at(addr, &token).expect("test: transport builds");
        write_token(&token, "new");
        let raw = transport
            .call(Method::GET, "/api/capabilities", None, None)
            .await
            .expect("test: rotated token is accepted on the retry");
        assert_eq!(raw.status, 200, "retry with the re-read token must succeed");
    }

    #[tokio::test]
    async fn a_401_after_the_reread_is_returned() {
        fn always_401(_: &str) -> (u16, String) {
            (401, r#"{"error":{"code":"auth_failed","message":"bad bearer"}}"#.to_owned())
        }
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let token = dir.path().join("token");
        write_token(&token, "still-bad");
        let addr = serve(always_401, 2).await;
        let transport = transport_at(addr, &token).expect("test: transport builds");
        let result = transport.call(Method::GET, "/api/capabilities", None, None).await;
        assert!(
            matches!(result, Err(PrxError::Api { status: 401, code: ApiCode::AuthFailed, .. })),
            "the 401 is returned after one retry"
        );
    }

    #[tokio::test]
    async fn silent_daemon_hits_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("test: bind loopback");
        let addr = listener.local_addr().expect("test: local addr");
        tokio::spawn(async move {
            if let Ok((_stream, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        let dir = tempfile::TempDir::new().expect("test: temp dir");
        let token = dir.path().join("token");
        write_token(&token, "tok");
        let settings = ClientConfig::new(format!("http://{addr}"), &token)
            .with_request_timeout(Duration::from_millis(200));
        let transport = Transport::new(&settings).expect("test: transport builds");
        let result = transport.call(Method::GET, "/api/capabilities", None, None).await;
        assert!(matches!(result, Err(PrxError::Timeout)), "a silent daemon must hit the deadline");
    }
}
