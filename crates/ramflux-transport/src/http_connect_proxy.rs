// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! HTTP CONNECT tunnel (RFC 9110 section 9.3.6) for the stream carriers.
//!
//! The tunnel only moves bytes. TLS 1.3 to the gateway, the pinned CA and the custody exporter
//! all run end to end inside it, so the proxy sees ciphertext and the gateway address it was
//! asked to reach, nothing else. QUIC is never sent through an HTTP proxy.
//!
//! Compiled only with the default-off `http-connect-proxy` feature, and never on Windows.
//! Proxy credentials are never logged: [`ProxyCredentials`] has a redacting `Debug`, no
//! `Display`, and no error produced here carries a request or response header.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::TransportError;

/// Largest accepted proxy response head.
pub const HTTP_CONNECT_MAX_RESPONSE_HEAD_BYTES: usize = 8192;

/// `Basic` proxy credentials. The secret is redacted from `Debug` output.
#[derive(Clone)]
pub struct ProxyCredentials {
    username: String,
    password: String,
}

impl ProxyCredentials {
    /// # Errors
    /// Refuses a user name containing `:` or any control character in either field, which
    /// the `Basic` scheme cannot carry.
    pub fn new(username: String, password: String) -> Result<Self, TransportError> {
        let control = |text: &str| text.chars().any(char::is_control);
        if username.contains(':') || control(&username) || control(&password) {
            return Err(TransportError::Http("proxy credentials are not encodable".to_owned()));
        }
        Ok(Self { username, password })
    }

    fn basic_header_value(&self) -> String {
        let pair = format!("{}:{}", self.username, self.password);
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair))
    }
}

impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProxyCredentials(<redacted>)")
    }
}

/// An HTTP proxy the host configured explicitly. There is no environment or system lookup.
#[derive(Clone, Debug)]
pub struct HttpConnectProxy {
    /// Address of the proxy itself.
    pub proxy_addr: SocketAddr,
    pub credentials: Option<ProxyCredentials>,
}

/// The CONNECT request for `target`. The request target is the authority form, written from
/// the configured gateway address, so the proxy performs no name resolution for the client.
fn connect_request(target: SocketAddr, credentials: Option<&ProxyCredentials>) -> String {
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(credentials) = credentials {
        request.push_str("Proxy-Authorization: ");
        request.push_str(&credentials.basic_header_value());
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request
}

/// Only the status code leaves this function; header lines are never copied into an error.
fn parse_connect_status(head: &[u8]) -> Result<u16, TransportError> {
    let malformed = || TransportError::Http("proxy CONNECT response is malformed".to_owned());
    let line_end = head.windows(2).position(|pair| pair == b"\r\n").ok_or_else(malformed)?;
    let line = std::str::from_utf8(head.get(..line_end).unwrap_or_default())
        .map_err(|_error| malformed())?;
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(malformed());
    }
    let code = parts.next().unwrap_or_default();
    if code.len() != 3 {
        return Err(malformed());
    }
    code.parse::<u16>().map_err(|_error| malformed())
}

impl HttpConnectProxy {
    /// Open a tunnel to the gateway address `target` and return the raw byte stream.
    ///
    /// # Errors
    /// Returns an error when the proxy is unreachable, answers anything other than a 2xx
    /// status, or does not answer within `timeout`.
    pub async fn open_tunnel(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, TransportError> {
        let elapsed = |_elapsed| {
            TransportError::Io(io::Error::new(io::ErrorKind::TimedOut, "proxy CONNECT timed out"))
        };
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(self.proxy_addr))
            .await
            .map_err(elapsed)??;
        let request = connect_request(target, self.credentials.as_ref());
        tokio::time::timeout(timeout, async {
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            // Byte-wise so nothing the tunnel delivers after the head is consumed here.
            let mut head = Vec::with_capacity(256);
            let mut byte = [0_u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if head.len() >= HTTP_CONNECT_MAX_RESPONSE_HEAD_BYTES {
                    return Err(TransportError::Http(
                        "proxy CONNECT response head is too large".to_owned(),
                    ));
                }
                stream.read_exact(&mut byte).await?;
                head.push(byte[0]);
            }
            match parse_connect_status(&head)? {
                // Any 2xx switches the connection to tunnel mode; a 2xx response to CONNECT
                // has no content, so the bytes after the head belong to the tunnel.
                200..=299 => Ok(()),
                status => Err(TransportError::HttpStatus { status, body: String::new() }),
            }
        })
        .await
        .map_err(elapsed)??;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> ProxyCredentials {
        ProxyCredentials::new("alice".to_owned(), "s3cret-value".to_owned())
            .unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn connect_request_uses_the_authority_form_and_a_host_header() {
        let v4 = connect_request(SocketAddr::from(([192, 0, 2, 1], 443)), None);
        assert_eq!(v4, "CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n\r\n");
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap_or_else(|_| unreachable!());
        assert!(connect_request(v6, None).starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
    }

    #[test]
    fn credentials_are_sent_only_in_the_proxy_authorization_header() {
        let request = connect_request(SocketAddr::from(([192, 0, 2, 1], 443)), Some(&credentials()));
        // base64("alice:s3cret-value")
        assert!(request.contains("Proxy-Authorization: Basic YWxpY2U6czNjcmV0LXZhbHVl\r\n"));
        assert!(!request.contains("s3cret-value"));
        assert!(!request.to_ascii_lowercase().contains("\r\nauthorization:"));
    }

    #[test]
    fn credentials_never_appear_in_debug_output() {
        let proxy = HttpConnectProxy {
            proxy_addr: SocketAddr::from(([127, 0, 0, 1], 3128)),
            credentials: Some(credentials()),
        };
        let rendered = format!("{proxy:?} {:?}", credentials());
        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("s3cret-value"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn refused_tunnel_error_carries_only_the_status() {
        let head = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                     Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n";
        assert_eq!(parse_connect_status(head).ok(), Some(407));
        let error = TransportError::HttpStatus { status: 407, body: String::new() };
        assert!(!error.to_string().contains("realm"));
    }

    #[test]
    fn refuses_unencodable_credentials() {
        assert!(ProxyCredentials::new("a:b".to_owned(), "x".to_owned()).is_err());
        assert!(ProxyCredentials::new("a".to_owned(), "x\r\ny".to_owned()).is_err());
    }

    #[test]
    fn malformed_status_lines_are_refused() {
        assert!(parse_connect_status(b"SOCKS 200\r\n\r\n").is_err());
        assert!(parse_connect_status(b"HTTP/1.1 20 OK\r\n\r\n").is_err());
        assert_eq!(parse_connect_status(b"HTTP/1.0 200 Connection established\r\n\r\n").ok(), Some(200));
    }
}
