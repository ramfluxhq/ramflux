// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The HTTP/1.1 upgrade of the web listener, checked before any frame is read.
//!
//! Only the headers named here are read. `Cookie`, `Authorization`, `Forwarded`,
//! `X-Forwarded-*`, `X-Real-IP`, `Via`, `User-Agent` and `Sec-Fetch-*` are never
//! consulted: the source of every limit is the accepted TCP peer address.

use super::config::WebIngressConfig;
use base64::Engine as _;
use ramflux_protocol::custody::{WEB_SESSION_PATH, WEB_SESSION_SUBPROTOCOL};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The request head must fit in this many bytes.
pub(crate) const MAX_REQUEST_HEAD_BYTES: usize = 8192;
/// The request head must arrive within this time of TLS completion.
pub(crate) const REQUEST_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Fixed GUID of the opening handshake (RFC 6455 §1.3).
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A refused upgrade. The response carries no body and no header beyond the fixed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    BadRequest,
    Forbidden,
    NotFound,
    UpgradeRequired,
    TooManyRequests,
}

impl Refused {
    const fn status_line(self) -> &'static str {
        match self {
            Self::BadRequest => "400 Bad Request",
            Self::Forbidden => "403 Forbidden",
            Self::NotFound => "404 Not Found",
            Self::UpgradeRequired => "426 Upgrade Required",
            Self::TooManyRequests => "429 Too Many Requests",
        }
    }

    /// Never CORS headers, never `Set-Cookie`, never `Sec-WebSocket-*` except the version
    /// hint that RFC 6455 §4.2.2 requires on a version mismatch.
    #[must_use]
    pub(crate) fn response(self) -> String {
        let version = if self == Self::UpgradeRequired { "Sec-WebSocket-Version: 13\r\n" } else { "" };
        format!(
            "HTTP/1.1 {}\r\nConnection: close\r\nContent-Length: 0\r\n{version}\r\n",
            self.status_line()
        )
    }
}

/// An accepted upgrade: the exact origin that matched and the accept token to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Accepted {
    pub(crate) origin: String,
    pub(crate) accept: String,
}

impl Accepted {
    /// No `Sec-WebSocket-Extensions` header is ever sent, so no extension is in effect.
    #[must_use]
    pub(crate) fn response(&self) -> String {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {WEB_SESSION_SUBPROTOCOL}\r\n\r\n",
            self.accept
        )
    }
}

/// Read the request head. `None` means the connection is dropped without a response:
/// the head was too large, the stream ended, or bytes followed the head before the `101`.
pub(crate) async fn read_head<R: AsyncRead + Unpin>(io: &mut R) -> Option<Vec<u8>> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = io.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        head.extend_from_slice(chunk.get(..read)?);
        if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            // A client must not send frames before it has seen the 101.
            return (end + 4 == head.len() && head.len() <= MAX_REQUEST_HEAD_BYTES).then_some(head);
        }
        if head.len() > MAX_REQUEST_HEAD_BYTES {
            return None;
        }
    }
}

fn single<'a>(headers: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    let mut values = headers.iter().filter(|(key, _)| key.eq_ignore_ascii_case(name));
    let value = values.next()?.1;
    values.next().is_none().then_some(value)
}

fn has_token(headers: &[(&str, &str)], name: &str, token: &str, ignore_case: bool) -> bool {
    headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .any(|item| if ignore_case { item.eq_ignore_ascii_case(token) } else { item == token })
}

/// `base64(SHA-1(key || GUID))` (RFC 6455 §4.2.2). SHA-1 is mandated by the protocol and
/// is not a security primitive here.
#[must_use]
pub(crate) fn accept_token(key: &str) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{ACCEPT_GUID}").as_bytes(),
    );
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

/// Check the request in the fixed order of the wire contract; the first failure decides
/// the status. Admission (the `429` step) is applied by the caller afterwards.
///
/// # Errors
/// Returns the status to answer with.
pub(crate) fn check(head: &[u8], config: &WebIngressConfig) -> Result<Accepted, Refused> {
    let head = std::str::from_utf8(head).map_err(|_| Refused::BadRequest)?;
    let head = head.strip_suffix("\r\n\r\n").ok_or(Refused::BadRequest)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(Refused::BadRequest)?;
    let mut headers = Vec::new();
    for line in lines {
        // Obsolete line folding and whitespace before the colon are refused, not repaired.
        let (name, value) = line.split_once(':').ok_or(Refused::BadRequest)?;
        if name.is_empty() || name.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(Refused::BadRequest);
        }
        headers.push((name, value.trim_matches([' ', '\t'])));
    }

    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refused::BadRequest);
    };
    if target.contains('?') {
        return Err(Refused::BadRequest);
    }
    if method != "GET" || version != "HTTP/1.1" || target != WEB_SESSION_PATH {
        return Err(Refused::NotFound);
    }
    // DNS-rebinding guard.
    let host = single(&headers, "Host").ok_or(Refused::BadRequest)?;
    if !config.host_matches(host) {
        return Err(Refused::BadRequest);
    }
    // Exactly one Origin, byte-equal to an allow-list entry. This protects browser users
    // from other pages; it is not authentication.
    let origin = single(&headers, "Origin").ok_or(Refused::Forbidden)?;
    if !config.origin_allowed(origin) {
        return Err(Refused::Forbidden);
    }
    if !has_token(&headers, "Upgrade", "websocket", true)
        || !has_token(&headers, "Connection", "Upgrade", true)
    {
        return Err(Refused::BadRequest);
    }
    match single(&headers, "Sec-WebSocket-Version") {
        Some("13") => {}
        Some(_) => return Err(Refused::UpgradeRequired),
        None => return Err(Refused::BadRequest),
    }
    let key = single(&headers, "Sec-WebSocket-Key").ok_or(Refused::BadRequest)?;
    if base64::engine::general_purpose::STANDARD.decode(key).map_or(true, |nonce| nonce.len() != 16)
    {
        return Err(Refused::BadRequest);
    }
    if !has_token(&headers, "Sec-WebSocket-Protocol", WEB_SESSION_SUBPROTOCOL, false) {
        return Err(Refused::BadRequest);
    }
    // A `Sec-WebSocket-Extensions` offer is ignored: every browser offers
    // permessage-deflate and script cannot turn that off. It is never accepted.
    Ok(Accepted { origin: origin.to_owned(), accept: accept_token(key) })
}

/// Answer a refused upgrade and end the stream.
pub(crate) async fn refuse<W: AsyncWrite + Unpin>(io: &mut W, refused: Refused) {
    let _ = io.write_all(refused.response().as_bytes()).await;
    let _ = io.flush().await;
    let _ = io.shutdown().await;
}

#[cfg(test)]
#[path = "upgrade_tests.rs"]
mod tests;
