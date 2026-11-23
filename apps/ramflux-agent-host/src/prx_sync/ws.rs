// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A minimal RFC 6455 client for `GET /api/sync/ws` on loopback, without TLS.

use base64::Engine;
use ramflux_prx_client::SyncDial;
use sha1::Digest;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

const MAX_MESSAGE: usize = 1024 * 1024;
const MAX_CLIENT: usize = 4096;
const HEADER_CAP: usize = 8192;
const READ_TIMEOUT: Duration = Duration::from_secs(45);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) enum Incoming {
    Text(Vec<u8>),
    Close(u16),
}

pub(super) enum WsFail {
    Auth,
    Timeout,
    Closed,
    Protocol,
}

struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

pub(super) struct Socket {
    stream: TcpStream,
    pending: Vec<u8>,
    assembly: Vec<u8>,
    fragments: u8,
    assembling: bool,
}

impl Socket {
    /// Upgrades one loopback TCP connection. `token` is placed only on this request.
    ///
    /// # Errors
    /// Returns [`WsFail::Auth`] on HTTP 401, and [`WsFail::Protocol`] when the accept key mismatches.
    pub(super) async fn open(
        dial: &SyncDial,
        token: &str,
        timeout: Duration,
    ) -> Result<Self, WsFail> {
        let addr = socket_addr(dial).ok_or(WsFail::Protocol)?;
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| WsFail::Timeout)?
            .map_err(|_| WsFail::Closed)?;
        let mut sock = Self {
            stream,
            pending: Vec::new(),
            assembly: Vec::new(),
            fragments: 0,
            assembling: false,
        };
        sock.handshake(dial, token).await?;
        Ok(sock)
    }

    pub(super) async fn send_text(&mut self, text: &str) -> Result<(), WsFail> {
        self.send_frame(0x1, text.as_bytes()).await
    }

    pub(super) async fn close_gracefully(&mut self) {
        let code = 1000_u16.to_be_bytes();
        let _ = self.send_frame_within(0x8, &code, Duration::from_secs(1)).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), self.recv()).await;
    }

    pub(super) async fn recv(&mut self) -> Result<Incoming, WsFail> {
        loop {
            let frame = self.next_frame().await?;
            if frame.opcode >= 0x8 {
                if let Some(code) = self.control(frame).await? {
                    return Ok(Incoming::Close(code));
                }
                continue;
            }
            if let Some(text) = self.data(frame)? {
                return Ok(Incoming::Text(text));
            }
        }
    }

    async fn handshake(&mut self, dial: &SyncDial, token: &str) -> Result<(), WsFail> {
        let mut raw_key = [0_u8; 16];
        random_bytes(&mut raw_key).map_err(|_| WsFail::Protocol)?;
        let key = standard_b64(&raw_key).ok_or(WsFail::Protocol)?;
        let expected = websocket_accept(&key).ok_or(WsFail::Protocol)?;
        let mut request = Zeroizing::new(String::new());
        push_request(&mut request, dial, token, &key)?;
        let write = self.stream.write_all(request.as_bytes());
        tokio::time::timeout(WRITE_TIMEOUT, write)
            .await
            .map_err(|_| WsFail::Timeout)?
            .map_err(|_| WsFail::Closed)?;
        drop(request);
        let head = self.read_head().await?;
        check_upgrade(&head, &expected)
    }

    async fn read_head(&mut self) -> Result<String, WsFail> {
        loop {
            if let Some(head) = split_head(&mut self.pending)? {
                return Ok(head);
            }
            if self.pending.len() > HEADER_CAP {
                return Err(WsFail::Protocol);
            }
            self.fill_one().await?;
        }
    }

    async fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), WsFail> {
        self.send_frame_within(opcode, payload, WRITE_TIMEOUT).await
    }

    async fn send_frame_within(
        &mut self,
        opcode: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<(), WsFail> {
        let mut mask = [0_u8; 4];
        random_bytes(&mut mask).map_err(|_| WsFail::Protocol)?;
        let bytes = encode_client_frame(opcode, payload, mask)?;
        let write = self.stream.write_all(&bytes);
        tokio::time::timeout(timeout, write)
            .await
            .map_err(|_| WsFail::Timeout)?
            .map_err(|_| WsFail::Closed)
    }

    async fn control(&mut self, frame: Frame) -> Result<Option<u16>, WsFail> {
        if !frame.fin || frame.payload.len() > 125 {
            return Err(WsFail::Protocol);
        }
        match frame.opcode {
            0x9 => {
                self.send_frame(0xA, &frame.payload).await?;
                Ok(None)
            }
            0xA => Ok(None),
            0x8 => {
                let code = close_code(&frame.payload)?;
                let _ = self.send_frame(0x8, &code.to_be_bytes()).await;
                Ok(Some(code))
            }
            _ => Err(WsFail::Protocol),
        }
    }

    fn data(&mut self, frame: Frame) -> Result<Option<Vec<u8>>, WsFail> {
        match frame.opcode {
            0x1 => self.begin_text(frame),
            0x0 => self.continue_text(&frame),
            _ => Err(WsFail::Protocol),
        }
    }

    fn begin_text(&mut self, frame: Frame) -> Result<Option<Vec<u8>>, WsFail> {
        if self.assembling || frame.payload.len() > MAX_MESSAGE {
            return Err(WsFail::Protocol);
        }
        if frame.fin {
            return Ok(Some(frame.payload));
        }
        self.assembly = frame.payload;
        self.fragments = 1;
        self.assembling = true;
        Ok(None)
    }

    fn continue_text(&mut self, frame: &Frame) -> Result<Option<Vec<u8>>, WsFail> {
        if !self.assembling || self.fragments >= 32 {
            return Err(WsFail::Protocol);
        }
        if self.assembly.len().saturating_add(frame.payload.len()) > MAX_MESSAGE {
            return Err(WsFail::Protocol);
        }
        self.assembly.extend_from_slice(&frame.payload);
        self.fragments = self.fragments.saturating_add(1);
        if !frame.fin {
            return Ok(None);
        }
        self.assembling = false;
        self.fragments = 0;
        Ok(Some(std::mem::take(&mut self.assembly)))
    }

    async fn next_frame(&mut self) -> Result<Frame, WsFail> {
        let head = self.take(2).await?;
        let b0 = *head.first().ok_or(WsFail::Protocol)?;
        let b1 = *head.get(1).ok_or(WsFail::Protocol)?;
        if b0 & 0x70 != 0 || b1 & 0x80 != 0 {
            return Err(WsFail::Protocol);
        }
        let len = payload_len(b1, self).await?;
        if len > MAX_MESSAGE {
            return Err(WsFail::Protocol);
        }
        let payload = self.take(len).await?;
        Ok(Frame { fin: b0 & 0x80 != 0, opcode: b0 & 0x0f, payload })
    }

    async fn take(&mut self, n: usize) -> Result<Vec<u8>, WsFail> {
        if n > MAX_MESSAGE {
            return Err(WsFail::Protocol);
        }
        while self.pending.len() < n {
            self.fill_one().await?;
        }
        let taken = self.pending.get(..n).ok_or(WsFail::Protocol)?.to_vec();
        self.pending = self.pending.get(n..).ok_or(WsFail::Protocol)?.to_vec();
        Ok(taken)
    }

    async fn fill_one(&mut self) -> Result<(), WsFail> {
        if self.pending.len() > MAX_MESSAGE.saturating_add(HEADER_CAP) {
            return Err(WsFail::Protocol);
        }
        let mut buf = [0_u8; 4096];
        let read = self.stream.read(&mut buf);
        let n = tokio::time::timeout(READ_TIMEOUT, read)
            .await
            .map_err(|_| WsFail::Timeout)?
            .map_err(|_| WsFail::Closed)?;
        if n == 0 {
            return Err(WsFail::Closed);
        }
        self.pending.extend_from_slice(buf.get(..n).ok_or(WsFail::Protocol)?);
        Ok(())
    }
}

async fn payload_len(b1: u8, sock: &mut Socket) -> Result<usize, WsFail> {
    let short = usize::from(b1 & 0x7f);
    if short < 126 {
        return Ok(short);
    }
    if short == 126 {
        let ext = sock.take(2).await?;
        let bytes = <[u8; 2]>::try_from(ext.as_slice()).map_err(|_| WsFail::Protocol)?;
        let len = usize::from(u16::from_be_bytes(bytes));
        if len < 126 { Err(WsFail::Protocol) } else { Ok(len) }
    } else {
        let ext = sock.take(8).await?;
        let bytes = <[u8; 8]>::try_from(ext.as_slice()).map_err(|_| WsFail::Protocol)?;
        let wide = u64::from_be_bytes(bytes);
        if wide < 65536 || wide > u64::try_from(MAX_MESSAGE).unwrap_or(u64::MAX) {
            return Err(WsFail::Protocol);
        }
        usize::try_from(wide).map_err(|_| WsFail::Protocol)
    }
}

fn encode_client_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Result<Vec<u8>, WsFail> {
    if payload.len() > MAX_CLIENT || opcode > 0x0f {
        return Err(WsFail::Protocol);
    }
    let mut masked = payload.to_vec();
    apply_mask(&mut masked, mask);
    let mut out = Vec::with_capacity(payload.len().saturating_add(8));
    out.push(0x80 | opcode);
    if let Ok(len) = u8::try_from(payload.len())
        && len < 126
    {
        out.push(0x80 | len);
        out.extend_from_slice(&mask);
        out.extend_from_slice(&masked);
        return Ok(out);
    }
    let len = u16::try_from(payload.len()).map_err(|_| WsFail::Protocol)?;
    out.push(0x80 | 0x7e);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&mask);
    out.extend_from_slice(&masked);
    Ok(out)
}

fn apply_mask(data: &mut [u8], mask: [u8; 4]) {
    for (index, byte) in data.iter_mut().enumerate() {
        let Some(part) = mask.get(index % 4).copied() else { continue };
        *byte ^= part;
    }
}

fn push_request(out: &mut String, dial: &SyncDial, token: &str, key: &str) -> Result<(), WsFail> {
    if token.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(WsFail::Protocol);
    }
    out.push_str("GET /api/sync/ws HTTP/1.1\r\nHost: ");
    out.push_str(&host_header(dial));
    out.push_str("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    out.push_str(key);
    out.push_str("\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer ");
    out.push_str(token);
    out.push_str("\r\n\r\n");
    Ok(())
}

fn host_header(dial: &SyncDial) -> String {
    if dial.host == "::1" {
        format!("[{}]:{}", dial.host, dial.port)
    } else {
        format!("{}:{}", dial.host, dial.port)
    }
}

fn socket_addr(dial: &SyncDial) -> Option<SocketAddr> {
    if dial.host == "127.0.0.1" {
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dial.port))
    } else if dial.host == "::1" {
        Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), dial.port))
    } else {
        None
    }
}

fn check_upgrade(head: &str, expected: &str) -> Result<(), WsFail> {
    match status_code(head) {
        Some(101) => {}
        Some(401) => return Err(WsFail::Auth),
        _ => return Err(WsFail::Protocol),
    }
    if !header_has_token(head, "upgrade", "websocket")
        || !header_has_token(head, "connection", "upgrade")
    {
        return Err(WsFail::Protocol);
    }
    match header_value(head, "sec-websocket-accept") {
        Some(value) if value == expected => Ok(()),
        _ => Err(WsFail::Protocol),
    }
}

fn status_code(head: &str) -> Option<u16> {
    let line = head.split("\r\n").next()?;
    let mut parts = line.split(' ');
    let version = parts.next()?;
    let code = parts.next()?;
    if version.starts_with("HTTP/1.") { code.parse().ok() } else { None }
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    for line in head.split("\r\n") {
        let Some((key, value)) = line.split_once(':') else { continue };
        if key.eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

fn header_has_token(head: &str, name: &str, token: &str) -> bool {
    header_value(head, name)
        .is_some_and(|value| value.split(',').any(|part| part.trim().eq_ignore_ascii_case(token)))
}

fn split_head(pending: &mut Vec<u8>) -> Result<Option<String>, WsFail> {
    let Some(pos) = pending
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos.saturating_add(4))
    else {
        return Ok(None);
    };
    let head = std::str::from_utf8(pending.get(..pos).ok_or(WsFail::Protocol)?)
        .map_err(|_| WsFail::Protocol)?;
    let text = head.to_owned();
    *pending = pending.get(pos..).ok_or(WsFail::Protocol)?.to_vec();
    Ok(Some(text))
}

fn close_code(payload: &[u8]) -> Result<u16, WsFail> {
    if payload.is_empty() {
        return Ok(1000);
    }
    if payload.len() < 2 {
        return Err(WsFail::Protocol);
    }
    let bytes = <[u8; 2]>::try_from(payload.get(..2).ok_or(WsFail::Protocol)?)
        .map_err(|_| WsFail::Protocol)?;
    let code = u16::from_be_bytes(bytes);
    if matches!(code, 1000..=1003 | 1007..=1011 | 3000..=4999) {
        Ok(code)
    } else {
        Err(WsFail::Protocol)
    }
}

/// Fills `dest` from `/dev/urandom`.
///
/// # Errors
/// Returns an error when the device cannot be read.
pub(super) fn random_bytes(dest: &mut [u8]) -> std::io::Result<()> {
    if dest.len() > 64 {
        return Err(std::io::Error::other("random request is too long"));
    }
    let mut file = std::fs::File::open("/dev/urandom")?;
    std::io::Read::read_exact(&mut file, dest)
}

fn standard_b64(input: &[u8]) -> Option<String> {
    if input.len() > 64 {
        return None;
    }
    Some(base64::engine::general_purpose::STANDARD.encode(input))
}

fn websocket_accept(key: &str) -> Option<String> {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    if key.len() > 128 {
        return None;
    }
    let mut joined = String::with_capacity(key.len().saturating_add(GUID.len()));
    joined.push_str(key);
    joined.push_str(GUID);
    let digest = sha1::Sha1::digest(joined.as_bytes());
    standard_b64(digest.as_ref())
}
