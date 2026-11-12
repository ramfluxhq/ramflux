// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native gateway carrier over TCP + TLS 1.3 + WebSocket (RFC 6455).
//!
//! One binary WebSocket message carries exactly one gateway frame body, without the native
//! length prefix. The TLS session is terminated by the gateway and verified against the pinned
//! CA, so this carrier exposes the same TLS 1.3 exporter and certificate pin as the TCP + TLS
//! carrier. A native device therefore keeps the native channel binding on this carrier; this
//! client never sends an `Origin` header, a cookie, or an extension offer, and it does not
//! implement the browser binding mode.

use std::io;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use rustls::pki_types::ServerName;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::quic_gateway::{
    GatewaySessionFrameFuture, GatewaySessionFrameSink, GatewaySessionFrameSource,
    GatewayTcpTlsStream,
};
use crate::{MAX_GATEWAY_FRAME_BYTES, TransportError};

/// The only request target the gateway WebSocket endpoint answers.
pub const GATEWAY_WEBSOCKET_PATH: &str = "/v1/session";
/// The required WebSocket subprotocol token.
pub const GATEWAY_WEBSOCKET_SUBPROTOCOL: &str = "ramflux.gateway_session.v1";
/// ALPN protocol offered on the WebSocket carrier.
pub const GATEWAY_WEBSOCKET_ALPN: &[u8] = b"http/1.1";
/// Largest accepted HTTP response head for the upgrade.
pub const GATEWAY_WEBSOCKET_MAX_RESPONSE_HEAD_BYTES: usize = 8192;
/// Largest number of fragments accepted for one message.
pub const GATEWAY_WEBSOCKET_MAX_FRAGMENTS: usize = 64;

const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_CONTROL_PAYLOAD_BYTES: usize = 125;
const READ_CHUNK_BYTES: usize = 16 * 1024;
const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;
const CLOSE_NORMAL: u16 = 1000;

pub struct WebSocketTlsGatewayClient;

/// A gateway session stream carried as binary WebSocket messages inside TLS 1.3.
pub struct WebSocketTlsGatewayBidiStream {
    stream: GatewayTcpTlsStream,
    /// Bytes read from TLS and not yet parsed.
    inbound: Vec<u8>,
    /// Payload of the message being reassembled.
    message: Vec<u8>,
    in_message: bool,
    fragments: usize,
    /// Encoded frames not yet fully written; survives a cancelled send or receive.
    outbound: Vec<u8>,
    outbound_offset: usize,
    /// Deadline of the read in progress; survives cancellation.
    read_deadline: Option<tokio::time::Instant>,
    timeout: Duration,
}

fn protocol_error(message: &'static str) -> TransportError {
    TransportError::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn timed_out(message: &'static str) -> TransportError {
    TransportError::Io(io::Error::new(io::ErrorKind::TimedOut, message))
}

fn secure_random(buffer: &mut [u8]) -> Result<(), TransportError> {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(buffer)
        .map_err(|_error| TransportError::Tls("secure random source unavailable".to_owned()))
}

/// The `Sec-WebSocket-Accept` value a server must return for `key` (RFC 6455 section 4.2.2).
fn expected_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(ACCEPT_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

fn valid_authority(authority: &str) -> bool {
    !authority.is_empty()
        && authority.len() <= 255
        && authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']'))
}

fn upgrade_request(authority: &str, key: &str) -> String {
    format!(
        "GET {GATEWAY_WEBSOCKET_PATH} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {GATEWAY_WEBSOCKET_SUBPROTOCOL}\r\n\
         \r\n"
    )
}

/// Validate the server's upgrade response head. The head is never echoed into an error.
fn validate_upgrade_response(head: &[u8], key: &str) -> Result<(), TransportError> {
    let head = std::str::from_utf8(head)
        .map_err(|_error| protocol_error("websocket upgrade response is not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut status_parts = status.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    let code = status_parts.next().unwrap_or_default();
    if version != "HTTP/1.1" {
        return Err(protocol_error("websocket upgrade response is not HTTP/1.1"));
    }
    if code != "101" {
        let code = code.parse::<u16>().unwrap_or(0);
        return Err(TransportError::HttpStatus { status: code, body: String::new() });
    }
    let mut upgrade = false;
    let mut connection = false;
    let mut accept = false;
    let mut subprotocol = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(protocol_error("websocket upgrade response has a malformed header"));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade = value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            connection = value.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
            if accept {
                return Err(protocol_error("websocket upgrade response repeats the accept header"));
            }
            accept = value == expected_accept(key);
            if !accept {
                return Err(protocol_error("websocket accept value does not match the key"));
            }
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            subprotocol = value == GATEWAY_WEBSOCKET_SUBPROTOCOL;
            if !subprotocol {
                return Err(protocol_error("websocket server selected a foreign subprotocol"));
            }
        } else if name.eq_ignore_ascii_case("sec-websocket-extensions") {
            // No extension was offered, so any negotiated extension (compression) is a failure.
            return Err(protocol_error("websocket server negotiated an extension"));
        }
    }
    if upgrade && connection && accept && subprotocol {
        Ok(())
    } else {
        Err(protocol_error("websocket upgrade response is incomplete"))
    }
}

/// Encode one client frame. Client frames are always masked (RFC 6455 section 5.3).
fn encode_client_frame(
    opcode: u8,
    payload: &[u8],
    mask: [u8; 4],
    out: &mut Vec<u8>,
) -> Result<(), TransportError> {
    out.push(0x80 | opcode);
    let len = payload.len();
    if len <= MAX_CONTROL_PAYLOAD_BYTES {
        out.push(0x80 | u8::try_from(len).map_err(|_error| TransportError::FrameTooLarge { len })?);
    } else if let Ok(len16) = u16::try_from(len) {
        out.push(0x80 | 126);
        out.extend_from_slice(&len16.to_be_bytes());
    } else {
        let len64 = u64::try_from(len).map_err(|_error| TransportError::FrameTooLarge { len })?;
        out.push(0x80 | 127);
        out.extend_from_slice(&len64.to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().zip(mask.iter().cycle()).map(|(byte, key)| byte ^ key));
    Ok(())
}

/// A parsed server frame header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ServerFrameHeader {
    fin: bool,
    opcode: u8,
    header_len: usize,
    payload_len: usize,
}

/// Parse a server frame header from the start of `bytes`; `Ok(None)` means more bytes are needed.
fn parse_server_frame_header(bytes: &[u8]) -> Result<Option<ServerFrameHeader>, TransportError> {
    let (Some(first), Some(second)) = (bytes.first().copied(), bytes.get(1).copied()) else {
        return Ok(None);
    };
    if first & 0x70 != 0 {
        return Err(protocol_error("websocket frame has a reserved bit set"));
    }
    if second & 0x80 != 0 {
        return Err(protocol_error("websocket server frame is masked"));
    }
    let fin = first & 0x80 != 0;
    let opcode = first & 0x0F;
    let (header_len, payload_len) = match second & 0x7F {
        126 => {
            let Some(raw) = bytes.get(2..4) else { return Ok(None) };
            let mut len = [0_u8; 2];
            len.copy_from_slice(raw);
            (4, usize::from(u16::from_be_bytes(len)))
        }
        127 => {
            let Some(raw) = bytes.get(2..10) else { return Ok(None) };
            let mut len = [0_u8; 8];
            len.copy_from_slice(raw);
            let len = u64::from_be_bytes(len);
            if len & (1 << 63) != 0 {
                return Err(protocol_error("websocket frame length has the top bit set"));
            }
            let len = usize::try_from(len)
                .map_err(|_error| TransportError::FrameTooLarge { len: usize::MAX })?;
            (10, len)
        }
        short => (2, usize::from(short)),
    };
    if opcode >= OPCODE_CLOSE && (!fin || payload_len > MAX_CONTROL_PAYLOAD_BYTES) {
        return Err(protocol_error("websocket control frame is fragmented or too long"));
    }
    Ok(Some(ServerFrameHeader { fin, opcode, header_len, payload_len }))
}

impl WebSocketTlsGatewayClient {
    /// Dial the WebSocket endpoint directly.
    ///
    /// # Errors
    /// Returns an error when the TCP socket, TLS 1.3 handshake, or WebSocket upgrade fails.
    pub async fn connect(
        bind_addr: std::net::SocketAddr,
        peer_addr: std::net::SocketAddr,
        server_name: &str,
        authority: &str,
        ca_cert: &Path,
        timeout: Duration,
    ) -> Result<(Self, WebSocketTlsGatewayBidiStream), TransportError> {
        let tcp = crate::quic_gateway::connect_gateway_tcp(bind_addr, peer_addr, timeout).await?;
        Self::connect_over(tcp, server_name, authority, ca_cert, timeout).await
    }

    /// Run TLS 1.3 and the WebSocket upgrade over an established byte stream to the gateway
    /// (a direct TCP connection, or an HTTP CONNECT tunnel that ends at the gateway).
    ///
    /// # Errors
    /// Returns an error when the TLS 1.3 handshake or the WebSocket upgrade fails.
    pub async fn connect_over(
        tcp: TcpStream,
        server_name: &str,
        authority: &str,
        ca_cert: &Path,
        timeout: Duration,
    ) -> Result<(Self, WebSocketTlsGatewayBidiStream), TransportError> {
        if !valid_authority(authority) {
            return Err(TransportError::InvalidDnsName(
                "websocket authority is not a host[:port]".to_owned(),
            ));
        }
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|error| TransportError::Tls(error.to_string()))?;
        let connector = TlsConnector::from(std::sync::Arc::new(
            crate::tls_config::websocket_gateway_client_config(ca_cert)?,
        ));
        let tls = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
            .await
            .map_err(|_elapsed| timed_out("websocket TLS handshake timed out"))?
            .map_err(TransportError::Io)?;
        let mut stream = tokio_rustls::TlsStream::Client(tls);
        tokio::time::timeout(timeout, upgrade(&mut stream, authority))
            .await
            .map_err(|_elapsed| timed_out("websocket upgrade timed out"))??;
        Ok((
            Self,
            WebSocketTlsGatewayBidiStream {
                stream,
                inbound: Vec::new(),
                message: Vec::new(),
                in_message: false,
                fragments: 0,
                outbound: Vec::new(),
                outbound_offset: 0,
                read_deadline: None,
                timeout,
            },
        ))
    }
}

async fn upgrade(stream: &mut GatewayTcpTlsStream, authority: &str) -> Result<(), TransportError> {
    let mut nonce = [0_u8; 16];
    secure_random(&mut nonce)?;
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);
    stream.write_all(upgrade_request(authority, &key).as_bytes()).await?;
    stream.flush().await?;
    // Read one byte at a time so nothing after the head is consumed from the frame stream.
    let mut head = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= GATEWAY_WEBSOCKET_MAX_RESPONSE_HEAD_BYTES {
            return Err(protocol_error("websocket upgrade response head is too large"));
        }
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    validate_upgrade_response(&head, &key)
}

impl WebSocketTlsGatewayBidiStream {
    fn queue_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), TransportError> {
        let mut mask = [0_u8; 4];
        secure_random(&mut mask)?;
        encode_client_frame(opcode, payload, mask, &mut self.outbound)
    }

    /// Write queued bytes. Progress is recorded after every write, so a cancelled caller
    /// leaves a consistent queue that the next operation continues.
    async fn flush_outbound(&mut self) -> Result<(), TransportError> {
        while self.outbound_offset < self.outbound.len() {
            let pending = self.outbound.get(self.outbound_offset..).unwrap_or_default();
            let written = self.stream.write(pending).await?;
            if written == 0 {
                return Err(TransportError::Io(io::ErrorKind::WriteZero.into()));
            }
            self.outbound_offset = self.outbound_offset.saturating_add(written);
        }
        if !self.outbound.is_empty() {
            self.outbound.clear();
            self.outbound_offset = 0;
            self.stream.flush().await?;
        }
        Ok(())
    }

    /// Consume complete frames from `inbound`. Returns a message when one is complete.
    fn take_message(&mut self, max: usize) -> Result<Option<Vec<u8>>, TransportError> {
        loop {
            let Some(header) = parse_server_frame_header(&self.inbound)? else {
                return Ok(None);
            };
            let is_data = header.opcode < OPCODE_CLOSE;
            if is_data {
                // Refuse on the running total before the crossing fragment is buffered.
                let total = self.message.len().saturating_add(header.payload_len);
                if total > max {
                    return Err(TransportError::FrameTooLarge { len: total });
                }
            }
            let frame_len = header.header_len.saturating_add(header.payload_len);
            if self.inbound.len() < frame_len {
                return Ok(None);
            }
            let payload: Vec<u8> =
                self.inbound.get(header.header_len..frame_len).unwrap_or_default().to_vec();
            self.inbound.drain(..frame_len);
            match header.opcode {
                OPCODE_BINARY | OPCODE_CONTINUATION => {
                    let continuation = header.opcode == OPCODE_CONTINUATION;
                    if continuation != self.in_message {
                        return Err(protocol_error("websocket fragment sequence is invalid"));
                    }
                    self.fragments = self.fragments.saturating_add(1);
                    if self.fragments > GATEWAY_WEBSOCKET_MAX_FRAGMENTS {
                        return Err(protocol_error("websocket message has too many fragments"));
                    }
                    self.message.extend_from_slice(&payload);
                    if header.fin {
                        self.in_message = false;
                        self.fragments = 0;
                        return Ok(Some(std::mem::take(&mut self.message)));
                    }
                    self.in_message = true;
                }
                OPCODE_TEXT => return Err(protocol_error("websocket text message refused")),
                OPCODE_PING => self.queue_frame(OPCODE_PONG, &payload)?,
                OPCODE_PONG => {}
                OPCODE_CLOSE => {
                    return Err(TransportError::Io(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "websocket closed by the gateway",
                    )));
                }
                _ => return Err(protocol_error("websocket frame has an unknown opcode")),
            }
        }
    }

    fn has_partial_input(&self) -> bool {
        !self.inbound.is_empty() || self.in_message
    }

    /// Read one message. With `idle`, no deadline runs until the first byte of a message
    /// arrives; a started message must complete within the stream timeout.
    async fn read_message(&mut self, max: usize, idle: bool) -> Result<Vec<u8>, TransportError> {
        loop {
            if let Some(message) = self.take_message(max)? {
                self.read_deadline = None;
                return Ok(message);
            }
            self.flush_outbound().await?;
            let deadline = if idle && !self.has_partial_input() {
                self.read_deadline = None;
                None
            } else {
                let timeout = self.timeout;
                Some(*self.read_deadline.get_or_insert_with(|| tokio::time::Instant::now() + timeout))
            };
            let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
            let read = match deadline {
                None => self.stream.read(&mut chunk).await?,
                Some(deadline) => tokio::time::timeout_at(deadline, self.stream.read(&mut chunk))
                    .await
                    .map_err(|_elapsed| timed_out("websocket frame read timed out"))??,
            };
            if read == 0 {
                return Err(TransportError::Io(io::ErrorKind::UnexpectedEof.into()));
            }
            self.inbound.extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
    }
}

impl GatewaySessionFrameSink for WebSocketTlsGatewayBidiStream {
    fn verify_custody_certificate_pin(&self, expected: &str) -> Result<(), TransportError> {
        crate::verify_custody_peer_certificate(&self.stream, expected)
    }

    fn custody_exporter(&self, nonce: &[u8; 32]) -> Result<[u8; 32], TransportError> {
        crate::custody_tcp_exporter(&self.stream, nonce)
    }

    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move {
            if frame.len() > MAX_GATEWAY_FRAME_BYTES {
                return Err(TransportError::FrameTooLarge { len: frame.len() });
            }
            self.queue_frame(OPCODE_BINARY, frame)?;
            tokio::time::timeout(self.timeout, self.flush_outbound())
                .await
                .map_err(|_elapsed| timed_out("websocket frame write timed out"))?
        })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        // Queued only; it is written by the next operation or dropped with the connection.
        self.queue_frame(OPCODE_CLOSE, &CLOSE_NORMAL.to_be_bytes())
    }
}

impl GatewaySessionFrameSource for WebSocketTlsGatewayBidiStream {
    fn recv_idle_custody_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(self.read_message(ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES, true))
    }

    fn recv_idle_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(self.read_message(MAX_GATEWAY_FRAME_BYTES, true))
    }

    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(self.read_message(MAX_GATEWAY_FRAME_BYTES, false))
    }

    fn recv_custody_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(self.read_message(ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6455 section 1.3 worked example.
    const RFC_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const RFC_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn response(extra: &str) -> String {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {RFC_ACCEPT}\r\n\
             Sec-WebSocket-Protocol: {GATEWAY_WEBSOCKET_SUBPROTOCOL}\r\n{extra}\r\n"
        )
    }

    #[test]
    fn accept_value_matches_the_rfc_6455_example() {
        assert_eq!(expected_accept(RFC_KEY), RFC_ACCEPT);
    }

    #[test]
    fn upgrade_request_has_no_origin_cookie_or_extension_offer() {
        let request = upgrade_request("gw.example.org", RFC_KEY).to_ascii_lowercase();
        assert!(request.starts_with("get /v1/session http/1.1\r\n"));
        assert!(request.contains("sec-websocket-protocol: ramflux.gateway_session.v1\r\n"));
        for forbidden in ["origin:", "cookie:", "authorization:", "sec-websocket-extensions:"] {
            assert!(!request.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn accepts_a_complete_upgrade_response() {
        assert!(validate_upgrade_response(response("").as_bytes(), RFC_KEY).is_ok());
    }

    #[test]
    fn refuses_a_negotiated_extension() {
        let head = response("Sec-WebSocket-Extensions: permessage-deflate\r\n");
        assert!(validate_upgrade_response(head.as_bytes(), RFC_KEY).is_err());
    }

    #[test]
    fn refuses_a_wrong_accept_a_foreign_subprotocol_and_a_non_101_status() {
        let wrong_accept = response("").replace(RFC_ACCEPT, "AAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert!(validate_upgrade_response(wrong_accept.as_bytes(), RFC_KEY).is_err());
        let foreign = response("").replace(GATEWAY_WEBSOCKET_SUBPROTOCOL, "chat");
        assert!(validate_upgrade_response(foreign.as_bytes(), RFC_KEY).is_err());
        let refused = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            validate_upgrade_response(refused.as_bytes(), RFC_KEY),
            Err(TransportError::HttpStatus { status: 403, .. })
        ));
    }

    #[test]
    fn client_frames_are_masked_and_round_trip() {
        let payload = vec![0x5A_u8; 300];
        let mask = [1, 2, 3, 4];
        let mut encoded = Vec::new();
        assert!(encode_client_frame(OPCODE_BINARY, &payload, mask, &mut encoded).is_ok());
        assert_eq!(encoded.first().copied(), Some(0x82));
        assert_eq!(encoded.get(1).copied(), Some(0x80 | 126));
        let body = encoded.get(8..).unwrap_or_default();
        let unmasked: Vec<u8> =
            body.iter().zip(mask.iter().cycle()).map(|(byte, key)| byte ^ key).collect();
        assert_eq!(unmasked, payload);
    }

    #[test]
    fn server_header_parser_refuses_reserved_bits_masks_and_long_control_frames() {
        assert!(parse_server_frame_header(&[0xC2, 0x01]).is_err());
        assert!(parse_server_frame_header(&[0x82, 0x81]).is_err());
        assert!(parse_server_frame_header(&[0x89, 126, 0, 200]).is_err());
        assert!(parse_server_frame_header(&[0x09, 0x00]).is_err());
        assert_eq!(parse_server_frame_header(&[0x82]).ok(), Some(None));
        assert_eq!(
            parse_server_frame_header(&[0x82, 126, 0x01, 0x00]).ok().flatten(),
            Some(ServerFrameHeader { fin: true, opcode: 2, header_len: 4, payload_len: 256 })
        );
    }
}
