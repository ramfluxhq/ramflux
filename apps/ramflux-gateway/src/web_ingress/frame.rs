// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Server side of the RFC 6455 base framing, restricted to what the web listener allows.
//!
//! No extension is ever negotiated, so any RSV bit is a protocol error. Client frames
//! must be masked. Only binary data messages are accepted. The size cap is applied to the
//! running total of fragment lengths from the frame header, before the payload is read.

use super::close::CloseCode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;
/// Control frame payload limit (RFC 6455 §5.5).
const MAX_CONTROL_PAYLOAD: u64 = 125;
/// Fragments accepted for one message.
pub(crate) const MAX_FRAGMENTS_PER_MESSAGE: usize = 64;
/// A partial message must complete within this time of its first fragment.
pub(crate) const FRAGMENT_COMPLETION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10);

/// One complete unit read from the client.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Incoming {
    /// A complete binary message: exactly one gateway frame body.
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    Close,
}

/// Why reading stopped.
#[derive(Debug)]
pub(crate) enum ReadEnd {
    /// The peer broke a rule; close with this code.
    Violation(CloseCode),
    /// The transport ended or failed; there is nobody to send a close to.
    Transport,
}

impl From<std::io::Error> for ReadEnd {
    fn from(_error: std::io::Error) -> Self {
        Self::Transport
    }
}

struct Partial {
    bytes: Vec<u8>,
    fragments: usize,
    deadline: tokio::time::Instant,
}

/// Reassembles client frames into messages under a caller-supplied size cap.
pub(crate) struct MessageReader<R> {
    io: R,
    partial: Option<Partial>,
}

struct Header {
    fin: bool,
    opcode: u8,
    len: u64,
}

impl<R: AsyncRead + Unpin> MessageReader<R> {
    pub(crate) fn new(io: R) -> Self {
        Self { io, partial: None }
    }

    async fn header(&mut self) -> Result<Header, ReadEnd> {
        let mut head = [0_u8; 2];
        self.io.read_exact(&mut head).await?;
        let [first, second] = head;
        if first & 0x70 != 0 {
            return Err(ReadEnd::Violation(CloseCode::ProtocolError));
        }
        // A client must mask every frame (RFC 6455 §5.1).
        if second & 0x80 == 0 {
            return Err(ReadEnd::Violation(CloseCode::ProtocolError));
        }
        let len = match second & 0x7F {
            126 => {
                let mut extended = [0_u8; 2];
                self.io.read_exact(&mut extended).await?;
                let len = u64::from(u16::from_be_bytes(extended));
                if len < 126 {
                    return Err(ReadEnd::Violation(CloseCode::ProtocolError));
                }
                len
            }
            127 => {
                let mut extended = [0_u8; 8];
                self.io.read_exact(&mut extended).await?;
                let len = u64::from_be_bytes(extended);
                if len >> 63 != 0 || len <= u64::from(u16::MAX) {
                    return Err(ReadEnd::Violation(CloseCode::ProtocolError));
                }
                len
            }
            short => u64::from(short),
        };
        Ok(Header { fin: first & 0x80 != 0, opcode: first & 0x0F, len })
    }

    async fn payload(&mut self, len: usize) -> Result<Vec<u8>, ReadEnd> {
        let mut mask = [0_u8; 4];
        self.io.read_exact(&mut mask).await?;
        let mut payload = vec![0_u8; len];
        self.io.read_exact(&mut payload).await?;
        for (byte, key) in payload.iter_mut().zip(mask.iter().cycle()) {
            *byte ^= key;
        }
        Ok(payload)
    }

    async fn frame(&mut self, cap: usize) -> Result<Option<Incoming>, ReadEnd> {
        let header = self.header().await?;
        if header.opcode & 0x8 != 0 {
            if !header.fin || header.len > MAX_CONTROL_PAYLOAD {
                return Err(ReadEnd::Violation(CloseCode::ProtocolError));
            }
            if !matches!(header.opcode, OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG) {
                return Err(ReadEnd::Violation(CloseCode::ProtocolError));
            }
            let len = usize::try_from(header.len)
                .map_err(|_| ReadEnd::Violation(CloseCode::ProtocolError))?;
            let payload = self.payload(len).await?;
            return Ok(Some(match header.opcode {
                OPCODE_PING => Incoming::Ping(payload),
                OPCODE_PONG => Incoming::Pong,
                _ => Incoming::Close,
            }));
        }
        match (header.opcode, self.partial.is_some()) {
            (OPCODE_BINARY, false) | (OPCODE_CONTINUATION, true) => {}
            (OPCODE_TEXT, false) => return Err(ReadEnd::Violation(CloseCode::UnsupportedData)),
            _ => return Err(ReadEnd::Violation(CloseCode::ProtocolError)),
        }
        // Enforce the cap on the running total before a single payload byte is buffered.
        let buffered = self.partial.as_ref().map_or(0, |partial| partial.bytes.len());
        let total = u64::try_from(buffered)
            .ok()
            .and_then(|buffered| buffered.checked_add(header.len))
            .filter(|total| u64::try_from(cap).is_ok_and(|cap| *total <= cap))
            .ok_or(ReadEnd::Violation(CloseCode::MessageTooBig))?;
        let fragments = self.partial.as_ref().map_or(0, |partial| partial.fragments) + 1;
        if fragments > MAX_FRAGMENTS_PER_MESSAGE {
            return Err(ReadEnd::Violation(CloseCode::Policy));
        }
        let len = usize::try_from(header.len)
            .map_err(|_| ReadEnd::Violation(CloseCode::MessageTooBig))?;
        let _ = total;
        let payload = self.payload(len).await?;
        let mut partial = self.partial.take().unwrap_or_else(|| Partial {
            bytes: Vec::new(),
            fragments: 0,
            deadline: tokio::time::Instant::now() + FRAGMENT_COMPLETION_TIMEOUT,
        });
        partial.bytes.extend_from_slice(&payload);
        partial.fragments = fragments;
        if header.fin {
            return Ok(Some(Incoming::Binary(partial.bytes)));
        }
        self.partial = Some(partial);
        Ok(None)
    }

    /// Read until one message or control frame is complete.
    ///
    /// `cap` is read for every frame, so the limit can rise when the session is
    /// established. Not cancellation safe: a caller that abandons this future must close.
    ///
    /// # Errors
    /// Returns the close code for a rule violation, or `Transport` when the stream ended.
    pub(crate) async fn next(&mut self, cap: &(dyn Fn() -> usize + Sync)) -> Result<Incoming, ReadEnd> {
        loop {
            let read = match self.partial.as_ref().map(|partial| partial.deadline) {
                Some(deadline) => tokio::time::timeout_at(deadline, self.frame(cap()))
                    .await
                    .map_err(|_| ReadEnd::Violation(CloseCode::Timeout))?,
                None => self.frame(cap()).await,
            };
            if let Some(incoming) = read? {
                return Ok(incoming);
            }
        }
    }
}

fn encode(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    // FIN set, no RSV bits, never masked: a server must not mask (RFC 6455 §5.1).
    frame.push(0x80 | opcode);
    if let Ok(len) = u8::try_from(payload.len())
        && len < 126
    {
        frame.push(len);
    } else if let Ok(len) = u16::try_from(payload.len()) {
        frame.push(126);
        frame.extend_from_slice(&len.to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

/// Write one unfragmented binary message.
/// # Errors
/// Returns the transport failure.
pub(crate) async fn write_binary<W: AsyncWrite + Unpin>(
    io: &mut W,
    payload: &[u8],
) -> std::io::Result<()> {
    io.write_all(&encode(OPCODE_BINARY, payload)).await?;
    io.flush().await
}

/// Write a control frame; the payload is truncated to the control limit.
async fn write_control<W: AsyncWrite + Unpin>(
    io: &mut W,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let payload = payload.get(..125).unwrap_or(payload);
    io.write_all(&encode(opcode, payload)).await?;
    io.flush().await
}

/// # Errors
/// Returns the transport failure.
pub(crate) async fn write_ping<W: AsyncWrite + Unpin>(io: &mut W) -> std::io::Result<()> {
    write_control(io, OPCODE_PING, &[]).await
}

/// # Errors
/// Returns the transport failure.
pub(crate) async fn write_pong<W: AsyncWrite + Unpin>(
    io: &mut W,
    payload: &[u8],
) -> std::io::Result<()> {
    write_control(io, OPCODE_PONG, payload).await
}

/// # Errors
/// Returns the transport failure.
pub(crate) async fn write_close<W: AsyncWrite + Unpin>(
    io: &mut W,
    code: CloseCode,
) -> std::io::Result<()> {
    write_control(io, OPCODE_CLOSE, &code.payload()).await
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;
