// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One upgraded connection: reader and writer tasks plus the adapters that present
//! binary messages to the existing gateway session code as frames.
//!
//! One binary message is exactly one frame body. The session state machine is the one
//! every native carrier uses; nothing about frame handling is duplicated here.

use super::close::CloseCode;
use super::frame::{Incoming, MessageReader, ReadEnd};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// Server ping cadence and the time a pong may take.
pub(crate) const PING_INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const PONG_TIMEOUT: Duration = Duration::from_secs(20);
/// No application frame from the client for this long ends the connection.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Client pings tolerated per window (non-browser clients only; browsers cannot ping).
const CLIENT_PING_BUDGET: u32 = 4;
const CLIENT_PING_WINDOW: Duration = Duration::from_secs(10);
/// After a Close is sent, the transport is dropped once this passes without a reply.
pub(crate) const CLOSE_LINGER: Duration = Duration::from_secs(2);
const INBOUND_QUEUE: usize = 8;
const OUTBOUND_QUEUE: usize = 64;

/// A unit for the writer task.
#[derive(Debug)]
pub(crate) enum Outgoing {
    Binary(Vec<u8>),
    Pong(Vec<u8>),
    Close(CloseCode),
}

/// State shared by the reader, the writer and the frame adapters of one connection.
#[derive(Default)]
pub(crate) struct Shared {
    /// Set when the gateway `session_established` frame has been queued.
    established: AtomicBool,
    /// Set when the session code tried to send anything else before establishment.
    refused: AtomicBool,
    /// Set by the reader when a pong arrives.
    pong_seen: AtomicBool,
}

impl Shared {
    pub(crate) fn established(&self) -> bool {
        self.established.load(Ordering::Acquire)
    }
    pub(crate) fn refused(&self) -> bool {
        self.refused.load(Ordering::Acquire)
    }
    fn message_cap(&self) -> usize {
        if self.established() {
            super::WEB_SESSION_FRAME_MAX_BYTES
        } else {
            super::WEB_PRE_SESSION_FRAME_MAX_BYTES
        }
    }
}

/// The running connection as the driver sees it.
pub(crate) struct Socket {
    pub(crate) out: mpsc::Sender<Outgoing>,
    pub(crate) shared: Arc<Shared>,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl Socket {
    /// Start the reader and writer for an upgraded stream. The second value yields the
    /// client's complete binary messages in order.
    pub(crate) fn start<R, W>(read: R, write: W) -> (Self, mpsc::Receiver<Vec<u8>>)
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let shared = Arc::new(Shared::default());
        let (frames_tx, frames) = mpsc::channel(INBOUND_QUEUE);
        let (out, out_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let reader = tokio::spawn(read_loop(read, frames_tx, out.clone(), Arc::clone(&shared)));
        let writer = tokio::spawn(write_loop(write, out_rx, Arc::clone(&shared)));
        (Self { out, shared, reader, writer }, frames)
    }

    /// Send the Close, give the peer a moment to answer, then drop the transport.
    pub(crate) async fn close(self, code: Option<CloseCode>) {
        if let Some(code) = code {
            let _ = self.out.send(Outgoing::Close(code)).await;
        }
        drop(self.out);
        let _ = tokio::time::timeout(CLOSE_LINGER, self.writer).await;
        let mut reader = self.reader;
        if tokio::time::timeout(CLOSE_LINGER, &mut reader).await.is_err() {
            reader.abort();
        }
    }
}

async fn read_loop<R: AsyncRead + Unpin>(
    read: R,
    frames: mpsc::Sender<Vec<u8>>,
    out: mpsc::Sender<Outgoing>,
    shared: Arc<Shared>,
) {
    let mut reader = MessageReader::new(read);
    let cap_shared = Arc::clone(&shared);
    let cap = move || cap_shared.message_cap();
    let mut last_application = tokio::time::Instant::now();
    let mut ping_window = tokio::time::Instant::now();
    let mut pings = 0_u32;
    let close = loop {
        let incoming =
            match tokio::time::timeout_at(last_application + IDLE_TIMEOUT, reader.next(&cap)).await
            {
                Ok(Ok(incoming)) => incoming,
                Ok(Err(ReadEnd::Violation(code))) => break Some(code),
                Ok(Err(ReadEnd::Transport)) => break None,
                Err(_idle) => break Some(CloseCode::Timeout),
            };
        match incoming {
            Incoming::Binary(body) => {
                last_application = tokio::time::Instant::now();
                // A bounded queue: a slow session applies backpressure to the TCP read.
                if frames.send(body).await.is_err() {
                    break None;
                }
            }
            Incoming::Ping(payload) => {
                let now = tokio::time::Instant::now();
                if now.duration_since(ping_window) >= CLIENT_PING_WINDOW {
                    ping_window = now;
                    pings = 0;
                }
                pings += 1;
                if pings > CLIENT_PING_BUDGET {
                    break Some(CloseCode::Policy);
                }
                if out.send(Outgoing::Pong(payload)).await.is_err() {
                    break None;
                }
            }
            // An unsolicited pong is harmless; a solicited one clears the writer's wait.
            Incoming::Pong => shared.pong_seen.store(true, Ordering::Release),
            Incoming::Close => break Some(CloseCode::Normal),
        }
    };
    if let Some(code) = close {
        let _ = out.send(Outgoing::Close(code)).await;
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(
    mut write: W,
    mut out: mpsc::Receiver<Outgoing>,
    shared: Arc<Shared>,
) {
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
    let mut awaiting_pong: Option<tokio::time::Instant> = None;
    loop {
        let pong_deadline = awaiting_pong;
        let step = tokio::select! {
            command = out.recv() => match command {
                Some(Outgoing::Binary(body)) => super::frame::write_binary(&mut write, &body).await,
                Some(Outgoing::Pong(payload)) => super::frame::write_pong(&mut write, &payload).await,
                Some(Outgoing::Close(code)) => {
                    let _ = super::frame::write_close(&mut write, code).await;
                    break;
                }
                None => break,
            },
            _ = ping.tick() => {
                shared.pong_seen.store(false, Ordering::Release);
                awaiting_pong = Some(tokio::time::Instant::now() + PONG_TIMEOUT);
                super::frame::write_ping(&mut write).await
            }
            () = async {
                match pong_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                if shared.pong_seen.load(Ordering::Acquire) {
                    awaiting_pong = None;
                    Ok(())
                } else {
                    let _ = super::frame::write_close(&mut write, CloseCode::Timeout).await;
                    break;
                }
            }
        };
        if step.is_err() {
            break;
        }
    }
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut write).await;
}

fn closed() -> ramflux_transport::TransportError {
    ramflux_transport::TransportError::Quic("web gateway connection closed".to_owned())
}

/// What an outgoing session frame is, as far as the carrier needs to know.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outbound {
    /// `session_established`, rewritten to carry the informational carrier name.
    Established(Vec<u8>),
    /// Anything else.
    Other,
}

/// Recognise `session_established` and add `"carrier":"websocket"` to its session object.
#[must_use]
pub(crate) fn classify(frame: &[u8]) -> Outbound {
    let Ok(serde_json::Value::Object(mut object)) = serde_json::from_slice(frame) else {
        return Outbound::Other;
    };
    if object.get("frame_type").and_then(serde_json::Value::as_str) != Some("session_established") {
        return Outbound::Other;
    }
    let carrier = serde_json::Value::String(
        ramflux_protocol::custody::TRANSPORT_KIND_WEBSOCKET.to_owned(),
    );
    if let Some(serde_json::Value::Object(session)) = object.get_mut("session") {
        // The session-push form nests the plain session one level down.
        if let Some(serde_json::Value::Object(inner)) = session.get_mut("session") {
            inner.insert("carrier".to_owned(), carrier);
        } else {
            session.insert("carrier".to_owned(), carrier);
        }
    }
    serde_json::to_vec(&serde_json::Value::Object(object)).map_or(Outbound::Other, Outbound::Established)
}

/// Frame sink of the gateway session over the web connection.
pub(crate) struct WebFrameSink {
    pub(crate) out: mpsc::Sender<Outgoing>,
    pub(crate) shared: Arc<Shared>,
    /// Runs once, when `session_established` is queued.
    pub(crate) on_established: Option<Box<dyn FnOnce() + Send>>,
}

impl ramflux_transport::GatewaySessionFrameSink for WebFrameSink {
    fn send_frame<'a>(
        &'a mut self,
        frame: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>>
    {
        Box::pin(async move {
            let body = if self.shared.established() {
                frame.to_vec()
            } else {
                match classify(frame) {
                    Outbound::Established(body) => {
                        self.shared.established.store(true, Ordering::Release);
                        if let Some(notify) = self.on_established.take() {
                            notify();
                        }
                        body
                    }
                    Outbound::Other => {
                        // Before establishment no error frame is sent on this listener:
                        // the connection is closed with the single authentication code.
                        self.shared.refused.store(true, Ordering::Release);
                        return Err(closed());
                    }
                }
            };
            self.out.send(Outgoing::Binary(body)).await.map_err(|_| closed())
        })
    }

    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        // The driver chooses the close code once the session function returns.
        Ok(())
    }
}

/// Frame source of the gateway session over the web connection.
pub(crate) struct WebFrameSource {
    pub(crate) frames: mpsc::Receiver<Vec<u8>>,
}

impl ramflux_transport::GatewaySessionFrameSource for WebFrameSource {
    fn recv_frame(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>>
    {
        Box::pin(async move { self.frames.recv().await.ok_or_else(closed) })
    }
}

#[cfg(test)]
#[path = "socket_tests.rs"]
mod tests;
