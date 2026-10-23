// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One reader demultiplexes responses while cloned handles issue concurrent requests.

use crate::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as PendingMutex};
use tokio::sync::oneshot;

type Pending =
    Arc<PendingMutex<BTreeMap<String, oneshot::Sender<Result<LocalBusFrame, SdkError>>>>>;

#[derive(Clone)]
pub struct LocalBusClient {
    inner: Arc<ClientConnection>,
}
struct OutboundFrame {
    frame: LocalBusFrame,
    encoded: Vec<u8>,
}

struct ClientConnection {
    outbound: mpsc::Sender<OutboundFrame>,
    pending: Pending,
    next: AtomicU64,
    connected: Arc<AtomicBool>,
    events: Mutex<mpsc::Receiver<LocalBusFrame>>,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

impl LocalBusClient {
    /// # Errors
    /// Returns an error when the Unix socket cannot be opened.
    pub async fn connect(socket_path: impl AsRef<Path>) -> Result<Self, SdkError> {
        let stream = UnixStream::connect(socket_path).await?;
        let (mut reader, mut writer) = stream.into_split();
        let (outbound, mut outbound_rx) = mpsc::channel::<OutboundFrame>(64);
        let (events, event_rx) = mpsc::channel(64);
        let pending: Pending = Arc::new(PendingMutex::new(BTreeMap::new()));
        let connected = Arc::new(AtomicBool::new(true));
        let reader_connected = Arc::clone(&connected);
        let writer_connected = Arc::clone(&connected);
        let (disconnected, mut writer_disconnect) = watch::channel(false);
        let reader_pending = Arc::clone(&pending);
        let reader_task = tokio::spawn(async move {
            loop {
                let frame = match read_local_bus_frame(&mut reader).await {
                    Ok(frame) => frame,
                    Err(error) => {
                        reader_connected.store(false, Ordering::Release);
                        fail_pending(&reader_pending, &error.to_string());
                        break;
                    }
                };
                local_bus_trace(
                    "BUS-CLIENT-RX",
                    format!(
                        "kind={:?} method={} request_id={}",
                        frame.kind, frame.method, frame.request_id
                    ),
                );
                if !matches!(
                    frame.kind,
                    LocalBusFrameKind::Response
                        | LocalBusFrameKind::Error
                        | LocalBusFrameKind::Event
                ) {
                    reader_connected.store(false, Ordering::Release);
                    fail_pending(&reader_pending, "unexpected local bus frame kind");
                    break;
                }
                if frame.kind == LocalBusFrameKind::Event {
                    if events.try_send(frame).is_err() {
                        reader_connected.store(false, Ordering::Release);
                        fail_pending(&reader_pending, "local bus event queue overflow");
                        break;
                    }
                } else if let Ok(mut pending) = reader_pending.lock() {
                    if let Some(reply) = pending.remove(&frame.request_id) {
                        let _ = reply.send(Ok(frame));
                    }
                } else {
                    break;
                }
            }
            reader_connected.store(false, Ordering::Release);
            let _ = disconnected.send(true);
        });
        let writer_pending = Arc::clone(&pending);
        let writer_task = tokio::spawn(async move {
            loop {
                let frame = tokio::select! {
                    _ = writer_disconnect.changed() => break,
                    frame = outbound_rx.recv() => frame,
                };
                let Some(frame) = frame else {
                    break;
                };
                let OutboundFrame { frame, encoded } = frame;
                local_bus_trace(
                    "BUS-CLIENT-TX-IN",
                    format!("method={} request_id={}", frame.method, frame.request_id),
                );
                if let Err(error) =
                    super::io::write_encoded_local_bus_frame(&mut writer, &encoded).await
                {
                    writer_connected.store(false, Ordering::Release);
                    fail_pending(&writer_pending, &error.to_string());
                    break;
                }
                local_bus_trace(
                    "BUS-CLIENT-TX-OUT",
                    format!("method={} request_id={}", frame.method, frame.request_id),
                );
            }
            writer_connected.store(false, Ordering::Release);
            fail_pending(&writer_pending, "local bus writer stopped");
        });
        Ok(Self {
            inner: Arc::new(ClientConnection {
                outbound,
                pending,
                connected,
                next: AtomicU64::new(1),
                events: Mutex::new(event_rx),
                reader: reader_task,
                writer: writer_task,
            }),
        })
    }

    /// # Errors
    /// Returns an error on transport failure, backpressure, or a daemon rejection.
    pub async fn request<T: serde::Serialize>(
        &mut self,
        account_id: Option<String>,
        sdk_api: &str,
        method: &str,
        body: &T,
    ) -> Result<serde_json::Value, SdkError> {
        let id = self
            .inner
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| SdkError::LocalBus("request id exhausted".to_owned()))?;
        self.request_frame(LocalBusFrame::request(
            format!("req_{id}"),
            account_id,
            sdk_api,
            method,
            serde_json::to_value(body)?,
        ))
        .await
    }

    /// Sends a frame with caller-supplied deadline and operation ID.
    ///
    /// # Errors
    /// Rejects duplicate in-flight request IDs, excess concurrency, and daemon errors.
    pub async fn request_frame(&self, frame: LocalBusFrame) -> Result<serde_json::Value, SdkError> {
        let deadline = super::requests::deadline(&frame)?;
        let encoded = super::io::encode_local_bus_frame(&frame)?;
        let (sender, receiver) = oneshot::channel();
        {
            let mut pending = self.inner.pending.lock().map_err(|_| closed())?;
            if !self.inner.connected.load(Ordering::Acquire) {
                return Err(closed());
            }
            if pending.len() >= 64 || pending.contains_key(&frame.request_id) {
                return Err(SdkError::LocalBus(
                    "duplicate request id or in-flight request limit".to_owned(),
                ));
            }
            pending.insert(frame.request_id.clone(), sender);
        }
        let _registration =
            Registration { pending: Arc::clone(&self.inner.pending), id: frame.request_id.clone() };
        let wait = async {
            self.inner
                .outbound
                .send(OutboundFrame { frame, encoded })
                .await
                .map_err(|_| closed())?;
            receiver.await.map_err(|_| closed())?
        };
        let response = if let Some(deadline) = deadline {
            tokio::time::timeout_at(deadline, wait)
                .await
                .map_err(|_| SdkError::LocalBus("request deadline exceeded".to_owned()))??
        } else {
            wait.await?
        };
        if response.kind == LocalBusFrameKind::Error {
            let message = response.error.map_or_else(
                || "unknown local bus error".to_owned(),
                |error| format!("{}: {}", error.code, error.message),
            );
            Err(SdkError::LocalBus(message))
        } else {
            Ok(response.body)
        }
    }

    /// # Errors
    /// Returns an error when the connection or bounded event stream closes.
    pub async fn next_event(&mut self) -> Result<LocalBusFrame, SdkError> {
        let event = self.inner.events.lock().await.recv().await.ok_or_else(closed)?;
        local_bus_trace(
            "BUS-CLIENT-NEXT-EVENT-QUEUED",
            format!("method={} request_id={}", event.method, event.request_id),
        );
        Ok(event)
    }
}

struct Registration {
    pending: Pending,
    id: String,
}
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&self.id);
        }
    }
}
fn fail_pending(pending: &Pending, message: &str) {
    if let Ok(mut pending) = pending.lock() {
        for (_, reply) in std::mem::take(&mut *pending) {
            let _ = reply.send(Err(SdkError::LocalBus(message.to_owned())));
        }
    }
}
fn closed() -> SdkError {
    SdkError::LocalBus("local bus connection closed".to_owned())
}
