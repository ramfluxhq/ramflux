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
    encoded: zeroize::Zeroizing<Vec<u8>>,
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
            let mut last_seq = 0;
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
                if !route_received(
                    frame,
                    &events,
                    &reader_pending,
                    &reader_connected,
                    &mut last_seq,
                ) {
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
    pub fn request(
        &mut self,
        account_id: Option<String>,
        sdk_api: &str,
        method: &str,
        body: serde_json::Value,
    ) -> impl Future<Output = Result<serde_json::Value, SdkError>> + '_ {
        let id = self
            .inner
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| SdkError::LocalBus("request id exhausted".to_owned()));
        let frame = SecretFrame(LocalBusFrame::request(
            format!("req_{}", id.as_ref().unwrap_or(&0)),
            account_id,
            sdk_api,
            method,
            body,
        ));
        async move {
            id?;
            self.request_owned_frame(frame).await
        }
    }

    /// Sends a frame with caller-supplied deadline and operation ID.
    ///
    /// # Errors
    /// Rejects duplicate in-flight request IDs, excess concurrency, and daemon errors.
    pub fn request_frame(
        &self,
        frame: LocalBusFrame,
    ) -> impl Future<Output = Result<serde_json::Value, SdkError>> + '_ {
        let frame = SecretFrame(frame);
        async move { self.request_owned_frame(frame).await }
    }

    /// Returns the complete daemon response, including typed error details and retry hints.
    ///
    /// Transport failures remain errors; daemon refusals are returned as error frames. Use
    /// this method when an explicit user decision depends on `reason_code` or `details`.
    /// Secret request bodies receive the same erasure protection as `request_frame`.
    ///
    /// # Errors
    /// Rejects duplicate request IDs, excess concurrency, deadlines and connection failures.
    pub fn request_frame_response(
        &self,
        frame: LocalBusFrame,
    ) -> impl Future<Output = Result<LocalBusFrame, SdkError>> + '_ {
        let frame = SecretFrame(frame);
        async move { self.request_owned_response(frame).await }
    }

    async fn request_owned_frame(
        &self,
        protected: SecretFrame,
    ) -> Result<serde_json::Value, SdkError> {
        let response = self.request_owned_response(protected).await?;
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

    async fn request_owned_response(
        &self,
        mut protected: SecretFrame,
    ) -> Result<LocalBusFrame, SdkError> {
        let deadline = super::requests::deadline(&protected.0);
        let encoded = encode_owned_body(&mut protected.0);
        let deadline = deadline?;
        let encoded = encoded?;
        // The queue retains identifiers only; the request value has already been erased.
        let frame = protected.0.clone();
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
        Ok(response)
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

struct SecretFrame(LocalBusFrame);
impl Drop for SecretFrame {
    fn drop(&mut self) {
        super::secrets::wipe(&mut self.0.body);
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

fn route_received(
    frame: LocalBusFrame,
    events: &mpsc::Sender<LocalBusFrame>,
    reader_pending: &Pending,
    reader_connected: &AtomicBool,
    last_seq: &mut u64,
) -> bool {
    if !matches!(
        frame.kind,
        LocalBusFrameKind::Response | LocalBusFrameKind::Error | LocalBusFrameKind::Event
    ) {
        reader_connected.store(false, Ordering::Release);
        fail_pending(reader_pending, "unexpected local bus frame kind");
        return false;
    }
    if frame.kind == LocalBusFrameKind::Event {
        if events.capacity() <= 1 {
            let request = LocalBusFrame::request(
                "client-lagged",
                frame.account_id.clone(),
                "stream",
                "bus.subscribe",
                serde_json::json!({}),
            );
            super::subscription::lagged(events, &request, *last_seq);
            reader_connected.store(false, Ordering::Release);
            fail_pending(
                reader_pending,
                "local bus event queue overflow; resume from applied cursor",
            );
            return false;
        }
        let seq = frame.seq;
        if events.try_send(frame).is_err() {
            reader_connected.store(false, Ordering::Release);
            fail_pending(reader_pending, "local bus event queue overflow");
            return false;
        }
        if let Some(seq) = seq {
            *last_seq = seq;
        }
    } else if let Ok(mut pending) = reader_pending.lock() {
        if let Some(reply) = pending.remove(&frame.request_id) {
            let _ = reply.send(Ok(frame));
        }
    } else {
        return false;
    }
    true
}

fn encode_owned_body(frame: &mut LocalBusFrame) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    let encoded = ramflux_protocol::canonical_json_bytes(frame).map(zeroize::Zeroizing::new);
    super::secrets::wipe(&mut frame.body);
    frame.body = serde_json::Value::Null;
    let encoded = encoded?;
    super::io::checked_frame_len(encoded.len())?;
    Ok(encoded)
}
#[cfg(test)]
mod secret_tests {
    use super::*;
    #[test]
    fn owned_unlock_body_is_erased_after_wire_encoding_and_on_encoding_failure()
    -> Result<(), SdkError> {
        let mut frame = LocalBusFrame::request(
            "secret",
            Some("a".to_owned()),
            "account",
            "account.unlock",
            serde_json::json!({"passphrase":"sensitive unlock text"}),
        );
        let encoded = encode_owned_body(&mut frame)?;
        assert!(String::from_utf8_lossy(&encoded).contains("sensitive unlock text"));
        assert_eq!(frame.body, serde_json::Value::Null);
        frame.body = serde_json::json!({"passphrase":"x".repeat(2*1024*1024)});
        assert!(encode_owned_body(&mut frame).is_err());
        assert_eq!(frame.body, serde_json::Value::Null);
        Ok(())
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    #[test]
    fn local_overflow_reports_actual_delivered_sequence_for_filtered_topics() -> Result<(), SdkError>
    {
        let (tx, mut rx) = mpsc::channel(3);
        let pending = Arc::new(PendingMutex::new(BTreeMap::new()));
        let connected = AtomicBool::new(true);
        let mut last = 0;
        for seq in [10, 40] {
            let frame = LocalBusFrame {
                kind: LocalBusFrameKind::Event,
                seq: Some(seq),
                ..LocalBusFrame::request(
                    "event",
                    Some("a".to_owned()),
                    "stream",
                    "message.received",
                    serde_json::json!({}),
                )
            };
            assert!(route_received(frame, &tx, &pending, &connected, &mut last));
        }
        let frame = LocalBusFrame {
            kind: LocalBusFrameKind::Event,
            seq: Some(90),
            ..LocalBusFrame::request(
                "overflow",
                Some("a".to_owned()),
                "stream",
                "message.received",
                serde_json::json!({}),
            )
        };
        assert!(!route_received(frame, &tx, &pending, &connected, &mut last));
        assert_eq!(rx.try_recv().map_err(|_| closed())?.seq, Some(10));
        assert_eq!(rx.try_recv().map_err(|_| closed())?.seq, Some(40));
        let lagged = rx.try_recv().map_err(|_| closed())?;
        assert_eq!(lagged.method, "stream.lagged");
        assert_eq!(lagged.body["last_delivered_seq"], 40);
        Ok(())
    }
}

#[cfg(test)]
#[path = "contact_error_client_tests.rs"]
mod contact_error_tests;
