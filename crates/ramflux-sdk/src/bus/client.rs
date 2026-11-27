// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One reader demultiplexes responses while cloned handles issue concurrent requests.

use crate::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as PendingMutex};
use tokio::sync::oneshot;

use super::client_prompt::{PROMPT_METHOD, Prompts};
use crate::custody::pairing::LocalCredentialProvider;

type Pending =
    Arc<PendingMutex<BTreeMap<String, oneshot::Sender<Result<LocalBusFrame, SdkError>>>>>;

/// Answers a provider-key prompt of the daemon (`agent.host.credential`): given the provider id it
/// returns the key, or `None` to refuse. It runs on a blocking thread, so it may read a terminal
/// or a keychain. The key goes straight into the private 0xC1 reply and never into a JSON frame.
pub type HostKeyProvider =
    Arc<dyn Fn(&str) -> Option<zeroize::Zeroizing<String>> + Send + Sync + 'static>;

type HostKeySlot = Arc<PendingMutex<Option<HostKeyProvider>>>;

#[derive(Clone)]
pub struct LocalBusClient {
    inner: Arc<ClientConnection>,
}
/// One queued write. `frame` is `None` for a private raw reply, which is already length-prefixed.
struct OutboundFrame {
    frame: Option<LocalBusFrame>,
    encoded: zeroize::Zeroizing<Vec<u8>>,
}

struct ClientConnection {
    outbound: mpsc::Sender<OutboundFrame>,
    host_key: HostKeySlot,
    pending: Pending,
    next: AtomicU64,
    connected: Arc<AtomicBool>,
    events: Mutex<mpsc::Receiver<LocalBusFrame>>,
    prompts: Arc<Prompts>,
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
    /// Connects without an attended credential provider: an account-code prompt from the
    /// daemon is answered with a refusal and the connection stays up.
    ///
    /// # Errors
    /// Returns an error when the Unix socket cannot be opened.
    pub async fn connect(socket_path: impl AsRef<Path>) -> Result<Self, SdkError> {
        Self::connect_inner(socket_path, None).await
    }

    /// Connects with an attended provider that answers the daemon's account-code prompts
    /// (for example when weakening the app lock) on this same shared connection.
    ///
    /// # Errors
    /// Returns an error when the Unix socket cannot be opened.
    pub async fn connect_with_provider(
        socket_path: impl AsRef<Path>,
        provider: Arc<dyn LocalCredentialProvider>,
    ) -> Result<Self, SdkError> {
        Self::connect_inner(socket_path, Some(provider)).await
    }

    async fn connect_inner(
        socket_path: impl AsRef<Path>,
        provider: Option<Arc<dyn LocalCredentialProvider>>,
    ) -> Result<Self, SdkError> {
        let (prompts, reply_rx, window_rx) = Prompts::new(provider);
        let reader_prompts = Arc::clone(&prompts);
        let writer_prompts = Arc::clone(&prompts);
        let stream = crate::platform::listener::connect(socket_path).await?;
        let (mut reader, writer) = stream.into_split();
        let (outbound, outbound_rx) = mpsc::channel::<OutboundFrame>(64);
        let (events, event_rx) = mpsc::channel(64);
        let pending: Pending = Arc::new(PendingMutex::new(BTreeMap::new()));
        let connected = Arc::new(AtomicBool::new(true));
        let reader_connected = Arc::clone(&connected);
        let writer_connected = Arc::clone(&connected);
        let (disconnected, writer_disconnect) = watch::channel(false);
        let reader_pending = Arc::clone(&pending);
        let host_key: HostKeySlot = Arc::new(PendingMutex::new(None));
        let reader_host_key = Arc::clone(&host_key);
        let reader_outbound = outbound.clone();
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
                if frame.kind == LocalBusFrameKind::Request && frame.method == PROMPT_METHOD {
                    // An account-code prompt is answered on this connection, never fatal.
                    reader_prompts.handle(&frame);
                    continue;
                }
                local_bus_trace(
                    "BUS-CLIENT-RX",
                    format!(
                        "kind={:?} method={} request_id={}",
                        frame.kind, frame.method, frame.request_id
                    ),
                );
                if let Some(prompt) = host_key_prompt(&frame) {
                    answer_host_key_prompt(prompt, &reader_host_key, &reader_outbound);
                    continue;
                }
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
            reader_prompts.connection_closed();
            let _ = disconnected.send(true);
        });
        let writer_pending = Arc::clone(&pending);
        let writer_task = tokio::spawn(run_writer(WriterParts {
            writer,
            outbound_rx,
            reply_rx,
            window_rx,
            disconnect: writer_disconnect,
            connected: writer_connected,
            pending: writer_pending,
            prompts: writer_prompts,
        }));
        Ok(Self {
            inner: Arc::new(ClientConnection {
                outbound,
                host_key,
                pending,
                connected,
                next: AtomicU64::new(1),
                events: Mutex::new(event_rx),
                prompts,
                reader: reader_task,
                writer: writer_task,
            }),
        })
    }

    /// Installs, or with `None` removes, the answer to the daemon's provider-key prompts
    /// (`agent.host.manage` install). Without one every prompt is refused: the daemon reports
    /// `credential_unavailable` and the connection stays up.
    pub fn set_host_key_provider(&self, provider: Option<HostKeyProvider>) {
        let mut slot =
            self.inner.host_key.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = provider;
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
            Err(SdkError::LocalBus(response.error.map_or_else(
                || "unknown local bus error".to_owned(),
                |error| format!("{}: {}", error.code, error.message),
            )))
        } else {
            Ok(response.body)
        }
    }

    /// Sends a frame and preserves a daemon refusal's code, message and response body.
    ///
    /// Existing request methods retain their text-only `LocalBus` errors. Choose this
    /// method to inspect replay bounds; transport errors keep their existing types.
    /// Secret bodies have the same erasure protection as `request_frame`.
    ///
    /// # Errors
    /// Returns `LocalBusRefused` for daemon errors, or the original transport/deadline error.
    pub fn request_frame_structured(
        &self,
        frame: LocalBusFrame,
    ) -> impl Future<Output = Result<serde_json::Value, SdkError>> + '_ {
        let frame = SecretFrame(frame);
        async move {
            let response = self.request_owned_response(frame).await?;
            if response.kind == LocalBusFrameKind::Error {
                return Err(match response.error {
                    Some(error) => SdkError::LocalBusRefused {
                        code: error.code,
                        message: error.message,
                        body: Box::new(response.body),
                    },
                    None => SdkError::LocalBus("unknown local bus error".to_owned()),
                });
            }
            Ok(response.body)
        }
    }

    async fn request_owned_response(
        &self,
        mut protected: SecretFrame,
    ) -> Result<LocalBusFrame, SdkError> {
        if super::custody_setup::handles(&protected.0.method) {
            return Err(SdkError::CustodySetupInvalid);
        }
        let deadline = super::requests::deadline(&protected.0);
        let parent = self.inner.prompts.parent_of(&protected.0);
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
        self.inner.prompts.register(parent);
        let _registration = Registration {
            pending: Arc::clone(&self.inner.pending),
            prompts: Arc::clone(&self.inner.prompts),
            id: frame.request_id.clone(),
        };
        let wait = async {
            self.inner
                .outbound
                .send(OutboundFrame { frame: Some(frame), encoded })
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
    prompts: Arc<Prompts>,
    id: String,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.prompts.forget(&self.id);
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&self.id);
        }
    }
}
struct WriterParts<W> {
    writer: W,
    outbound_rx: mpsc::Receiver<OutboundFrame>,
    reply_rx: mpsc::Receiver<super::client_prompt::Reply>,
    window_rx: watch::Receiver<bool>,
    disconnect: watch::Receiver<bool>,
    connected: Arc<AtomicBool>,
    pending: Pending,
    prompts: Arc<Prompts>,
}

/// Writes queued requests and, with priority, private credential replies. While an input
/// window is open the daemon reads only the reply, so every other frame waits for it.
async fn run_writer<W: tokio::io::AsyncWrite + Unpin>(parts: WriterParts<W>) {
    let WriterParts {
        mut writer,
        mut outbound_rx,
        mut reply_rx,
        mut window_rx,
        mut disconnect,
        connected,
        pending,
        prompts,
    } = parts;
    // A frame taken from the queue while an input window opened waits here.
    let mut held: Option<OutboundFrame> = None;
    loop {
        let reply = if *window_rx.borrow() {
            tokio::select! {
                _ = disconnect.changed() => break,
                reply = reply_rx.recv() => reply,
            }
        } else if let Some(frame) = held.take() {
            if let Err(error) = write_outbound(&mut writer, frame).await {
                connected.store(false, Ordering::Release);
                fail_pending(&pending, &error.to_string());
                break;
            }
            continue;
        } else {
            tokio::select! {
                _ = disconnect.changed() => break,
                _ = window_rx.changed() => continue,
                reply = reply_rx.recv() => reply,
                frame = outbound_rx.recv() => {
                    let Some(frame) = frame else {
                        break;
                    };
                    held = Some(frame);
                    continue;
                }
            }
        };
        let Some(reply) = reply else {
            break;
        };
        let written = write_private_reply(&mut writer, &reply).await;
        prompts.reply_written();
        if let Err(error) = written {
            connected.store(false, Ordering::Release);
            fail_pending(&pending, &error.to_string());
            break;
        }
    }
    connected.store(false, Ordering::Release);
    fail_pending(&pending, "local bus writer stopped");
}

async fn write_outbound<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    outbound: OutboundFrame,
) -> Result<(), SdkError> {
    let OutboundFrame { frame, encoded } = outbound;
    let label = frame.as_ref().map_or_else(
        || "private credential reply".to_owned(),
        |frame| format!("method={} request_id={}", frame.method, frame.request_id),
    );
    local_bus_trace("BUS-CLIENT-TX-IN", label.clone());
    match &frame {
        Some(_) => super::io::write_encoded_local_bus_frame(writer, &encoded).await?,
        None => write_private_reply(writer, &encoded).await?,
    }
    local_bus_trace("BUS-CLIENT-TX-OUT", label);
    Ok(())
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

/// The generation and provider id of an `agent.host.credential` prompt, when `frame` is one. A
/// prompt frame without a valid generation is not answered here and stays a fatal request frame.
fn host_key_prompt(frame: &LocalBusFrame) -> Option<(u64, String)> {
    if frame.kind != LocalBusFrameKind::Request || frame.method != "agent.host.credential" {
        return None;
    }
    let generation =
        crate::custody::pairing::private_credential::host_prompt_generation(&frame.frame_id)?;
    let provider =
        frame.body.get("provider").and_then(serde_json::Value::as_str).unwrap_or("").to_owned();
    Some((generation, provider))
}

/// Answers a provider-key prompt with a private reply. The provider runs on a blocking thread and
/// the reader keeps reading meanwhile. No provider, an empty id, or no key is a refusal.
fn answer_host_key_prompt(
    prompt: (u64, String),
    slot: &HostKeySlot,
    outbound: &mpsc::Sender<OutboundFrame>,
) {
    use crate::custody::pairing::CredentialOutcome;
    use crate::custody::pairing::private_credential::{encode_reply, host_outcome};
    let (generation, provider) = prompt;
    let callback = slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    let outbound = outbound.clone();
    tokio::spawn(async move {
        let key = match callback {
            Some(callback) if !provider.is_empty() => {
                tokio::task::spawn_blocking(move || callback(&provider)).await.ok().flatten()
            }
            _ => None,
        };
        let outcome = host_outcome(key.as_ref().map(|key| key.as_bytes()));
        drop(key);
        let Ok(encoded) = encode_reply(generation, "provider", &outcome)
            .or_else(|_| encode_reply(generation, "provider", &CredentialOutcome::Refused))
        else {
            return;
        };
        let _ = outbound.send(OutboundFrame { frame: None, encoded }).await;
    });
}

async fn write_private_reply<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    encoded: &[u8],
) -> Result<(), SdkError> {
    use tokio::io::AsyncWriteExt;
    writer.write_all(encoded).await?;
    writer.flush().await?;
    Ok(())
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
        if super::events::is_transient(&frame) && !events.is_closed() {
            // A transient drop never disconnects a durable subscription or changes its cursor.
            if events.capacity() > 1 {
                let _ = events.try_send(frame);
            }
            return true;
        }
        if events.capacity() <= 1 {
            let request = LocalBusFrame::request(
                "client-lagged",
                frame.account_id.clone(),
                "stream",
                "bus.subscribe",
                serde_json::json!({}),
            );
            super::subscription::lagged(&events.clone().into(), &request, *last_seq);
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

#[cfg(all(test, unix))]
#[path = "contact_error_client_tests.rs"]
mod contact_error_tests;

#[cfg(all(test, unix))]
#[path = "client_stream_error_tests.rs"]
mod stream_error_tests;

#[cfg(test)]
mod transient_tests {
    use super::*;
    #[test]
    fn transient_events_never_advance_cursor_or_disconnect_on_overflow() -> Result<(), SdkError> {
        let (tx, mut rx) = mpsc::channel(3);
        let pending = Arc::new(PendingMutex::new(BTreeMap::new()));
        let connected = AtomicBool::new(true);
        let mut last = 40;
        let mut frame = LocalBusFrame::request(
            "",
            Some("a".into()),
            "message",
            ramflux_protocol::message::TRANSIENT_TOPIC,
            serde_json::json!({}),
        );
        frame.kind = LocalBusFrameKind::Event;
        frame.seq = Some(0);
        for _ in 0..4 {
            assert!(route_received(frame.clone(), &tx, &pending, &connected, &mut last));
        }
        assert_eq!(last, 40, "transient event changed the durable cursor");
        assert!(connected.load(Ordering::Acquire));
        for _ in 0..2 {
            let event = rx.try_recv().map_err(|_| closed())?;
            assert_eq!(event.method, ramflux_protocol::message::TRANSIENT_TOPIC);
            assert_eq!(event.seq, Some(0));
        }
        assert!(rx.try_recv().is_err());
        frame.method = "message.received".into();
        frame.seq = Some(90);
        assert!(route_received(frame, &tx, &pending, &connected, &mut last));
        assert_eq!(last, 90);
        assert_eq!(rx.try_recv().map_err(|_| closed())?.seq, Some(90));
        Ok(())
    }
}
