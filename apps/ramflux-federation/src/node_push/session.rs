// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The `rfc-push-1` session: one persistent QUIC connection to the centre edge, `sync` frames, and
//! wake batches for the handoff socket (at most four streams in flight).
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ramflux_node_core::push_handoff::{
    HandoffReply, HandoffResult, HandoffStatus, HandoffWake, MAX_WAKES, PushCentralState,
    WakeOutcome, read_push_central_state, write_push_central_state,
};
use serde_json::{Value, json};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

use super::frame;
use super::state::{apply_ok, now_ms};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_STREAMS: usize = 4;
const DEFAULT_RETRY_MS: u64 = 2000;
const DEFAULT_SYNC_S: u64 = 3600;
const STOPPED_WAIT: Duration = Duration::from_secs(300);
/// QUIC application close codes (A9.1).
const CLOSE_CLOSED: u64 = 0;
const CLOSE_REJECTED_TWICE: u64 = 1;
const CLOSE_ACCESS: u64 = 2;

pub(crate) struct PushShared {
    pub(crate) seed: [u8; 32],
    pub(crate) centre_id: String,
    pub(crate) node_key: String,
    pub(crate) key_gen: u64,
    pub(crate) state_path: std::path::PathBuf,
    pub(crate) state: Mutex<PushCentralState>,
    /// `dir.sync_s` from the last `ok` reply.
    pub(crate) sync_s: Mutex<u64>,
    /// While set and in the future, handoffs answer `stopped` without contacting the centre.
    pub(crate) stopped_until: Mutex<Option<Instant>>,
    endpoint: quinn::Endpoint,
    centre: SocketAddr,
    server_name: String,
    connection: AsyncMutex<Option<quinn::Connection>>,
    streams: Semaphore,
    /// Raised when a stop is recorded, so the sync loop re-times its next sync (A-stop: 300 s).
    stop_notify: tokio::sync::Notify,
}

/// What one request produced on the wire.
pub(crate) enum Exchange {
    Reply(Value),
    /// The edge closed the connection with an application close code.
    Closed(u64),
    Failed(String),
}

impl PushShared {
    pub(crate) fn new(
        seed: [u8; 32],
        centre_id: String,
        node_key: String,
        key_gen: u64,
        state_path: std::path::PathBuf,
        link: (quinn::Endpoint, SocketAddr, String),
    ) -> Result<Self, String> {
        let (endpoint, centre, server_name) = link;
        let state = read_push_central_state(&state_path)
            .map_err(|error| format!("push state: {error}"))?
            .unwrap_or_else(|| PushCentralState {
                ks: None,
                ks_seq: 0,
                served: ramflux_node_core::push_handoff::Served {
                    apns: false,
                    apns_voip: false,
                    fcm: false,
                },
                classes: Vec::new(),
                ttl_max_s: ramflux_node_core::push_handoff::TtlMax::default(),
                policy: ramflux_node_core::push_handoff::PushPolicy::default(),
                quota: None,
                updated_at_ms: 0,
            });
        Ok(Self {
            seed,
            centre_id,
            node_key,
            key_gen,
            state_path,
            state: Mutex::new(state),
            sync_s: Mutex::new(DEFAULT_SYNC_S),
            stopped_until: Mutex::new(None),
            endpoint,
            centre,
            server_name,
            connection: AsyncMutex::new(None),
            streams: Semaphore::new(MAX_STREAMS),
            stop_notify: tokio::sync::Notify::new(),
        })
    }

    fn snapshot(&self) -> PushCentralState {
        match self.state.lock() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn is_stopped(&self) -> bool {
        match self.stopped_until.lock() {
            Ok(until) => until.is_some_and(|instant| instant > Instant::now()),
            Err(_) => false,
        }
    }

    fn stop_for(&self, wait: Duration) {
        if let Ok(mut until) = self.stopped_until.lock() {
            *until = Some(Instant::now() + wait);
        }
        self.stop_notify.notify_one();
    }

    /// Time left of the current stop, if any.
    fn stop_remaining(&self) -> Option<Duration> {
        self.stopped_until
            .lock()
            .ok()
            .and_then(|until| *until)
            .and_then(|instant| instant.checked_duration_since(Instant::now()))
    }

    /// Applies an `ok` reply: `dir`, `ks`, and the state file, written atomically.
    pub(crate) fn apply_reply(&self, reply: &Value) {
        let next = {
            let Ok(mut guard) = self.state.lock() else { return };
            let next = apply_ok(guard.clone(), reply);
            *guard = next.clone();
            next
        };
        if let Some(sync_s) =
            reply.get("dir").and_then(|dir| dir.get("sync_s")).and_then(Value::as_u64)
            && (60..=86_400).contains(&sync_s)
            && let Ok(mut slot) = self.sync_s.lock()
        {
            *slot = sync_s;
        }
        if let Err(error) = write_push_central_state(&self.state_path, &next) {
            tracing::error!(%error, "push state file not written");
        }
    }

    /// Current connection, or a new one. One connect at a time.
    async fn connection(&self) -> Result<quinn::Connection, String> {
        let mut slot = self.connection.lock().await;
        if let Some(existing) = slot.as_ref()
            && existing.close_reason().is_none()
        {
            return Ok(existing.clone());
        }
        let connecting = self
            .endpoint
            .connect(self.centre, &self.server_name)
            .map_err(|error| error.to_string())?;
        let connection = tokio::time::timeout(IO_TIMEOUT, connecting)
            .await
            .map_err(|_| "connect timeout".to_owned())?
            .map_err(|error| error.to_string())?;
        *slot = Some(connection.clone());
        Ok(connection)
    }

    /// One request on one bidirectional stream.
    pub(crate) async fn exchange(&self, request: &[u8]) -> Exchange {
        let Ok(_permit) = self.streams.acquire().await else {
            return Exchange::Failed("streams closed".to_owned());
        };
        let connection = match self.connection().await {
            Ok(connection) => connection,
            Err(error) => return Exchange::Failed(error),
        };
        let outcome = async {
            let (mut send, mut recv) =
                connection.open_bi().await.map_err(|error| error.to_string())?;
            send.write_all(request).await.map_err(|error| error.to_string())?;
            send.finish().map_err(|error| error.to_string())?;
            recv.read_to_end(frame::MAX_REPLY_LEN + 4).await.map_err(|error| error.to_string())
        };
        match tokio::time::timeout(IO_TIMEOUT, outcome).await {
            Err(_) => {
                self.drop_connection(&connection).await;
                Exchange::Failed("reply timeout".to_owned())
            }
            Ok(Ok(bytes)) => match frame::decode_reply(&bytes) {
                Ok(value) => Exchange::Reply(value),
                Err(error) => Exchange::Failed(error),
            },
            Ok(Err(error)) => {
                if let Some(code) = closed_code(&connection) {
                    return Exchange::Closed(code);
                }
                self.drop_connection(&connection).await;
                Exchange::Failed(error)
            }
        }
    }

    /// Forgets a connection that failed, so the next request dials again (a restarted edge would
    /// otherwise stay unreachable until QUIC notices the dead peer).
    async fn drop_connection(&self, failed: &quinn::Connection) {
        let mut slot = self.connection.lock().await;
        if slot.as_ref().is_some_and(|current| current.stable_id() == failed.stable_id()) {
            *slot = None;
        }
        failed.close(0u32.into(), b"");
    }
}

/// Sleeps for `wait`, but a stop recorded meanwhile moves the wake-up to the end of the stop.
pub(crate) async fn pause(shared: &PushShared, wait: Duration) {
    let mut wait = wait;
    loop {
        tokio::select! {
            () = tokio::time::sleep(wait) => return,
            () = shared.stop_notify.notified() => match shared.stop_remaining() {
                Some(left) => wait = left,
                None => return,
            },
        }
    }
}

fn closed_code(connection: &quinn::Connection) -> Option<u64> {
    match connection.close_reason()? {
        quinn::ConnectionError::ApplicationClosed(close) => Some(close.error_code.into_inner()),
        _ => None,
    }
}

fn jittered(base: Duration) -> Duration {
    let byte = ramflux_crypto::random_32().map_or(0, |bytes| bytes.first().copied().unwrap_or(0));
    base.mul_f64(0.8 + f64::from(byte) / 637.5)
}

fn body_json(
    shared: &PushShared,
    kind: &str,
    wakes: Option<&[HandoffWake]>,
) -> Result<Vec<u8>, String> {
    let state = shared.snapshot();
    let mut body = json!({
        "pv": 1,
        "kind": kind,
        "node_key": shared.node_key,
        "key_gen": shared.key_gen,
        "ts": now_ms(),
        "ks_seq": state.ks_seq,
        "policy_version": state.policy.version,
    });
    if let Some(wakes) = wakes {
        let wakes = serde_json::to_value(wakes).map_err(|error| error.to_string())?;
        if let Some(object) = body.as_object_mut() {
            object.insert("wakes".to_owned(), wakes);
        }
    }
    serde_json::to_vec(&body).map_err(|error| error.to_string())
}

/// Sends one `sync` now. Returns the wait before the next sync and whether the session is stopped.
pub(crate) async fn sync_once(shared: &PushShared) -> Duration {
    let body = match body_json(shared, "sync", None) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(%error, "push sync body");
            return STOPPED_WAIT;
        }
    };
    let request = match frame::encode_request(&shared.seed, &shared.centre_id, &body) {
        Ok(request) => request,
        Err(error) => {
            tracing::error!(%error, "push sync frame");
            return STOPPED_WAIT;
        }
    };
    match shared.exchange(&request).await {
        Exchange::Reply(reply) => {
            if reply.get("status").and_then(Value::as_str) == Some("ok") {
                shared.apply_reply(&reply);
                if let Ok(mut until) = shared.stopped_until.lock() {
                    *until = None;
                }
                let sync_s = match shared.sync_s.lock() {
                    Ok(value) => *value,
                    Err(_) => DEFAULT_SYNC_S,
                };
                Duration::from_secs(sync_s)
            } else {
                refusal_wait(shared, &reply)
            }
        }
        Exchange::Closed(code) => closed_wait(shared, code),
        Exchange::Failed(error) => {
            tracing::warn!(%error, "push centre unreachable");
            jittered(Duration::from_secs(2))
        }
    }
}

fn closed_wait(shared: &PushShared, code: u64) -> Duration {
    match code {
        CLOSE_ACCESS => {
            shared.stop_for(STOPPED_WAIT);
            tracing::warn!("push session: admission revoked (close 2); stopped, sync every 300 s");
            STOPPED_WAIT
        }
        CLOSE_CLOSED | CLOSE_REJECTED_TWICE => {
            tracing::info!(code, "push session closed by edge; reconnecting");
            Duration::from_secs(2)
        }
        other => {
            tracing::warn!(code = other, "push session closed with an unknown code");
            Duration::from_secs(2)
        }
    }
}

fn refusal_wait(shared: &PushShared, reply: &Value) -> Duration {
    match reply.get("status").and_then(Value::as_str) {
        Some("unavailable" | "throttled") => {
            let ms =
                reply.get("retry_after_ms").and_then(Value::as_u64).unwrap_or(DEFAULT_RETRY_MS);
            Duration::from_millis(ms.clamp(1000, 3_600_000))
        }
        Some("rejected") => {
            let reason = reply.get("reason").and_then(Value::as_str).unwrap_or("");
            tracing::warn!(reason, "push sync rejected");
            if matches!(reason, "unknown_key" | "suspended_key" | "revoked_key") {
                shared.stop_for(STOPPED_WAIT);
            }
            STOPPED_WAIT
        }
        _ => Duration::from_millis(DEFAULT_RETRY_MS),
    }
}

/// Splits a wake list so that every frame fits the centre's limit, then sends each frame.
/// Results keep request order; any non-`ok` chunk makes the whole batch non-`ok`.
pub(crate) async fn send_wakes(shared: &PushShared, wakes: &[HandoffWake]) -> HandoffReply {
    if wakes.is_empty() || wakes.len() > MAX_WAKES {
        return reply_status(HandoffStatus::Rejected, Some("malformed"), None, Vec::new());
    }
    let mut results = Vec::with_capacity(wakes.len());
    let mut pending: Vec<&[HandoffWake]> = vec![wakes];
    while let Some(chunk) = pending.pop() {
        let body = match body_json(shared, "wake", Some(chunk)) {
            Ok(body) => body,
            Err(error) => {
                tracing::error!(%error, "push wake body");
                return reply_status(
                    HandoffStatus::Unavailable,
                    Some("body"),
                    Some(DEFAULT_RETRY_MS),
                    Vec::new(),
                );
            }
        };
        if body.len() > frame::MAX_BODY_LEN {
            if chunk.len() <= 1 {
                return reply_status(HandoffStatus::Rejected, Some("too_large"), None, Vec::new());
            }
            let (left, right) = chunk.split_at(chunk.len() / 2);
            // Keep order: the right half waits until the left half has been sent.
            pending.push(right);
            pending.push(left);
            continue;
        }
        if shared.is_stopped() {
            return reply_status(HandoffStatus::Stopped, Some("access"), Some(300_000), Vec::new());
        }
        let request = match frame::encode_request(&shared.seed, &shared.centre_id, &body) {
            Ok(request) => request,
            Err(error) => {
                tracing::error!(%error, "push wake frame");
                return reply_status(
                    HandoffStatus::Unavailable,
                    Some("frame"),
                    Some(DEFAULT_RETRY_MS),
                    Vec::new(),
                );
            }
        };
        match shared.exchange(&request).await {
            Exchange::Reply(reply) => match map_wake_reply(shared, &reply, chunk) {
                Ok(mut chunk_results) => results.append(&mut chunk_results),
                Err(reply) => return reply,
            },
            Exchange::Closed(code) => {
                let _ = closed_wait(shared, code);
                let status = if code == CLOSE_ACCESS {
                    HandoffStatus::Stopped
                } else {
                    HandoffStatus::Unavailable
                };
                return reply_status(status, Some("closed"), Some(DEFAULT_RETRY_MS), Vec::new());
            }
            Exchange::Failed(error) => {
                tracing::warn!(%error, "push wake exchange failed");
                return reply_status(
                    HandoffStatus::Unavailable,
                    Some("transport"),
                    Some(DEFAULT_RETRY_MS),
                    Vec::new(),
                );
            }
        }
    }
    reply_status(HandoffStatus::Ok, None, None, results)
}

/// Maps one centre reply for `chunk`. `Err` carries the batch reply to return instead.
fn map_wake_reply(
    shared: &PushShared,
    reply: &Value,
    chunk: &[HandoffWake],
) -> Result<Vec<HandoffResult>, HandoffReply> {
    let status = reply.get("status").and_then(Value::as_str).unwrap_or("");
    match status {
        "ok" => {
            shared.apply_reply(reply);
            let results = reply.get("results").and_then(Value::as_array);
            let Some(results) = results.filter(|results| results.len() == chunk.len()) else {
                return Err(reply_status(
                    HandoffStatus::Unavailable,
                    Some("bad_reply"),
                    Some(DEFAULT_RETRY_MS),
                    Vec::new(),
                ));
            };
            let mut mapped = Vec::with_capacity(chunk.len());
            for (wake, result) in chunk.iter().zip(results) {
                // A8.5: results are matched by position and the `w` must be the wake's own.
                if result.get("w").and_then(Value::as_str) != Some(wake.w.as_str()) {
                    return Err(reply_status(
                        HandoffStatus::Unavailable,
                        Some("bad_reply"),
                        Some(DEFAULT_RETRY_MS),
                        Vec::new(),
                    ));
                }
                let Some(outcome) = result
                    .get("r")
                    .and_then(|r| serde_json::from_value::<WakeOutcome>(r.clone()).ok())
                else {
                    return Err(reply_status(
                        HandoffStatus::Unavailable,
                        Some("bad_reply"),
                        Some(DEFAULT_RETRY_MS),
                        Vec::new(),
                    ));
                };
                mapped.push(HandoffResult {
                    w: wake.w.clone(),
                    r: outcome,
                    why: result.get("why").and_then(Value::as_str).map(str::to_owned),
                    at: result.get("at").and_then(Value::as_u64),
                });
            }
            Ok(mapped)
        }
        "unavailable" | "throttled" => {
            let ms =
                reply.get("retry_after_ms").and_then(Value::as_u64).unwrap_or(DEFAULT_RETRY_MS);
            let status = if status == "throttled" {
                HandoffStatus::Throttled
            } else {
                HandoffStatus::Unavailable
            };
            Err(reply_status(status, Some(status_name(status)), Some(ms), Vec::new()))
        }
        "rejected" => {
            let reason =
                reply.get("reason").and_then(Value::as_str).unwrap_or("rejected").to_owned();
            let stopped =
                matches!(reason.as_str(), "unknown_key" | "suspended_key" | "revoked_key");
            if stopped {
                shared.stop_for(STOPPED_WAIT);
            }
            let status = if stopped { HandoffStatus::Stopped } else { HandoffStatus::Rejected };
            Err(reply_status(status, Some(reason.as_str()), None, Vec::new()))
        }
        _ => Err(reply_status(
            HandoffStatus::Unavailable,
            Some("bad_reply"),
            Some(DEFAULT_RETRY_MS),
            Vec::new(),
        )),
    }
}

fn status_name(status: HandoffStatus) -> &'static str {
    match status {
        HandoffStatus::Throttled => "throttled",
        _ => "unavailable",
    }
}

pub(crate) fn reply_status(
    status: HandoffStatus,
    why: Option<&str>,
    retry_after_ms: Option<u64>,
    results: Vec<HandoffResult>,
) -> HandoffReply {
    HandoffReply {
        v: ramflux_node_core::push_handoff::HANDOFF_VERSION,
        status,
        retry_after_ms,
        reason: why.map(str::to_owned),
        results,
    }
}
