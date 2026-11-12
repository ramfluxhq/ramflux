// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A bounded, polled view of one supervisor subscription.
//!
//! Events are the supervisor's own frames with its own sequence numbers; the shim adds no
//! acceptance or completion records. The queue is bounded by count and by bytes. When the
//! host falls behind, the subscription ends with a terminal `lagged` record instead of
//! dropping an event silently or growing without limit.

use super::error::{V2Error, V2Result};
use super::types::MAX_QUEUE_BYTES;
use super::super::RamfluxErrorCode;
use crate::{LocalBusClient, LocalBusFrame, LocalBusFrameKind, SdkError};
use std::collections::VecDeque;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, watch};

/// Time the supervisor has to acknowledge `subscription.open`.
pub(super) const OPEN_DEADLINE: Duration = Duration::from_secs(5);
/// Longest time one poll may block.
pub(super) const MAX_POLL_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Terminal {
    /// The host fell behind. It resubscribes from the last sequence it applied.
    Lagged,
    /// The connection ended: suspend, stop, close or a supervisor exit.
    Closed,
    /// The host cancelled.
    Cancelled,
}

impl Terminal {
    const fn name(self) -> &'static str {
        match self {
            Self::Lagged => "lagged",
            Self::Closed => "closed",
            Self::Cancelled => "cancelled",
        }
    }
}

struct QueueState {
    events: VecDeque<(Option<u64>, Vec<u8>)>,
    bytes: usize,
    /// Sequence of the last event handed to the host by `poll`.
    last_delivered_seq: Option<u64>,
    terminal: Option<Terminal>,
}

pub(super) struct EventQueue {
    capacity: usize,
    state: Mutex<QueueState>,
    ready: Condvar,
    /// Wakes the pump when the host cancels.
    cancelled: Notify,
}

fn poisoned<T>(_error: T) -> V2Error {
    V2Error::new(RamfluxErrorCode::Internal, "subscription queue is poisoned")
}

impl EventQueue {
    pub(super) fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            state: Mutex::new(QueueState {
                events: VecDeque::new(),
                bytes: 0,
                last_delivered_seq: None,
                terminal: None,
            }),
            ready: Condvar::new(),
            cancelled: Notify::new(),
        })
    }

    /// Pump side. `false` when the subscription is over and the pump must stop.
    fn push(&self, seq: Option<u64>, encoded: Vec<u8>) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.terminal.is_some() {
            return false;
        }
        let over_count = state.events.len() >= self.capacity;
        let over_bytes = state.bytes.saturating_add(encoded.len()) > MAX_QUEUE_BYTES;
        if over_count || over_bytes {
            // The event that did not fit is not delivered and not counted as delivered.
            state.terminal = Some(Terminal::Lagged);
            self.ready.notify_all();
            return false;
        }
        state.bytes = state.bytes.saturating_add(encoded.len());
        state.events.push_back((seq, encoded));
        self.ready.notify_all();
        true
    }

    /// End the subscription. The first terminal reason wins.
    pub(super) fn terminate(&self, terminal: Terminal) {
        if let Ok(mut state) = self.state.lock()
            && state.terminal.is_none()
        {
            state.terminal = Some(terminal);
        }
        self.ready.notify_all();
        self.cancelled.notify_one();
    }

    /// Take up to `max_events`, waiting at most `wait` when nothing is queued. The result
    /// is `{"events":[frame,...],"terminal":null|{"kind":...,"last_seq":...}}`. The terminal
    /// record appears only once every queued event before it has been delivered.
    pub(super) fn poll(&self, max_events: u32, wait: Duration) -> V2Result<Vec<u8>> {
        if max_events == 0 {
            return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "max_events is zero"));
        }
        let limit = usize::try_from(max_events).unwrap_or(usize::MAX).min(self.capacity.max(1));
        let until = Instant::now() + wait.min(MAX_POLL_WAIT);
        let mut state = self.state.lock().map_err(poisoned)?;
        while state.events.is_empty() && state.terminal.is_none() {
            let now = Instant::now();
            if now >= until {
                break;
            }
            let (next, _timeout) =
                self.ready.wait_timeout(state, until - now).map_err(poisoned)?;
            state = next;
        }
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(br#"{"events":["#);
        let mut taken = 0_usize;
        while taken < limit {
            let Some((seq, encoded)) = state.events.pop_front() else {
                break;
            };
            if taken > 0 {
                out.push(b',');
            }
            state.bytes = state.bytes.saturating_sub(encoded.len());
            if seq.is_some() {
                state.last_delivered_seq = seq;
            }
            out.extend_from_slice(&encoded);
            taken += 1;
        }
        out.extend_from_slice(br#"],"terminal":"#);
        match state.terminal {
            Some(terminal) if state.events.is_empty() => {
                let record = serde_json::json!({
                    "kind": terminal.name(),
                    "last_seq": state.last_delivered_seq.map(|seq| seq.to_string()),
                });
                out.extend_from_slice(record.to_string().as_bytes());
            }
            _ => out.extend_from_slice(b"null"),
        }
        out.push(b'}');
        Ok(out)
    }
}

pub(super) struct SubscribeJob {
    pub(super) account_id: Option<String>,
    pub(super) body: serde_json::Value,
    pub(super) queue: Arc<EventQueue>,
    pub(super) opened: SyncSender<Result<(), SdkError>>,
}

/// Open the subscription on its own connection and move events into the queue until the
/// connection, the supervisor generation or the host ends it.
pub(super) async fn pump(
    client: Result<LocalBusClient, SdkError>,
    job: SubscribeJob,
    mut generation: watch::Receiver<u64>,
) {
    let SubscribeJob { account_id, body, queue, opened } = job;
    let mut client = match client {
        Ok(client) => client,
        Err(error) => {
            queue.terminate(Terminal::Closed);
            let _ignored = opened.try_send(Err(error));
            return;
        }
    };
    let mut open = LocalBusFrame::request(
        "cabi-v2-subscribe",
        account_id,
        "subscription",
        "subscription.open",
        body,
    );
    open.deadline_ms = unix_deadline(OPEN_DEADLINE);
    let acknowledged = client.request_frame_response(open).await.and_then(|frame| {
        if frame.kind == LocalBusFrameKind::Error {
            Err(frame.error.map_or_else(
                || SdkError::LocalBus("subscription refused".to_owned()),
                |error| SdkError::LocalBusRefused {
                    code: error.code,
                    message: error.message,
                    body: Box::new(frame.body),
                },
            ))
        } else {
            Ok(())
        }
    });
    let failed = acknowledged.is_err();
    let _ignored = opened.try_send(acknowledged);
    if failed {
        queue.terminate(Terminal::Closed);
        return;
    }
    loop {
        tokio::select! {
            _changed = generation.changed() => {
                queue.terminate(Terminal::Closed);
                return;
            }
            () = queue.cancelled.notified() => return,
            event = client.next_event() => {
                let Ok(frame) = event else {
                    queue.terminate(Terminal::Closed);
                    return;
                };
                let Ok(encoded) = serde_json::to_vec(&frame) else {
                    queue.terminate(Terminal::Closed);
                    return;
                };
                if !queue.push(frame.seq, encoded) {
                    return;
                }
            }
        }
    }
}

/// Absolute Unix deadline `after` from now, in milliseconds.
pub(super) fn unix_deadline(after: Duration) -> Option<u64> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?;
    u64::try_from(now.checked_add(after)?.as_millis()).ok()
}

#[cfg(test)]
pub(super) mod tests_support {
    /// Queue one synthetic event the way the pump does.
    pub(in super::super) fn push(queue: &super::EventQueue, seq: u64) -> bool {
        queue.push(Some(seq), format!("{{\"seq\":{seq}}}").into_bytes())
    }
}
