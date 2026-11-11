// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One transient consumer and one shared occupancy budget per account generation.

use super::lifetime::ReceiverClock;
use super::receiver::{
    EphemeralReceiver, RECEIVER_CHANNEL_BYTES, RECEIVER_CHANNEL_FRAMES, RECEIVER_MAX_FRAME_BYTES,
    ReceiverDequeue,
};
use ramflux_protocol::Envelope;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tokio::time::Duration;
use tokio::time::Instant;

/// Caller-resolved active signing authority. Resolve through authenticated root/device
/// membership and revocation policy, never from the incoming frame's key claims.
pub struct EphemeralSource {
    pub principal_id: String,
    pub device: ramflux_crypto::RootQualifiedDeviceRef,
    pub signing_public_key: String,
}

struct Pending {
    bytes: Vec<u8>,
    expires_at_ms: u64,
}

struct State {
    pending: VecDeque<Pending>,
    bytes: usize,
    receiver: EphemeralReceiver,
    taken: bool,
    connected: bool,
    closed: bool,
}

#[derive(Clone)]
pub(crate) struct SessionInbox {
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
    origin: Instant,
    #[cfg(test)]
    test_clock: Arc<Mutex<Option<ReceiverClock>>>,
}

pub(crate) struct SessionInboxOwner(SessionInbox);
impl Drop for SessionInboxOwner {
    fn drop(&mut self) {
        self.0.disconnect(true);
    }
}

/// Exclusive transient ciphertext consumer. No subscription queue, journal, or ACK path.
/// The account host owns its lifetime; lock/stop closes this consumer and clears its state.
pub struct EphemeralConsumer {
    inbox: SessionInbox,
}

impl Drop for EphemeralConsumer {
    fn drop(&mut self) {
        let mut state = self.inbox.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.pending.clear();
        state.bytes = 0;
        state.receiver.disconnect();
        state.taken = false;
    }
}

pub(crate) fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

impl SessionInbox {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                pending: VecDeque::new(),
                bytes: 0,
                receiver: EphemeralReceiver::new(),
                taken: false,
                connected: true,
                closed: false,
            })),
            #[cfg(test)]
            test_clock: Arc::default(),
            changed: Arc::new(Notify::new()),
            origin: Instant::now(),
        }
    }

    pub(crate) fn owner(&self) -> SessionInboxOwner {
        SessionInboxOwner(self.clone())
    }

    pub(crate) fn consumer(&self) -> Option<EphemeralConsumer> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.taken || state.closed {
            return None;
        }
        state.taken = true;
        Some(EphemeralConsumer { inbox: self.clone() })
    }

    pub(crate) fn push(&self, bytes: &[u8], expires_at_ms: u64) {
        let now = self.clock().local_now_ms;
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut retained = VecDeque::new();
        while let Some(pending) = state.pending.pop_front() {
            if pending.expires_at_ms > now {
                retained.push_back(pending);
            } else {
                state.bytes = state.bytes.saturating_sub(pending.bytes.len());
            }
        }
        state.pending = retained;
        let (frames, occupied) = state.receiver.occupancy();
        if state.closed
            || !state.connected
            || expires_at_ms <= now
            || bytes.len() > RECEIVER_MAX_FRAME_BYTES
            || frames + state.pending.len() >= RECEIVER_CHANNEL_FRAMES
            || occupied.saturating_add(state.bytes).saturating_add(bytes.len())
                > RECEIVER_CHANNEL_BYTES
        {
            return;
        }
        state.bytes += bytes.len();
        state.pending.push_back(Pending { bytes: bytes.to_vec(), expires_at_ms });
        drop(state);
        self.changed.notify_one();
    }

    pub(crate) fn reconnect(&self) {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).connected = true;
        self.changed.notify_one();
    }

    pub(crate) fn disconnect(&self, close: bool) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.pending.clear();
        state.bytes = 0;
        state.connected = false;
        state.closed |= close;
        if close {
            state.receiver.lock();
        } else {
            state.receiver.disconnect();
        }
        drop(state);
        self.changed.notify_one();
    }

    #[cfg(test)]
    pub(crate) fn set_clock(&self, clock: ReceiverClock) {
        *self.test_clock.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(clock);
    }

    #[cfg(test)]
    pub(crate) fn observation(&self) -> (usize, usize, usize, usize) {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (frames, bytes) = state.receiver.occupancy();
        (
            state.pending.len() + frames,
            state.bytes + bytes,
            state.receiver.hold_len(),
            state.receiver.dedup_len(),
        )
    }

    fn clock(&self) -> ReceiverClock {
        #[cfg(test)]
        if let Some(clock) =
            *self.test_clock.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return clock;
        }

        ReceiverClock {
            local_now_ms: wall_ms(),
            monotonic_ms: u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }
}

impl EphemeralConsumer {
    /// Wait for authenticated ciphertext, promoting Holds on timer ticks even without packets.
    /// The resolver must bind active source root/device authority before returning a key.
    /// Returns None after account lock/stop. Returned original bytes count against occupancy
    /// until complete is called; no durable receive bookkeeping is performed.
    pub async fn next(
        &mut self,
        mut resolve: impl FnMut(&Envelope) -> Option<EphemeralSource>,
    ) -> Option<(Vec<u8>, u64)> {
        loop {
            let changed = self.inbox.changed.notified();
            {
                let clock = self.inbox.clock();
                let mut state =
                    self.inbox.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.closed {
                    return None;
                }
                while let Some(pending) = state.pending.pop_front() {
                    state.bytes = state.bytes.saturating_sub(pending.bytes.len());
                    let Ok(crate::GatewayServerFrame::Ephemeral { envelope, .. }) =
                        ramflux_protocol::parse_i_json(&pending.bytes)
                    else {
                        continue;
                    };
                    let Some(source) = resolve(&envelope) else {
                        continue;
                    };
                    let root = envelope
                        .ext
                        .ext
                        .get("source_root_commitment")
                        .and_then(serde_json::Value::as_str);
                    if source.device.device_id() != envelope.source_device_id
                        || root != Some(source.device.root_commitment())
                    {
                        continue;
                    }
                    let _admission = state.receiver.admit(
                        &pending.bytes,
                        clock,
                        &source.principal_id,
                        &source.signing_public_key,
                    );
                }
                if let ReceiverDequeue::Delivered { bytes, expires_at_ms } =
                    state.receiver.pop(clock.local_now_ms, clock.monotonic_ms)
                {
                    return Some((bytes, expires_at_ms));
                }
            }
            tokio::select! {
                () = changed => {},
                () = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    }

    /// Release the in-flight ciphertext; live dedup remains until its signed deadline.
    pub fn complete(&mut self) {
        self.inbox
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .receiver
            .complete();
    }
}
