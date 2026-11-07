// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Registration-owned bounded delivery admission and frame-atomic output.
mod element;
mod state_mutex;
use crate::GatewaySendHandle;
use element::Element;
use ramflux_transport::{GatewaySessionFrameSink, TransportError};
use state_mutex::StateMutex;
#[cfg(test)]
use std::sync::Mutex;
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
pub(crate) const BYTE_CAP: usize = 4 * 1024 * 1024;
/// Per-session transient frame occupancy, including the in-flight write.
pub(crate) const TRANSIENT_FRAME_CAP: usize = 64;
/// Per-session transient byte occupancy, including the in-flight write.
pub(crate) const TRANSIENT_BYTE_CAP: usize = 262_144;
const EMPTY: u64 = u64::MAX;
#[cfg(test)]
static BYPASS_TRANSIENT_BOUND: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(crate) fn set_bypass_transient_bound(bypass: bool) {
    BYPASS_TRANSIENT_BOUND.store(bypass, std::sync::atomic::Ordering::SeqCst);
}
pub(crate) const WRITE_DEADLINE: Duration = Duration::from_secs(15);
// Sink admission is queue waiting, with its own bound; only the I/O consumes 15s.
const SINK_ADMISSION_DEADLINE: Duration = Duration::from_secs(60);
pub(crate) async fn write_frame(
    send: &GatewaySendHandle,
    bytes: &[u8],
) -> Result<(), crate::session_response::ClientWriteFailure> {
    use crate::session_response::ClientWriteFailure;
    let mut sink =
        tokio::time::timeout(SINK_ADMISSION_DEADLINE, send.lock()).await.map_err(|_| {
            ClientWriteFailure(TransportError::Quic("gateway sink admission deadline".into()))
        })?;
    tokio::time::timeout(WRITE_DEADLINE, sink.send_frame(bytes))
        .await
        .map_err(|_| {
            ClientWriteFailure(TransportError::Quic("gateway frame write deadline".into()))
        })?
        .map_err(ClientWriteFailure)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Queued,
    Overflowed,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransientAdmission {
    Queued,
    QueueFull,
    Closed,
}

struct Frame {
    bytes: Vec<u8>,
    seq: u64,
    incarnation: Option<String>,
}
struct TransientFrame {
    bytes: Vec<u8>,
    expires_at_ms: u64,
}
struct State {
    durable: VecDeque<Element>,
    transient: VecDeque<TransientFrame>,
    frames: usize,
    bytes: usize,
    transient_frames: usize,
    transient_bytes: usize,
    hint_inflight: bool,
    coverage: crate::issued_probe::Coverage,
    probe: Option<(u64, u64)>,
    detached_watermark: u64,
}
impl State {
    fn occupancy(&self) -> (usize, usize) {
        (self.frames, self.bytes)
    }
    fn transient_occupancy(&self) -> (usize, usize) {
        (self.transient_frames, self.transient_bytes)
    }
}

#[derive(Clone)]
pub(crate) struct PushQueue {
    inner: Arc<Inner>,
}
struct Inner {
    state: StateMutex,
    incarnation: std::sync::OnceLock<Option<String>>,
    #[cfg(test)]
    before_write: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Semaphore>)>>,
    #[cfg(test)]
    admission_probe: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    limit: usize,
    slot: AtomicU64,
    not_pushed: AtomicU64,
    hint_watermark: AtomicU64,
    retirement_requested: AtomicBool,
    retired: Arc<AtomicBool>,
    wake: tokio::sync::Notify,
    changed: tokio::sync::Notify,
    closed: tokio::sync::watch::Sender<bool>,
    #[cfg(test)]
    accesses: Arc<std::sync::atomic::AtomicUsize>,
    clock: AtomicU64,
}
enum Next {
    Frame(Frame),
    Transient(TransientFrame),
    Hint(u64, bool),
    Probe(u64, u64),
    Idle,
    Closed,
}
impl PushQueue {
    pub(crate) fn new(limit: usize, closed: tokio::sync::watch::Sender<bool>) -> Self {
        let limit = limit.clamp(16, 256);
        Self {
            inner: Arc::new(Inner {
                incarnation: std::sync::OnceLock::new(),
                #[cfg(test)]
                before_write: Mutex::new(None),
                #[cfg(test)]
                admission_probe: Mutex::new(None),
                state: StateMutex::new(State {
                    durable: VecDeque::with_capacity(limit),
                    transient: VecDeque::with_capacity(TRANSIENT_FRAME_CAP),
                    frames: 0,
                    bytes: 0,
                    transient_frames: 0,
                    transient_bytes: 0,
                    hint_inflight: false,
                    coverage: crate::issued_probe::Coverage::default(),
                    probe: None,
                    detached_watermark: 0,
                }),
                limit,
                slot: AtomicU64::new(EMPTY),
                not_pushed: AtomicU64::new(EMPTY),
                hint_watermark: AtomicU64::new(0),
                retirement_requested: AtomicBool::new(false),
                retired: Arc::new(AtomicBool::new(false)),
                wake: tokio::sync::Notify::new(),
                changed: tokio::sync::Notify::new(),
                closed,
                #[cfg(test)]
                accesses: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                clock: AtomicU64::new(0),
            }),
        }
    }
    pub(crate) fn retire(&self) {
        self.inner.retired.store(true, Ordering::Release);
        let _ = self.inner.closed.send(true);
        if let Ok(mut state) = self.inner.state.lock() {
            for frame in std::mem::take(&mut state.transient) {
                state.transient_frames = state.transient_frames.saturating_sub(1);
                state.transient_bytes = state.transient_bytes.saturating_sub(frame.bytes.len());
            }
        }
        self.inner.wake.notify_one();
        self.inner.changed.notify_waiters();
    }
    pub(crate) fn prevent_admission(&self) {
        self.inner.retirement_requested.store(true, Ordering::Release);
    }
    #[cfg(test)]
    pub(crate) fn set_admission_probe(&self, probe: Box<dyn Fn() + Send + Sync>) {
        *self.inner.admission_probe.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(probe);
    }
    #[cfg(test)]
    pub(crate) fn park_next_write(
        &self,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Semaphore>,
    ) {
        *self.inner.before_write.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((entered, release));
    }
    pub(crate) fn request_retirement(&self, send: GatewaySendHandle) {
        self.inner.retirement_requested.store(true, Ordering::Release);
        let queue = self.clone();
        tokio::spawn(async move {
            queue.retire_with_sink(&send).await;
        });
    }
    pub(crate) async fn retire_with_sink(&self, send: &GatewaySendHandle) {
        self.inner.retirement_requested.store(true, Ordering::Release);
        if let Ok(mut sink) = tokio::time::timeout(SINK_ADMISSION_DEADLINE, send.lock()).await {
            self.retire();
            let _ = sink.finish();
        } else {
            self.retire();
        }
    }
    pub(crate) fn not_pushed(&self, seq: u64) -> bool {
        if self.is_closed() || self.inner.retirement_requested.load(Ordering::Acquire) {
            return false;
        }
        self.inner.hint_watermark.fetch_max(seq, Ordering::AcqRel);
        self.inner.not_pushed.fetch_min(seq.saturating_sub(1), Ordering::AcqRel);
        self.inner.wake.notify_one();
        true
    }
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.retired.load(Ordering::Acquire)
    }
    pub(crate) fn try_push(&self, bytes: Vec<u8>, seq: u64) -> Admission {
        self.try_push_versioned(bytes, seq, None)
    }
    pub(crate) fn try_push_versioned(
        &self,
        bytes: Vec<u8>,
        seq: u64,
        incarnation: Option<String>,
    ) -> Admission {
        #[cfg(test)]
        if let Ok(probe) = self.inner.admission_probe.lock()
            && let Some(probe) = probe.as_ref()
        {
            probe();
        }
        if self.is_closed() || self.inner.retirement_requested.load(Ordering::Acquire) {
            return Admission::Closed;
        }
        let Ok(mut state) = self.inner.state.lock() else {
            self.retire();
            return Admission::Closed;
        };
        if self.is_closed() || self.inner.retirement_requested.load(Ordering::Acquire) {
            return Admission::Closed;
        }
        let (frames, bytes_used) = state.occupancy();
        if state.hint_inflight
            || self.inner.slot.load(Ordering::Acquire) != EMPTY
            || self.inner.not_pushed.load(Ordering::Acquire) != EMPTY
            || state.probe.is_some()
            || frames >= self.inner.limit
            || bytes.len() > BYTE_CAP.saturating_sub(bytes_used)
        {
            return self.overflow(seq);
        }
        state.frames += 1;
        state.bytes += bytes.len();
        state.durable.push_back(Element::new(Frame { bytes, seq, incarnation }, &self.inner));
        drop(state);
        self.inner.wake.notify_one();
        Admission::Queued
    }
    /// Enqueue a deadline-aware ephemeral frame on the registration-owned
    /// transient FIFO. Occupancy includes the in-flight write. Transients never
    /// touch durable occupancy, the Resync slot, or coverage.
    pub(crate) fn try_push_transient(
        &self,
        bytes: Vec<u8>,
        expires_at_ms: u64,
    ) -> TransientAdmission {
        if self.is_closed() || self.inner.retirement_requested.load(Ordering::Acquire) {
            return TransientAdmission::Closed;
        }
        let Ok(mut state) = self.inner.state.lock() else {
            self.retire();
            return TransientAdmission::Closed;
        };
        if self.is_closed() || self.inner.retirement_requested.load(Ordering::Acquire) {
            return TransientAdmission::Closed;
        }
        let (frames, used) = state.transient_occupancy();
        #[cfg(test)]
        let bypass = BYPASS_TRANSIENT_BOUND.load(Ordering::SeqCst);
        #[cfg(not(test))]
        let bypass = false;
        if !bypass
            && (frames >= TRANSIENT_FRAME_CAP
                || bytes.len() > TRANSIENT_BYTE_CAP.saturating_sub(used))
        {
            return TransientAdmission::QueueFull;
        }
        state.transient_frames = state.transient_frames.saturating_add(1);
        state.transient_bytes = state.transient_bytes.saturating_add(bytes.len());
        state.transient.push_back(TransientFrame { bytes, expires_at_ms });
        drop(state);
        self.inner.wake.notify_one();
        TransientAdmission::Queued
    }
    #[cfg(test)]
    pub(crate) fn ephemeral_len(&self) -> usize {
        self.inner.state.lock().map_or(0, |state| state.transient_occupancy().0)
    }
    fn overflow(&self, seq: u64) -> Admission {
        self.inner.hint_watermark.fetch_max(seq, Ordering::AcqRel);
        self.inner.slot.fetch_min(seq.saturating_sub(1), Ordering::AcqRel);
        self.inner.wake.notify_one();
        Admission::Overflowed
    }
    #[cfg(test)]
    pub(crate) fn probe_pending(&self) -> bool {
        self.inner.state.lock().is_ok_and(|s| s.probe.is_some())
    }
    pub(crate) fn observe_issued(&self, issued: Option<u64>) {
        if let Ok(mut state) = self.inner.state.lock() {
            if let Some(hint) = state.coverage.observe(issued) {
                state.probe = Some(hint);
                self.inner.wake.notify_one();
            } else if issued.is_none() {
                state.probe = None;
            }
        }
    }
    fn offered_wire(&self, bytes: &[u8]) {
        // Ignore ciphertext fields without allocating another payload-sized JSON tree.
        #[derive(serde::Deserialize)]
        struct Entry {
            inbox_seq: u64,
        }
        #[derive(serde::Deserialize)]
        struct Offered<'a> {
            frame_type: &'a str,
            entry: Option<Entry>,
            after_inbox_seq: Option<u64>,
            covered_through_seq: Option<u64>,
        }
        if let Ok(value) = serde_json::from_slice::<Offered<'_>>(bytes)
            && let Ok(mut state) = self.inner.state.lock()
        {
            let range = match value.frame_type {
                "deliver" => value.entry.map(|e| (e.inbox_seq, e.inbox_seq)),
                // The completed response is scoped to the client's requested cursor.
                // Its covered watermark is the offered baseline for this registration.
                "resume_page" => {
                    value.after_inbox_seq.zip(value.covered_through_seq).map(|(_, b)| (1, b))
                }
                _ => None,
            };
            if let Some((first, last)) = range
                && !state.coverage.offered(first, last)
            {
                self.inner.hint_watermark.fetch_max(last, Ordering::AcqRel);
                self.inner.not_pushed.fetch_min(state.coverage.prefix, Ordering::AcqRel);
                self.inner.wake.notify_one();
            }
            if state.probe.is_some_and(|(_, issued)| issued <= state.coverage.prefix) {
                state.probe = None;
                self.inner.changed.notify_waiters();
            }
        }
    }
    fn next(&self) -> Next {
        let Ok(mut state) = self.inner.state.lock() else {
            return Next::Closed;
        };
        if self.is_closed() {
            return Next::Closed;
        }
        let (frames, bytes) = state.occupancy();
        if frames <= self.inner.limit / 2 && bytes <= BYTE_CAP / 2 {
            let overflow = self.inner.slot.swap(EMPTY, Ordering::AcqRel);
            let not_pushed = self.inner.not_pushed.swap(EMPTY, Ordering::AcqRel);
            let after = overflow.min(not_pushed);
            if after != EMPTY {
                state.hint_inflight = true;
                state.detached_watermark = self.inner.hint_watermark.swap(0, Ordering::AcqRel);
                return Next::Hint(after, not_pushed != EMPTY);
            }
        }
        if frames <= self.inner.limit / 2
            && bytes <= BYTE_CAP / 2
            && let Some((after, issued)) = state.probe.take()
            && issued > state.coverage.prefix
        {
            state.hint_inflight = true;
            return Next::Probe(after.max(state.coverage.prefix), issued);
        }
        if let Some(frame) = state.durable.pop_front() {
            return Next::Frame(frame.into_frame());
        }
        self.take_transient(&mut state)
    }
    fn wall_clock_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
    /// Forced clock (tests only, 0 = unset) or wall clock; production never sets the forced clock.
    fn clock_ms(&self) -> u64 {
        let forced = self.inner.clock.load(Ordering::Acquire);
        if forced != 0 { forced } else { Self::wall_clock_ms() }
    }
    fn take_transient(&self, state: &mut State) -> Next {
        let now = self.clock_ms();
        let mut dropped = false;
        while let Some(front) = state.transient.front() {
            if now < front.expires_at_ms {
                let Some(frame) = state.transient.pop_front() else {
                    break;
                };
                return Next::Transient(frame);
            }
            let Some(expired) = state.transient.pop_front() else {
                break;
            };
            state.transient_frames = state.transient_frames.saturating_sub(1);
            state.transient_bytes = state.transient_bytes.saturating_sub(expired.bytes.len());
            dropped = true;
        }
        if dropped {
            self.inner.changed.notify_waiters();
        }
        Next::Idle
    }
    fn complete(&self, frame: Option<&Frame>) {
        if let Ok(mut state) = self.inner.state.lock() {
            if let Some(frame) = frame {
                state.frames -= 1;
                state.bytes -= frame.bytes.len();
            } else {
                state.hint_inflight = false;
            }
        }
        self.inner.changed.notify_waiters();
    }
    fn complete_transient(&self, frame: &TransientFrame) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.transient_frames = state.transient_frames.saturating_sub(1);
            state.transient_bytes = state.transient_bytes.saturating_sub(frame.bytes.len());
        }
        self.inner.changed.notify_waiters();
    }
    #[cfg(test)]
    pub(crate) fn set_clock_ms(&self, now_ms: u64) {
        self.inner.clock.store(now_ms, Ordering::Release);
    }
    pub(crate) async fn install(
        &self,
        send: &GatewaySendHandle,
        incarnation: Option<String>,
    ) -> anyhow::Result<()> {
        let mut sink = tokio::time::timeout(WRITE_DEADLINE, send.lock()).await?;
        let _ = self.inner.incarnation.set(incarnation);
        let old = std::mem::replace(&mut *sink, Box::new(EmptySink));
        *sink = Box::new(GuardedSink { sink: old, queue: self.clone(), finished: false });
        Ok(())
    }
    pub(crate) async fn run(
        &self,
        send: GatewaySendHandle,
        target: String,
        incarnation: Option<String>,
    ) {
        loop {
            let notified = self.inner.wake.notified();
            match self.next() {
                Next::Closed => break,
                Next::Idle => notified.await,
                Next::Frame(frame) => {
                    tracing::trace!(inbox_seq = frame.seq, "writing queued delivery");
                    if !self.write(&send, &frame.bytes, frame.incarnation.as_deref(), None).await {
                        break;
                    }
                    self.complete(Some(&frame));
                }
                Next::Transient(frame) => {
                    let deadline = Some(frame.expires_at_ms);
                    if !self.write(&send, &frame.bytes, incarnation.as_deref(), deadline).await {
                        break;
                    }
                    self.complete_transient(&frame);
                }
                Next::Probe(after, issued) => {
                    if let Some(id) = incarnation.as_ref() {
                        let wire = serde_json::to_vec(
                            &ramflux_node_core::SessionPushServerFrame::Resync {
                                incarnation_id: id.clone(),
                                target_delivery_id: target.clone(),
                                after_inbox_seq: after,
                                reason: ramflux_node_core::SessionPushResyncReason::NotPushed,
                            },
                        );
                        let Ok(wire) = wire else {
                            break;
                        };
                        // Recheck under the sink mutex: a completed Resume may have filled the hole.
                        if !self.write_probe(&send, &wire, issued).await {
                            break;
                        }
                    }
                    self.complete(None);
                }
                Next::Hint(after, not_pushed) => {
                    if let Some(id) = incarnation.as_ref() {
                        let wire = serde_json::to_vec(
                            &ramflux_node_core::SessionPushServerFrame::Resync {
                                incarnation_id: id.clone(),
                                target_delivery_id: target.clone(),
                                after_inbox_seq: after,
                                reason: if not_pushed {
                                    ramflux_node_core::SessionPushResyncReason::NotPushed
                                } else {
                                    ramflux_node_core::SessionPushResyncReason::QueueFull
                                },
                            },
                        );
                        let Ok(wire) = wire else {
                            break;
                        };
                        if !self.write(&send, &wire, incarnation.as_deref(), None).await {
                            break;
                        }
                    }
                    if let Ok(mut state) = self.inner.state.lock() {
                        let first = state.coverage.prefix.saturating_add(1);
                        let issued = state.detached_watermark;
                        state.coverage.offered(first, issued);
                        state.detached_watermark = 0;
                    }
                    self.complete(None);
                    tokio::task::yield_now().await;
                }
            }
        }
        self.retire_with_sink(&send).await;
        self.inner.slot.store(EMPTY, Ordering::Release);
        self.inner.not_pushed.store(EMPTY, Ordering::Release);
        let abandoned = self.inner.state.lock().ok().map(|mut state| {
            state.frames = 0;
            state.bytes = 0;
            state.transient_frames = 0;
            state.transient_bytes = 0;
            let durable = std::mem::take(&mut state.durable);
            let transient = std::mem::take(&mut state.transient);
            (durable, transient)
        });
        drop(abandoned);
        self.inner.changed.notify_waiters();
    }
    async fn write_probe(&self, send: &GatewaySendHandle, wire: &[u8], issued: u64) -> bool {
        let Ok(mut sink) = tokio::time::timeout(SINK_ADMISSION_DEADLINE, send.lock()).await else {
            return false;
        };
        if self.inner.state.lock().is_ok_and(|s| s.coverage.prefix >= issued) {
            return true;
        }
        if !tokio::time::timeout(WRITE_DEADLINE, sink.send_frame(wire))
            .await
            .is_ok_and(|r| r.is_ok())
        {
            return false;
        }
        if let Ok(mut state) = self.inner.state.lock() {
            let first = state.coverage.prefix.saturating_add(1);
            state.coverage.offered(first, issued);
        }
        true
    }
    /// Writes one frame under the sink mutex. `expires_at_ms` is the transient deadline:
    /// it is re-checked after the mutex is acquired, so a frame selected before its deadline
    /// that waited for the sink past it is dropped silently (`true`, nothing written).
    async fn write(
        &self,
        send: &GatewaySendHandle,
        bytes: &[u8],
        incarnation: Option<&str>,
        expires_at_ms: Option<u64>,
    ) -> bool {
        #[cfg(test)]
        {
            let barrier = self.inner.before_write.lock().ok().and_then(|mut b| b.take());
            if let Some((entered, release)) = barrier {
                entered.notify_one();
                let result = tokio::time::timeout(Duration::from_secs(10), release.acquire()).await;
                assert!(
                    matches!(result, Ok(Ok(_))),
                    "queue write release barrier failed: {result:?}"
                );
                if let Ok(Ok(permit)) = result {
                    permit.forget();
                }
            }
        }
        let Ok(mut sink) = tokio::time::timeout(SINK_ADMISSION_DEADLINE, send.lock()).await else {
            return false;
        };
        let expected = self.inner.incarnation.get().and_then(|id| id.as_deref());
        if incarnation != expected {
            self.retire();
            return false;
        }
        if expires_at_ms.is_some_and(|expires| self.clock_ms() >= expires) {
            return true;
        }
        tokio::time::timeout(WRITE_DEADLINE, sink.send_frame(bytes)).await.is_ok_and(|r| r.is_ok())
    }

    #[cfg(test)]
    pub(crate) async fn flushed(&self) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let changed = self.inner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let done = self.inner.state.lock().is_ok_and(|s| {
                    s.frames == 0
                        && s.transient_frames == 0
                        && !s.hint_inflight
                        && s.probe.is_none()
                        && self.inner.slot.load(Ordering::Acquire) == EMPTY
                        && self.inner.not_pushed.load(Ordering::Acquire) == EMPTY
                });
                if done || self.is_closed() {
                    return;
                }
                changed.await;
            }
        })
        .await?;
        Ok(())
    }
}
struct EmptySink;
impl GatewaySessionFrameSink for EmptySink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        Box::pin(async { Err(TransportError::Quic("registration not installed".into())) })
    }
}
struct GuardedSink {
    sink: Box<dyn GatewaySessionFrameSink + Send>,
    queue: PushQueue,
    finished: bool,
}
impl GatewaySessionFrameSink for GuardedSink {
    fn finish(&mut self) -> Result<(), TransportError> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        self.sink.finish()
    }
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        Box::pin(async move {
            if self.queue.is_closed()
                || self.queue.inner.retirement_requested.load(Ordering::Acquire)
                || self.finished
            {
                return Err(TransportError::Quic("registration retired".into()));
            }
            let mut cancellation = CancelledWrite { queue: self.queue.clone(), completed: false };
            let result = tokio::time::timeout(WRITE_DEADLINE, self.sink.send_frame(bytes))
                .await
                .unwrap_or_else(|_| {
                    Err(TransportError::Quic("gateway sink write deadline".into()))
                });
            cancellation.completed = result.is_ok();
            if result.is_ok() {
                self.queue.offered_wire(bytes);
            }
            result
        })
    }
}
struct CancelledWrite {
    queue: PushQueue,
    completed: bool,
}
impl Drop for CancelledWrite {
    fn drop(&mut self) {
        if !self.completed {
            self.queue.retire();
        }
    }
}

#[cfg(test)]
mod retirement_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transient_tests;
