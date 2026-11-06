// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Registration-owned bounded delivery admission and frame-atomic output.
mod element;
use crate::GatewaySendHandle;
use element::Element;
use ramflux_transport::{GatewaySessionFrameSink, TransportError};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
const BYTE_CAP: usize = 4 * 1024 * 1024;
const EMPTY: u64 = u64::MAX;
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
impl Admission {
    pub(crate) fn handled(self) -> bool {
        self != Self::Closed
    }
}
struct Frame {
    bytes: Vec<u8>,
    seq: u64,
}
struct State {
    durable: VecDeque<Element>,
    _transient: VecDeque<Frame>,
    frames: usize,
    bytes: usize,
    hint_inflight: bool,
}
impl State {
    fn occupancy(&self) -> (usize, usize) {
        (self.frames, self.bytes)
    }
}

#[derive(Clone)]
pub(crate) struct PushQueue {
    inner: Arc<Inner>,
}
struct Inner {
    state: Mutex<State>,
    limit: usize,
    slot: AtomicU64,
    retired: Arc<AtomicBool>,
    wake: tokio::sync::Notify,
    changed: tokio::sync::Notify,
    closed: tokio::sync::watch::Sender<bool>,
    #[cfg(test)]
    accesses: Arc<std::sync::atomic::AtomicUsize>,
}
enum Next {
    Frame(Frame),
    Hint(u64),
    Idle,
    Closed,
}
impl PushQueue {
    pub(crate) fn new(limit: usize, closed: tokio::sync::watch::Sender<bool>) -> Self {
        let limit = limit.clamp(16, 256);
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    durable: VecDeque::with_capacity(limit),
                    _transient: VecDeque::new(),
                    frames: 0,
                    bytes: 0,
                    hint_inflight: false,
                }),
                limit,
                slot: AtomicU64::new(EMPTY),
                retired: Arc::new(AtomicBool::new(false)),
                wake: tokio::sync::Notify::new(),
                changed: tokio::sync::Notify::new(),
                closed,
                #[cfg(test)]
                accesses: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }),
        }
    }
    pub(crate) fn retire(&self) {
        self.inner.retired.store(true, Ordering::Release);
        let _ = self.inner.closed.send(true);
        self.inner.wake.notify_one();
    }
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.retired.load(Ordering::Acquire)
    }
    pub(crate) fn try_push(&self, bytes: Vec<u8>, seq: u64) -> Admission {
        if self.is_closed() {
            return Admission::Closed;
        }
        let Ok(mut state) = self.inner.state.try_lock() else {
            return self.overflow(seq);
        };
        if self.is_closed() {
            return Admission::Closed;
        }
        let (frames, bytes_used) = state.occupancy();
        if state.hint_inflight
            || self.inner.slot.load(Ordering::Acquire) != EMPTY
            || frames >= self.inner.limit
            || bytes.len() > BYTE_CAP.saturating_sub(bytes_used)
        {
            return self.overflow(seq);
        }
        state.frames += 1;
        state.bytes += bytes.len();
        state.durable.push_back(Element::new(Frame { bytes, seq }, &self.inner));
        drop(state);
        self.inner.wake.notify_one();
        Admission::Queued
    }
    fn overflow(&self, seq: u64) -> Admission {
        self.inner.slot.fetch_min(seq.saturating_sub(1), Ordering::AcqRel);
        self.inner.wake.notify_one();
        Admission::Overflowed
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
            let after = self.inner.slot.swap(EMPTY, Ordering::AcqRel);
            if after != EMPTY {
                state.hint_inflight = true;
                return Next::Hint(after);
            }
        }
        state.durable.pop_front().map_or(Next::Idle, |e| Next::Frame(e.into_frame()))
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
    pub(crate) async fn install(&self, send: &GatewaySendHandle) -> anyhow::Result<()> {
        let mut sink = tokio::time::timeout(WRITE_DEADLINE, send.lock()).await?;
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
                    if !self.write(&send, &frame.bytes).await {
                        break;
                    }
                    self.complete(Some(&frame));
                }
                Next::Hint(after) => {
                    if let Some(id) = incarnation.as_ref() {
                        let wire = serde_json::to_vec(
                            &ramflux_node_core::SessionPushServerFrame::Resync {
                                incarnation_id: id.clone(),
                                target_delivery_id: target.clone(),
                                after_inbox_seq: after,
                                reason: ramflux_node_core::SessionPushResyncReason::QueueFull,
                            },
                        );
                        let Ok(wire) = wire else {
                            break;
                        };
                        if !self.write(&send, &wire).await {
                            break;
                        }
                    }
                    self.complete(None);
                    tokio::task::yield_now().await;
                }
            }
        }
        self.retire();
        let abandoned = self.inner.state.lock().ok().map(|mut state| {
            state.frames = 0;
            state.bytes = 0;
            std::mem::take(&mut state.durable)
        });
        drop(abandoned);
        if let Ok(mut sink) = tokio::time::timeout(WRITE_DEADLINE, send.lock()).await {
            let _ = sink.finish();
        }
        self.inner.changed.notify_waiters();
    }
    async fn write(&self, send: &GatewaySendHandle, bytes: &[u8]) -> bool {
        write_frame(send, bytes).await.is_ok()
    }

    #[cfg(test)]
    pub(crate) async fn flushed(&self) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.inner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let done = self.inner.state.lock().is_ok_and(|s| {
                    s.frames == 0
                        && !s.hint_inflight
                        && self.inner.slot.load(Ordering::Acquire) == EMPTY
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
            if self.queue.is_closed() || self.finished {
                return Err(TransportError::Quic("registration retired".into()));
            }
            let mut cancellation = CancelledWrite { queue: self.queue.clone(), completed: false };
            let result = self.sink.send_frame(bytes).await;
            cancellation.completed = result.is_ok();
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
mod tests;
