// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The waiter of one `execute` call: claim gate, cancel handle, deadline and reply cell.
//!
//! UniFFI has no built-in cancellation of a Rust future, so cancellation is this explicit
//! handle. The rule the gate enforces: a waiter that ends BEFORE the core claimed the request
//! withdraws it and nothing runs; a waiter that ends AFTER the claim only stops waiting, and
//! the core keeps the execution and its receipt. The two cases are decided by one atomic
//! compare-and-swap, so a "no effect" answer is never given for a request that was claimed.

use std::collections::BinaryHeap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use crate::error::CoreError;
use crate::types::{CoreResponse, ExecuteOutcome, WaiterEnd};

const GATE_OPEN: u8 = 0;
const GATE_CLAIMED: u8 = 1;
const GATE_CLAIMED_LIFECYCLE: u8 = 2;
const GATE_WITHDRAWN: u8 = 3;

/// What kind of work the core claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimKind {
    /// An ordinary request. After admission a mutation may already have effects.
    Ordinary,
    /// A keyed lifecycle operation. The supervisor retains it and its receipt.
    Lifecycle,
}

/// One-shot arbiter between "the core starts this request" and "the waiter gave up first".
#[derive(Debug, Default)]
pub struct ClaimGate {
    state: AtomicU8,
}

impl ClaimGate {
    /// Called by the core immediately before the first effect of the request. `false` means
    /// the waiter withdrew first: the core must drop the request without any effect.
    #[must_use]
    pub fn try_claim(&self, kind: ClaimKind) -> bool {
        let claimed = match kind {
            ClaimKind::Ordinary => GATE_CLAIMED,
            ClaimKind::Lifecycle => GATE_CLAIMED_LIFECYCLE,
        };
        self.state
            .compare_exchange(GATE_OPEN, claimed, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Called by the waiter when it ends. `true` means the request was never claimed and
    /// now never will be.
    fn try_withdraw(&self) -> bool {
        self.state
            .compare_exchange(GATE_OPEN, GATE_WITHDRAWN, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn claimed_lifecycle(&self) -> bool {
        self.state.load(Ordering::Acquire) == GATE_CLAIMED_LIFECYCLE
    }
}

#[derive(Default)]
struct CellState {
    reply: Option<Result<CoreResponse, CoreError>>,
    end: Option<WaiterEnd>,
    waker: Option<Waker>,
}

/// Shared between the waiter future, the reply sender, the cancel handle and the deadline.
#[derive(Default)]
pub(crate) struct WaitCell {
    state: Mutex<CellState>,
}

impl WaitCell {
    fn with_state<T>(&self, apply: impl FnOnce(&mut CellState) -> T) -> T {
        // A poisoned cell still holds consistent plain data; keep serving it.
        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        apply(&mut guard)
    }

    /// Record why the waiter ends. The first reason wins; a reply that already arrived wins
    /// over every reason.
    pub(crate) fn end(&self, end: WaiterEnd) {
        let waker = self.with_state(|state| {
            if state.reply.is_none() && state.end.is_none() {
                state.end = Some(end);
            }
            state.waker.take()
        });
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn reply(&self, reply: Result<CoreResponse, CoreError>) {
        let waker = self.with_state(|state| {
            if state.reply.is_none() {
                state.reply = Some(reply);
            }
            state.waker.take()
        });
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The reply end handed to the core. Dropping it without a reply ends the waiter with
/// [`WaiterEnd::ReplyLost`]; whether that is "no effect" is decided by the claim gate alone.
pub struct ReplySender {
    cell: Arc<WaitCell>,
    sent: bool,
}

impl ReplySender {
    /// Deliver the reply. The execution result stands whether or not a waiter still listens.
    pub fn send(mut self, reply: Result<CoreResponse, CoreError>) {
        self.sent = true;
        self.cell.reply(reply);
    }
}

impl Drop for ReplySender {
    fn drop(&mut self) {
        if !self.sent {
            self.cell.end(WaiterEnd::ReplyLost);
        }
    }
}

/// Host-held cancel handle. One handle may cover several `execute` calls; cancelling it ends
/// every waiter registered on it, and a call started on a cancelled handle ends at once
/// (before any claim). `cancel` is idempotent and never blocks.
#[derive(Default, uniffi::Object)]
pub struct CancelHandle {
    cancelled: AtomicBool,
    waiters: Mutex<Vec<Weak<WaitCell>>>,
}

#[uniffi::export]
impl CancelHandle {
    /// A fresh, not cancelled handle.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Stop waiting. Does not undo, and does not prove the absence of, an execution the core
    /// already claimed.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let waiters = match self.waiters.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        for waiter in waiters {
            if let Some(cell) = waiter.upgrade() {
                cell.end(WaiterEnd::Cancelled);
            }
        }
    }

    /// Whether `cancel` was called.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl CancelHandle {
    fn register(&self, cell: &Arc<WaitCell>) {
        {
            let mut guard = match self.waiters.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.retain(|waiter| waiter.strong_count() > 0);
            guard.push(Arc::downgrade(cell));
        }
        // Checked after registration so a concurrent `cancel` cannot fall between the two.
        if self.is_cancelled() {
            cell.end(WaiterEnd::Cancelled);
        }
    }
}

/// The waiting half of one request.
pub(crate) struct Waiter {
    cell: Arc<WaitCell>,
    gate: Arc<ClaimGate>,
    operation_id: Option<String>,
}

/// Build the two halves of one request: what the binding awaits and what the core receives.
pub(crate) fn waiter(
    cancel: &CancelHandle,
    deadline: Duration,
    operation_id: Option<String>,
) -> (Waiter, Arc<ClaimGate>, ReplySender) {
    let cell = Arc::new(WaitCell::default());
    let gate = Arc::new(ClaimGate::default());
    cancel.register(&cell);
    deadlines().arm(deadline, &cell);
    let sender = ReplySender { cell: Arc::clone(&cell), sent: false };
    (Waiter { cell, gate: Arc::clone(&gate), operation_id }, gate, sender)
}

impl Future for Waiter {
    type Output = Result<ExecuteOutcome, CoreError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let (reply, end) = this.cell.with_state(|state| {
            let reply = state.reply.take();
            if reply.is_none() && state.end.is_none() {
                state.waker = Some(context.waker().clone());
            }
            (reply, state.end)
        });
        if let Some(reply) = reply {
            return Poll::Ready(reply.map(|response| ExecuteOutcome::Completed { response }));
        }
        let Some(end) = end else {
            return Poll::Pending;
        };
        if this.gate.try_withdraw() {
            return Poll::Ready(Ok(ExecuteOutcome::EndedBeforeClaim { end }));
        }
        Poll::Ready(Ok(ExecuteOutcome::EndedAfterClaim {
            end,
            operation_id: this.operation_id.clone(),
            lifecycle: this.gate.claimed_lifecycle(),
        }))
    }
}

struct Armed {
    at: Instant,
    cell: Weak<WaitCell>,
}

impl PartialEq for Armed {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
    }
}
impl Eq for Armed {}
impl PartialOrd for Armed {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Armed {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reversed: the heap yields the earliest deadline first.
        other.at.cmp(&self.at)
    }
}

/// One timer thread for all request deadlines. It needs no async runtime, because the foreign
/// executor (Swift concurrency, Kotlin coroutines) polls binding futures.
pub(crate) struct Deadlines {
    queue: Mutex<BinaryHeap<Armed>>,
    changed: Condvar,
    started: AtomicBool,
}

fn deadlines() -> &'static Arc<Deadlines> {
    static DEADLINES: OnceLock<Arc<Deadlines>> = OnceLock::new();
    DEADLINES.get_or_init(|| {
        Arc::new(Deadlines {
            queue: Mutex::new(BinaryHeap::new()),
            changed: Condvar::new(),
            started: AtomicBool::new(false),
        })
    })
}

impl Deadlines {
    fn arm(self: &Arc<Self>, after: Duration, cell: &Arc<WaitCell>) {
        let Some(at) = Instant::now().checked_add(after) else {
            return;
        };
        {
            let mut queue = match self.queue.lock() {
                Ok(queue) => queue,
                Err(poisoned) => poisoned.into_inner(),
            };
            queue.push(Armed { at, cell: Arc::downgrade(cell) });
        }
        self.changed.notify_one();
        if !self.started.swap(true, Ordering::AcqRel) {
            let timer = Arc::clone(self);
            let spawned = std::thread::Builder::new()
                .name("ramflux-ffi-deadlines".to_owned())
                .spawn(move || timer.run());
            if spawned.is_err() {
                // No timer thread: the core still enforces the same deadline on its side.
                self.started.store(false, Ordering::Release);
            }
        }
    }

    fn run(&self) {
        let mut queue = match self.queue.lock() {
            Ok(queue) => queue,
            Err(poisoned) => poisoned.into_inner(),
        };
        loop {
            let now = Instant::now();
            let mut due = Vec::new();
            while queue.peek().is_some_and(|armed| armed.at <= now) {
                if let Some(armed) = queue.pop() {
                    due.push(armed);
                }
            }
            if !due.is_empty() {
                drop(queue);
                for armed in due {
                    if let Some(cell) = armed.cell.upgrade() {
                        cell.end(WaiterEnd::Deadline);
                    }
                }
                queue = match self.queue.lock() {
                    Ok(queue) => queue,
                    Err(poisoned) => poisoned.into_inner(),
                };
                continue;
            }
            let wait = queue.peek().map(|armed| armed.at.saturating_duration_since(now));
            queue = match wait {
                Some(wait) => match self.changed.wait_timeout(queue, wait) {
                    Ok((queue, _)) => queue,
                    Err(poisoned) => poisoned.into_inner().0,
                },
                None => match self.changed.wait(queue) {
                    Ok(queue) => queue,
                    Err(poisoned) => poisoned.into_inner(),
                },
            };
        }
    }
}
