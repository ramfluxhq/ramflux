// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One update stream: a bounded queue, a credit counter and a delivery thread.
//!
//! Back-pressure is credit, not an unbounded channel. Rows wait in a queue of at most
//! `max_pending` entries while the host has granted no credit. When the queue is full the
//! queued rows are dropped FROM THE QUEUE ONLY and the host is told the journal sequence to
//! re-read from; the journal still has every row, so nothing is silently lost. Lag and end
//! notices use reserved control capacity and never wait for credit.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use crate::error::{CoreError, code};
use crate::listener::UpdateListener;
use crate::port::{PortSubscription, UpdateSink};
use crate::types::{SubscriptionEnd, UpdateRow};

/// Largest batch handed to one `on_updates` call.
const MAX_BATCH: usize = 64;

struct State {
    credit: u64,
    pending: VecDeque<UpdateRow>,
    /// Rows dropped from the queue since the last lag notice.
    skipped: u64,
    /// Journal sequence of the last row handed to the listener.
    delivered_through: u64,
    end: Option<SubscriptionEnd>,
    port: Option<Box<dyn PortSubscription>>,
}

pub(crate) struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    max_pending: usize,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// End the stream once. Later calls change nothing.
    pub(crate) fn finish(&self, end: SubscriptionEnd) {
        let port = {
            let mut state = self.lock();
            if state.end.is_none() {
                state.end = Some(end);
            }
            state.port.take()
        };
        if let Some(port) = port {
            port.cancel();
        }
        self.changed.notify_all();
    }
}

impl UpdateSink for Shared {
    fn offer(&self, row: UpdateRow) {
        {
            let mut state = self.lock();
            if state.end.is_some() {
                return;
            }
            if state.pending.len() >= self.max_pending {
                let dropped = u64::try_from(state.pending.len()).unwrap_or(u64::MAX);
                state.skipped = state.skipped.saturating_add(dropped).saturating_add(1);
                state.pending.clear();
            } else {
                state.pending.push_back(row);
            }
        }
        self.changed.notify_all();
    }

    fn end(&self, end: SubscriptionEnd) {
        self.finish(end);
    }
}

enum Step {
    Lag { resume_after: u64, skipped: u64 },
    Rows(Vec<UpdateRow>),
    End(SubscriptionEnd),
}

fn next_step(shared: &Shared) -> Step {
    let mut state = shared.lock();
    loop {
        if let Some(end) = state.end {
            return Step::End(end);
        }
        if state.skipped > 0 {
            let skipped = std::mem::take(&mut state.skipped);
            return Step::Lag { resume_after: state.delivered_through, skipped };
        }
        if state.credit > 0 && !state.pending.is_empty() {
            let credit = usize::try_from(state.credit).unwrap_or(usize::MAX);
            let count = credit.min(state.pending.len()).min(MAX_BATCH);
            let rows: Vec<UpdateRow> = state.pending.drain(..count).collect();
            state.credit = state.credit.saturating_sub(u64::try_from(count).unwrap_or(u64::MAX));
            if let Some(last) = rows.last() {
                state.delivered_through = state.delivered_through.max(last.journal_sequence);
            }
            return Step::Rows(rows);
        }
        state = match shared.changed.wait(state) {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
    }
}

fn deliver(shared: &Shared, listener: &dyn UpdateListener) {
    loop {
        // The lock is never held across a listener call.
        let applied = match next_step(shared) {
            Step::Lag { resume_after, skipped } => listener.on_lag(resume_after, skipped),
            Step::Rows(rows) => listener.on_updates(rows),
            Step::End(end) => {
                let _ = listener.on_end(end);
                return;
            }
        };
        if applied.is_err() {
            // The host could not apply the call. Stop producing; the journal keeps the rows.
            shared.finish(SubscriptionEnd::Failed);
        }
    }
}

/// Host handle of one update stream. Dropping the handle cancels the stream.
#[derive(uniffi::Object)]
pub struct Subscription {
    shared: Arc<Shared>,
}

#[uniffi::export]
impl Subscription {
    /// Grant `rows` more update rows. Call it after applying delivered rows.
    pub fn grant(&self, rows: u32) {
        {
            let mut state = self.shared.lock();
            state.credit = state.credit.saturating_add(u64::from(rows));
        }
        self.shared.changed.notify_all();
    }

    /// Stop the stream. Idempotent. The listener receives one final `on_end(Cancelled)`.
    pub fn cancel(&self) {
        self.shared.finish(SubscriptionEnd::Cancelled);
    }

    /// Whether the stream has ended for any reason.
    #[must_use]
    pub fn is_ended(&self) -> bool {
        self.shared.lock().end.is_some()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.shared.finish(SubscriptionEnd::Cancelled);
    }
}

impl Subscription {
    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }
}

/// Create the shared state and start the delivery thread. The caller attaches the core-side
/// subscription with [`attach`] once the core accepted the stream.
///
/// # Errors
/// `InvalidArgument` for a zero queue bound; `Internal` when no thread can be started.
pub(crate) fn open(
    listener: Arc<dyn UpdateListener>,
    initial_credit: u32,
    after_journal_sequence: Option<u64>,
    max_pending: u32,
) -> Result<Arc<Subscription>, CoreError> {
    let max_pending = usize::try_from(max_pending).unwrap_or(usize::MAX);
    if max_pending == 0 {
        return Err(CoreError::plain(code::INVALID_ARGUMENT, "max_pending_updates must be > 0"));
    }
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            credit: u64::from(initial_credit),
            pending: VecDeque::new(),
            skipped: 0,
            delivered_through: after_journal_sequence.unwrap_or(0),
            end: None,
            port: None,
        }),
        changed: Condvar::new(),
        max_pending,
    });
    let worker = Arc::clone(&shared);
    std::thread::Builder::new()
        .name("ramflux-ffi-updates".to_owned())
        .spawn(move || deliver(&worker, listener.as_ref()))
        .map_err(|error| {
            CoreError::plain(code::INTERNAL, format!("update delivery thread: {error}"))
        })?;
    Ok(Arc::new(Subscription { shared }))
}

/// Attach the core-side handle. If the stream already ended, the handle is cancelled at once.
pub(crate) fn attach(subscription: &Subscription, port: Box<dyn PortSubscription>) {
    let rejected = {
        let mut state = subscription.shared.lock();
        if state.end.is_some() {
            Some(port)
        } else {
            state.port = Some(port);
            None
        }
    };
    if let Some(port) = rejected {
        port.cancel();
    }
}
