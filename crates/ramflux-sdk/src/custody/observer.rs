// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only cleanup observer shared by every owned-buffer cleanup proof.
//!
//! A [`Session`] owns the process-wide serialization lock for one observed case. Observations
//! are recorded globally (so drops on worker threads are seen) but only for the session's
//! allow-listed labels. `begin` fails loudly instead of deadlocking: a same-thread re-entry
//! panics at once, and a lock held by another test for more than 10 s panics too.
use std::{
    cell::Cell,
    sync::{Mutex, MutexGuard, PoisonError, TryLockError},
    time::{Duration, Instant},
};

pub(crate) struct Observation {
    pub label: &'static str,
    /// Owned capacity of the observed allocation; `bytes` covers all of it.
    pub capacity: usize,
    pub bytes: Vec<u8>,
}
struct State {
    labels: &'static [&'static str],
    items: Vec<Observation>,
}
static SERIAL: Mutex<()> = Mutex::new(());
static STATE: Mutex<Option<State>> = Mutex::new(None);
thread_local! {
    static HELD: Cell<bool> = const { Cell::new(false) };
}
fn state() -> MutexGuard<'static, Option<State>> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One observed case. Scope it in its own block (or `drop` it) before the next `begin`.
#[must_use = "bind the session: `let _s = observer::begin(..)`"]
pub(crate) struct Session {
    _serial: MutexGuard<'static, ()>,
}
impl Drop for Session {
    fn drop(&mut self) {
        // Clear the observations and the thread marker before the serialization lock is released.
        *state() = None;
        HELD.set(false);
    }
}
pub(crate) fn begin(labels: &'static [&'static str]) -> Session {
    assert!(
        !HELD.get(),
        "observer::begin while this thread holds a Session (scope it: r4 section 1)"
    );
    let end = Instant::now() + Duration::from_secs(10);
    let serial = loop {
        match SERIAL.try_lock() {
            Ok(guard) => break guard,
            Err(TryLockError::Poisoned(poisoned)) => break poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                assert!(Instant::now() < end, "observer Session held >10s by another test");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    HELD.set(true);
    *state() = Some(State { labels, items: Vec::new() });
    Session { _serial: serial }
}
/// Records `bytes` (the whole allocation) for an allow-listed label of the active session.
pub(crate) fn inspect_capacity(label: &'static str, capacity: usize, bytes: &[u8]) {
    if let Some(state) = state().as_mut()
        && state.labels.contains(&label)
    {
        state.items.push(Observation { label, capacity, bytes: bytes.to_vec() });
    }
}
#[cfg(target_os = "linux")]
pub(crate) fn inspect(label: &'static str, bytes: &[u8]) {
    inspect_capacity(label, bytes.len(), bytes);
}
pub(crate) fn take() -> Vec<Observation> {
    state().as_mut().map(|state| std::mem::take(&mut state.items)).unwrap_or_default()
}
