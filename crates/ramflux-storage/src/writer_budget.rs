// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-thread yield between durable commits when a command is queued.
//!
//! The budget is armed only on the account writer thread. A pause is reported
//! before the next top-level `BEGIN IMMEDIATE`, after at least one commit in
//! the current attempt, and only while a pause scope is open. Durability
//! pragmas are not part of this budget.

use std::cell::{Cell, RefCell};
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static SCOPE: Cell<u32> = const { Cell::new(0) };
    static SERVICE: Cell<u32> = const { Cell::new(0) };
    static SAW_COMMIT: Cell<bool> = const { Cell::new(false) };
    static STARTED: Cell<Option<Instant>> = const { Cell::new(None) };
    static SLICE: Cell<Duration> = const { Cell::new(Duration::from_secs(1)) };
    static WAITING: RefCell<Option<Arc<AtomicUsize>>> = const { RefCell::new(None) };
}

#[derive(Debug)]
struct PauseSentinel;

impl fmt::Display for PauseSentinel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("writer pause")
    }
}

impl Error for PauseSentinel {}

/// Arms the caller thread. Drop disarms it, including on unwind.
pub struct Armed {
    active: bool,
}

impl Armed {
    #[must_use]
    pub fn arm(waiting: Arc<AtomicUsize>, slice: Duration) -> Self {
        ARMED.set(true);
        SLICE.set(slice);
        let _ = WAITING.try_with(|slot| {
            if let Ok(mut guard) = slot.try_borrow_mut() {
                *guard = Some(waiting);
            }
        });
        SAW_COMMIT.set(false);
        STARTED.set(Some(Instant::now()));
        Self { active: true }
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        if self.active {
            disarm();
        }
    }
}

fn disarm() {
    ARMED.set(false);
    SCOPE.set(0);
    SERVICE.set(0);
    SAW_COMMIT.set(false);
    STARTED.set(None);
    let _ = WAITING.try_with(|slot| {
        if let Ok(mut guard) = slot.try_borrow_mut() {
            *guard = None;
        }
    });
}

/// One background attempt. The first commit of the attempt cannot pause.
pub fn begin_attempt() {
    if ARMED.get() {
        SAW_COMMIT.set(false);
        STARTED.set(Some(Instant::now()));
    }
}

/// Records a top-level `COMMIT` on the caller thread.
pub fn note_durable_commit() {
    if ARMED.get() {
        SAW_COMMIT.set(true);
    }
}

/// Opens a region whose next top-level immediate transaction may pause.
pub struct PauseScope;

impl PauseScope {
    #[must_use]
    pub fn enter() -> Self {
        SCOPE.set(SCOPE.get().saturating_add(1));
        Self
    }
}

impl Drop for PauseScope {
    fn drop(&mut self) {
        SCOPE.set(SCOPE.get().saturating_sub(1));
    }
}

/// Suppresses a nested pause while one queued command is applied.
pub struct ServiceGuard;

impl ServiceGuard {
    #[must_use]
    pub fn enter() -> Option<Self> {
        if SERVICE.get() > 0 {
            return None;
        }
        SERVICE.set(1);
        Some(Self)
    }
}

impl Drop for ServiceGuard {
    fn drop(&mut self) {
        SERVICE.set(0);
    }
}

#[must_use]
pub fn should_pause() -> bool {
    if !ARMED.get() || SCOPE.get() == 0 || SERVICE.get() > 0 || !SAW_COMMIT.get() {
        return false;
    }
    if !command_waiting() {
        return false;
    }
    let slice = SLICE.get();
    STARTED.get().is_some_and(|started| started.elapsed() >= slice)
}

fn command_waiting() -> bool {
    WAITING
        .try_with(|slot| {
            slot.try_borrow()
                .ok()
                .and_then(|guard| guard.as_ref().map(|waiting| waiting.load(Ordering::Acquire) > 0))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

pub(crate) fn pause_error() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(PauseSentinel))
}

pub(crate) fn is_pause(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::ToSqlConversionFailure(source) if source.is::<PauseSentinel>())
}
