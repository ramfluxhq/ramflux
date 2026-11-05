// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-wide ordering between fatal storage uncertainty and released success.
//! The supervisor never owns database, shard or mutation locks.
use crate::NodeCoreError;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;

static FENCED: AtomicBool = AtomicBool::new(false);
static REASON: AtomicU8 = AtomicU8::new(0);
static GATE: Mutex<()> = Mutex::new(());
static SUPERVISOR: OnceLock<thread::Thread> = OnceLock::new();

pub(crate) fn initialize() {
    SUPERVISOR.get_or_init(|| {
        thread::Builder::new()
            .name("ramflux-fatal-supervisor".into())
            .spawn(|| {
                loop {
                    if FENCED.load(Ordering::Acquire) {
                        #[cfg(test)]
                        supervisor_test_barrier();
                        if REASON.load(Ordering::Acquire) == 2 {
                            tracing::error!("fatal_tombstone_persistence");
                            eprintln!("fatal_tombstone_persistence");
                        } else {
                            tracing::error!("fatal_durability_uncertain");
                            eprintln!("fatal_durability_uncertain");
                        }
                        std::process::abort();
                    }
                    thread::park();
                }
            })
            .unwrap_or_else(|_| std::process::abort())
            .thread()
            .clone()
    });
}

pub(crate) fn check() -> Result<(), NodeCoreError> {
    if FENCED.load(Ordering::Acquire) {
        Err(NodeCoreError::Redb("fatal_durability_uncertain".into()))
    } else {
        Ok(())
    }
}

pub(crate) fn publication() -> Result<MutexGuard<'static, ()>, NodeCoreError> {
    let gate = GATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    check()?;
    Ok(gate)
}

pub(crate) fn fence(tombstone: bool) {
    // Only this short gate is shared with publication. Never held across I/O.
    {
        let _gate = GATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !FENCED.swap(true, Ordering::AcqRel) {
            REASON.store(if tombstone { 2 } else { 1 }, Ordering::Release);
        }
    }
    if let Some(supervisor) = SUPERVISOR.get() {
        supervisor.unpark();
    } else {
        std::process::abort();
    }
}

/// Ownership starts before any writer conversion, mutation or syscall. Unwind
/// only signals the supervisor; it never attempts cleanup or a nested transaction.
pub(crate) struct WriteGuard {
    complete: bool,
    tombstone: bool,
}
impl WriteGuard {
    pub(crate) fn new(tombstone: bool) -> Result<Self, NodeCoreError> {
        initialize();
        check()?;
        Ok(Self { complete: false, tombstone })
    }
    pub(crate) fn complete(mut self) -> Result<(), NodeCoreError> {
        self.complete = true;
        check()
    }
}
impl Drop for WriteGuard {
    fn drop(&mut self) {
        if !self.complete {
            fence(self.tombstone);
        }
    }
}
pub(crate) fn run<T>(work: impl FnOnce() -> Result<T, NodeCoreError>) -> Result<T, NodeCoreError> {
    let guard = WriteGuard::new(false)?;
    let value = work()?;
    guard.complete()?;
    Ok(value)
}

#[cfg(test)]
fn supervisor_test_barrier() {
    if let Some(root) = std::env::var_os("RAMFLUX_FATAL_HOLD") {
        let root = std::path::PathBuf::from(root);
        let _ = std::fs::write(root.join("fenced"), []);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !root.join("abort").exists() && std::time::Instant::now() < deadline {
            thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}
