// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ownership of listener runtime threads, including non-cancellable blocking jobs.

use super::{RUNTIME, ShutdownRuntime, shutdown_deadline};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Observer for threads created by one service listener runtime.
pub struct RuntimeThreadTracker {
    threads: Arc<AtomicUsize>,
}

impl RuntimeThreadTracker {
    /// Runtime threads that have started and have not stopped.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.threads.load(Ordering::Acquire)
    }
}

/// Track a listener's Tokio workers and blocking pool before building its runtime.
/// Keep independent provider runtimes under their existing service finalizer ownership.
#[must_use]
pub fn track_service_runtime(builder: &mut tokio::runtime::Builder) -> RuntimeThreadTracker {
    let threads = Arc::new(AtomicUsize::new(0));
    if let Some(runtime) = RUNTIME.get() {
        runtime
            .async_runtimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::downgrade(&threads));
    }
    let started = Arc::clone(&threads);
    let stopped = Arc::clone(&threads);
    builder.on_thread_start(move || {
        started.fetch_add(1, Ordering::AcqRel);
    });
    builder.on_thread_stop(move || {
        stopped.fetch_sub(1, Ordering::AcqRel);
    });
    RuntimeThreadTracker { threads }
}

/// Poll admitted requests through the grace, then cancel async tasks and wait for runtime
/// teardown within the shared extra second. Surviving blocking workers remain registered.
pub fn drain_service_runtime(runtime: tokio::runtime::Runtime) {
    let deadline = shutdown_deadline().unwrap_or_else(|| Instant::now() + Duration::from_secs(1));
    runtime.block_on(async {
        loop {
            let count = RUNTIME.get().map_or(0, |runtime| {
                *runtime.in_flight.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            });
            if count == 0 || Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    runtime.shutdown_timeout(
        (deadline + Duration::from_secs(1)).saturating_duration_since(Instant::now()),
    );
}

pub(super) fn wait_for_runtime_threads(runtime: &ShutdownRuntime, deadline: Instant) -> usize {
    loop {
        let outstanding = runtime
            .async_runtimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .map(|threads| {
                // A surviving callback also covers a worker that has not reached its start hook,
                // or is finishing teardown after its stop hook. No callback may outlive clean exit.
                threads.load(Ordering::Acquire).max(1)
            })
            .sum();
        if outstanding == 0 || Instant::now() >= deadline {
            return outstanding;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timed_out_blocking_work_remains_owned_after_runtime_shutdown()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = tokio::runtime::Builder::new_current_thread();
        builder.enable_all();
        let tracker = track_service_runtime(&mut builder);
        let runtime = builder.build()?;
        let store = Arc::new(());
        let captured = Arc::clone(&store);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        runtime.spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            drop(captured);
        });
        started_rx.recv_timeout(Duration::from_secs(1))?;
        drain_service_runtime(runtime);
        assert_eq!(tracker.outstanding(), 1);
        assert_eq!(Arc::strong_count(&store), 2);
        release_tx.send(())?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while tracker.outstanding() != 0 || Arc::strong_count(&store) != 1 {
            assert!(Instant::now() < deadline, "runtime resources did not drain");
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
}
