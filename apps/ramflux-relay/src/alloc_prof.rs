// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static FLUSHED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
// Default output lands on the host bind mount (survives `compose down -v`) so the profile persists.
const DEFAULT_FILE: &str = "/var/lib/ramflux/alloc-prof/dhat-heap.json";
const FILE_ENV: &str = "RAMFLUX_RELAY_ALLOC_PROF_FILE";

extern "C" fn on_signal(_sig: libc::c_int) {
    // Only an atomic store — async-signal-safe. The Profiler drop (IO/alloc) runs on the owner thread.
    SHUTDOWN.store(true, Ordering::SeqCst);
}

// DIAGNOSTIC-only: the workspace denies `unsafe_code`; the single `libc::signal` FFI call to
// register a trivial async-signal-safe handler is the only exception, compiled solely under the
// default-off profiler feature and never in the production relay.
#[allow(unsafe_code)]
fn install_signal_handlers() {
    // SAFETY: registering a trivial async-signal-safe handler (atomic store) at startup.
    let handler = on_signal as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

/// Starts the profiler ONLY for the long-lived serving invocation. The short-lived
/// `--health-check` (compose healthcheck exec) and `--once` init runs exit cleanly and would
/// otherwise OVERWRITE the serving process's dump at the same path with a near-empty profile.
///
/// The Profiler lives on a dedicated owner thread that polls the SIGTERM flag and, on shutdown,
/// drops the Profiler (writing the heap json), then notifies the shared shutdown coordinator.
/// Returns after a short delay so the global profiler is armed
/// before the workload begins.
pub fn maybe_start() {
    let serving = !std::env::args().any(|arg| arg == "--health-check" || arg == "--once");
    if !serving {
        return;
    }
    install_signal_handlers();
    let file = ramflux_node_core::environment::var(FILE_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_FILE.to_owned());
    eprintln!("ramflux-relay: itest-alloc-prof active; dhat heap profile -> {file}");
    let _ = std::thread::Builder::new().name("dhat-profiler-owner".to_owned()).spawn(move || {
        // The Profiler is created and dropped entirely on this thread (never crosses a thread
        // boundary), so no `Send` bound is required. The global dhat allocator records every
        // thread's allocations for the Profiler's lifetime.
        let profiler =
            dhat::Profiler::builder().file_name(std::path::PathBuf::from(&file)).build();
        while !SHUTDOWN.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        eprintln!(
            "ramflux-relay: itest-alloc-prof shutdown signal received; flushing dhat heap profile -> {file}"
        );
        drop(profiler); // writes the heap json
        let mut flushed = FLUSHED.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *flushed = true;
        FLUSHED.1.notify_all();
    });
    // Give the owner thread a moment to arm the global profiler before the workload starts.
    std::thread::sleep(std::time::Duration::from_millis(100));
}

/// Request a profile flush and wait for the profiler owner to finish writing it.
pub fn flush_and_wait() {
    SHUTDOWN.store(true, Ordering::SeqCst);
    let flushed = FLUSHED.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _guard = FLUSHED
        .1
        .wait_timeout_while(flushed, std::time::Duration::from_secs(4), |done| !*done)
        .unwrap_or_else(std::sync::PoisonError::into_inner);
}
