// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cooperative, bounded shutdown shared by the node services.

#[cfg(test)]
mod connection_tests;
mod connections;
mod runtime;
pub use connections::{
    ConnectionGuard, ConnectionRequestGuard, ConnectionSet, DEFAULT_CONNECTION_LIMIT,
    begin_connection_request,
};
pub use runtime::{RuntimeThreadTracker, drain_service_runtime, track_service_runtime};

use crate::NodeCoreError;
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const SHUTDOWN_GRACE_SECONDS_ENV: &str = "RAMFLUX_SHUTDOWN_GRACE_SECONDS";
const DEFAULT_SHUTDOWN_GRACE_SECONDS: u64 = 1;
const MAX_SHUTDOWN_GRACE_SECONDS: u64 = 4;

static RUNTIME: OnceLock<Arc<ShutdownRuntime>> = OnceLock::new();

struct ShutdownRuntime {
    token: CancellationToken,
    in_flight: Mutex<usize>,
    drained: Condvar,
    workers: Mutex<Vec<JoinHandle<()>>>,
    connections: Mutex<Vec<std::sync::Weak<ConnectionSet>>>,
    deadline: Mutex<Option<Instant>>,
    async_runtimes: Mutex<Vec<std::sync::Weak<std::sync::atomic::AtomicUsize>>>,
}

/// Process shutdown coordinator. Install it before configuration or stores are opened.
pub struct ServiceShutdown {
    service: &'static str,
    grace: Duration,
    signal: mpsc::Receiver<i32>,

    runtime: Arc<ShutdownRuntime>,
}

/// RAII admission permit for work that must finish before stores are closed.
pub struct InFlightGuard {
    runtime: Option<Arc<ShutdownRuntime>>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let Some(runtime) = &self.runtime else {
            return;
        };
        let mut count = runtime.in_flight.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *count = count.saturating_sub(1);
        if *count == 0 {
            runtime.drained.notify_all();
        }
    }
}

impl ServiceShutdown {
    /// Validate configuration and register SIGTERM/SIGINT before service startup.
    ///
    /// # Errors
    /// Returns an error for an invalid grace period, duplicate installation, or signal failure.
    pub fn install(service: &'static str) -> Result<Self, NodeCoreError> {
        let grace = shutdown_grace_period()?;
        let runtime = Arc::new(ShutdownRuntime {
            token: CancellationToken::new(),
            in_flight: Mutex::new(0),
            drained: Condvar::new(),
            workers: Mutex::new(Vec::new()),
            connections: Mutex::new(Vec::new()),
            deadline: Mutex::new(None),
            async_runtimes: Mutex::new(Vec::new()),
        });
        RUNTIME.set(Arc::clone(&runtime)).map_err(|_| {
            NodeCoreError::ServiceShutdown("shutdown coordinator already installed".to_owned())
        })?;
        #[cfg(unix)]
        {
            use signal_hook::consts::signal::{SIGINT, SIGTERM};
            use signal_hook::iterator::Signals;

            let mut signals = Signals::new([SIGTERM, SIGINT])
                .map_err(|error| NodeCoreError::ServiceShutdown(error.to_string()))?;
            let (sender, signal) = mpsc::sync_channel(1);
            let signal_runtime = Arc::clone(&runtime);
            std::thread::Builder::new()
                .name(format!("{service}-shutdown-signal"))
                .spawn(move || {
                    for (index, number) in signals.forever().enumerate() {
                        if index != 0 {
                            tracing::error!(service, "shutdown interrupted by second signal");
                            std::process::exit(1);
                        }
                        *signal_runtime
                            .deadline
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(Instant::now() + grace);
                        signal_runtime.token.cancel();
                        signal_runtime.drained.notify_all();
                        let _ = sender.send(number);
                    }
                })
                .map_err(|error| NodeCoreError::ServiceShutdown(error.to_string()))?;
            Ok(Self { service, grace, signal, runtime })
        }
        #[cfg(not(unix))]
        {
            let _ = service;
            Err(NodeCoreError::ServiceShutdown(
                "SIGTERM shutdown is supported only on Unix".to_owned(),
            ))
        }
    }

    /// Wait for a signal, stop admission, drain admitted work, join service roots, then finalize.
    ///
    /// The finalizer owns the service's remaining state and store handles. It is run after all
    /// registered workers have released their clones, so dropping those handles closes redb and
    /// joins its commit/WAL writers before the clean-shutdown log is emitted.
    ///
    /// # Errors
    /// Returns an error if the signal monitor ends, a worker panics, or the finalizer fails.
    /// Outstanding resource owners after bounded cleanup cause process exit status 1.
    pub fn wait_and_finalize<F>(self, finalize: F) -> Result<(), NodeCoreError>
    where
        F: FnOnce() -> Result<(), NodeCoreError>,
    {
        let signal = self
            .signal
            .recv()
            .map_err(|error| NodeCoreError::ServiceShutdown(error.to_string()))?;
        let deadline = shutdown_deadline().unwrap_or_else(|| Instant::now() + self.grace);
        // Cancellation closes listener loops first. No TLS handshake runs on those loops.
        let sets = connections::registered_sets(&self.runtime);
        for set in &sets {
            set.stop_idle();
        }
        self.wait_for_drain(deadline);
        for set in &sets {
            set.force_close();
        }
        let cleanup_deadline = deadline + Duration::from_secs(1);
        let mut outstanding = 0;
        for set in &sets {
            outstanding += set.wait_empty(cleanup_deadline);
        }
        outstanding += self.join_workers(cleanup_deadline)?;
        outstanding += runtime::wait_for_runtime_threads(&self.runtime, cleanup_deadline);
        outstanding +=
            *self.runtime.in_flight.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if outstanding != 0 {
            tracing::error!(
                service = self.service,
                "shutdown incomplete outstanding={outstanding}"
            );
            // Do not run a finalizer that might contend with surviving store owners.
            // This is a shutdown failure, independent of a binary's startup-error exit code.
            std::process::exit(1);
        }
        finalize()?;
        tracing::info!(service = self.service, signal, "graceful shutdown complete");
        Ok(())
    }

    fn wait_for_drain(&self, deadline: Instant) {
        let mut count =
            self.runtime.in_flight.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        while *count != 0 {
            let now = Instant::now();
            if now >= deadline {
                tracing::warn!(
                    service = self.service,
                    in_flight = *count,
                    "shutdown drain deadline reached"
                );
                break;
            }
            let waited = self.runtime.drained.wait_timeout(count, deadline - now);
            let (next, _) = waited.unwrap_or_else(std::sync::PoisonError::into_inner);
            count = next;
        }
    }

    fn join_workers(&self, deadline: Instant) -> Result<usize, NodeCoreError> {
        let mut workers =
            self.runtime.workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        while workers.iter().any(|worker| !worker.is_finished()) && Instant::now() < deadline {
            drop(workers);
            std::thread::sleep(Duration::from_millis(10));
            workers =
                self.runtime.workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let mut outstanding = 0;
        for worker in workers.drain(..) {
            if worker.is_finished() {
                worker.join().map_err(|_| {
                    NodeCoreError::ServiceShutdown("service shutdown worker panicked".to_owned())
                })?;
            } else {
                outstanding += 1;
            }
        }
        Ok(outstanding)
    }
}

/// Return a clone of the process cancellation token.
#[must_use]
pub fn service_shutdown_token() -> CancellationToken {
    RUNTIME.get().map_or_else(CancellationToken::new, |runtime| runtime.token.clone())
}

/// Deadline shared by socket draining and async runtimes.
#[must_use]
pub fn shutdown_deadline() -> Option<Instant> {
    RUNTIME.get().and_then(|runtime| {
        *runtime.deadline.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    })
}

/// Sleep cooperatively, returning `false` as soon as process shutdown is requested.
#[must_use]
pub fn service_shutdown_sleep(duration: Duration) -> bool {
    let token = service_shutdown_token();
    let deadline = Instant::now() + duration;
    while !token.is_cancelled() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(50)));
    }
    false
}

/// Admit a request unless shutdown has started.
#[must_use]
pub fn begin_service_request() -> Option<InFlightGuard> {
    let Some(runtime) = RUNTIME.get().cloned() else {
        return Some(InFlightGuard { runtime: None });
    };
    let mut count = runtime.in_flight.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if runtime.token.is_cancelled() {
        return None;
    }
    *count += 1;
    drop(count);
    Some(InFlightGuard { runtime: Some(runtime) })
}

/// Spawn and register a root worker whose captured store handles must be released on shutdown.
///
/// A worker started outside a service process (for example by a unit test) is spawned normally
/// when no coordinator is installed.
///
/// # Errors
/// Returns an error when the operating system cannot spawn the thread.
pub fn spawn_service_worker<F>(name: impl Into<String>, worker: F) -> Result<(), NodeCoreError>
where
    F: FnOnce(CancellationToken) + Send + 'static,
{
    let runtime = RUNTIME.get().cloned();
    let token =
        runtime.as_ref().map_or_else(CancellationToken::new, |runtime| runtime.token.clone());
    let handle = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || worker(token))
        .map_err(|error| NodeCoreError::ServiceShutdown(error.to_string()))?;
    if let Some(runtime) = runtime {
        runtime.workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(handle);
    }
    Ok(())
}

fn shutdown_grace_period() -> Result<Duration, NodeCoreError> {
    let seconds = match crate::environment::var(SHUTDOWN_GRACE_SECONDS_ENV) {
        Ok(value) if value.trim().is_empty() => DEFAULT_SHUTDOWN_GRACE_SECONDS,
        Ok(value) => parse_shutdown_grace_seconds(&value)?,
        Err(std::env::VarError::NotPresent) => DEFAULT_SHUTDOWN_GRACE_SECONDS,
        Err(error) => return Err(NodeCoreError::ServiceShutdown(error.to_string())),
    };
    Ok(Duration::from_secs(seconds))
}

fn parse_shutdown_grace_seconds(value: &str) -> Result<u64, NodeCoreError> {
    let seconds = value.parse::<u64>().map_err(|_| invalid_grace_error())?;
    if seconds > MAX_SHUTDOWN_GRACE_SECONDS {
        return Err(invalid_grace_error());
    }
    Ok(seconds)
}

fn invalid_grace_error() -> NodeCoreError {
    NodeCoreError::ServiceShutdown(format!(
        "{SHUTDOWN_GRACE_SECONDS_ENV} must be an integer from 0 to {MAX_SHUTDOWN_GRACE_SECONDS}"
    ))
}

/// Deterministic request rendezvous, compiled only for explicit integration-test builds.
#[cfg(feature = "itest-http")]
pub fn shutdown_request_test_delay() {
    let Ok(marker) = crate::environment::var("RAMFLUX_ITEST_SHUTDOWN_REQUEST_MARKER") else {
        return;
    };
    if let Err(error) = std::fs::write(marker, b"admitted") {
        tracing::error!(%error, "shutdown test rendezvous failed");
    }
    std::thread::sleep(Duration::from_millis(500));
}

/// Root handles only; connection threads must never accumulate here.
#[cfg(feature = "itest-http")]
#[must_use]
pub fn service_worker_count() -> usize {
    RUNTIME.get().map_or(0, |runtime| {
        runtime.workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn incomplete_shutdown_exits_one_without_running_the_finalizer()
    -> Result<(), Box<dyn std::error::Error>> {
        const PROBE: &str = "RAMFLUX_SHUTDOWN_EXIT_PROBE";
        if std::env::var_os(PROBE).is_some() {
            let shutdown = ServiceShutdown::install("shutdown-exit-probe")?;
            let _request = begin_service_request().ok_or("request admission failed")?;
            let signal = std::process::Command::new("kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status()?;
            assert!(signal.success());
            shutdown.wait_and_finalize(|| std::process::exit(98))?;
            return Err("incomplete shutdown returned".into());
        }
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "shutdown::tests::incomplete_shutdown_exits_one_without_running_the_finalizer",
            ])
            .env(PROBE, "1")
            .env(SHUTDOWN_GRACE_SECONDS_ENV, "0")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = child.try_wait()? {
                assert_eq!(status.code(), Some(1));
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("shutdown exit probe exceeded timeout".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    #[test]
    fn shutdown_grace_is_bounded_below_container_timeout() -> Result<(), NodeCoreError> {
        assert_eq!(parse_shutdown_grace_seconds("0")?, 0);
        assert_eq!(parse_shutdown_grace_seconds("4")?, 4);
        assert!(parse_shutdown_grace_seconds("5").is_err());
        assert!(parse_shutdown_grace_seconds("invalid").is_err());
        Ok(())
    }
}
