// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-process supervisor for hosts that have no helper process (iOS, Android).
//!
//! The app process is the supervisor. It runs the same account actors as the desktop daemon
//! on one dedicated thread, over the in-process carrier, and binds no socket. `suspend`
//! returns only after that thread exited (which closes every database connection it owned)
//! and a fresh descriptor took the exclusive data-root lock. Nothing here is specific to one
//! phone platform; platform preparation of the data root is one call in `prepare_data_root`.

use std::path::Path;
use std::sync::Mutex;
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::sync::watch;

use super::in_process::{self, InProcessConnector};
use super::lifecycle::{
    HostLifecycle, HostPaths, LifecycleState, LifecycleTransition, SuspendReport, illegal,
};
use crate::{LocalBusClient, LocalBusConfig, NodeProfile, SdkError};

/// OPEN-VALUE: time `suspend`/`stop` wait for the supervisor thread and the lock release.
/// The supervisor's own drain is bounded at five seconds; a phone background task gives
/// more than this, and the host may pass its own value.
pub const DEFAULT_SUSPEND_DEADLINE: Duration = Duration::from_secs(10);
/// Interval between probes of the data-root lock after the supervisor thread exited.
const LOCK_PROBE_INTERVAL: Duration = Duration::from_millis(20);

/// What the host gives an in-process supervisor.
#[derive(Clone)]
pub struct EmbeddedConfig {
    /// Directories chosen by the host application. The SDK never guesses a container path.
    pub paths: HostPaths,
    /// Node profiles compiled into or configured by the host.
    pub builtin_nodes: Vec<NodeProfile>,
    /// Longest time `suspend` and `stop` may take.
    pub suspend_deadline: Duration,
}

impl EmbeddedConfig {
    #[must_use]
    pub fn new(paths: HostPaths) -> Self {
        Self { paths, builtin_nodes: Vec::new(), suspend_deadline: DEFAULT_SUSPEND_DEADLINE }
    }
}

struct Running {
    shutdown: watch::Sender<bool>,
    connector: InProcessConnector,
    done: Receiver<Result<(), SdkError>>,
    thread: JoinHandle<()>,
}

/// The in-process supervisor handle. One per data root per process.
pub struct EmbeddedSupervisor {
    /// Behind a mutex so the handle is `Sync` whatever the configuration carries.
    config: Mutex<LocalBusConfig>,
    data_root: std::path::PathBuf,
    deadline: Duration,
    /// Held for the whole of a transition, so transitions never interleave.
    running: Mutex<Option<Running>>,
    /// Read by `state` without waiting for a transition in progress.
    state: Mutex<LifecycleState>,
}

fn poisoned<T>(_error: T) -> SdkError {
    SdkError::LocalBus("embedded supervisor state is poisoned".to_owned())
}

impl EmbeddedSupervisor {
    /// Build a stopped supervisor. Nothing is opened until [`HostLifecycle::start`].
    #[must_use]
    pub fn new(config: EmbeddedConfig) -> Self {
        // The in-process carrier has no socket; the path stays empty and is never bound.
        let mut bus = LocalBusConfig::new(std::path::PathBuf::new(), config.paths.data_root);
        bus.builtin_nodes = config.builtin_nodes;
        Self::from_bus_config(bus, config.suspend_deadline)
    }

    pub(crate) fn from_bus_config(config: LocalBusConfig, deadline: Duration) -> Self {
        Self {
            data_root: config.data_root.clone(),
            config: Mutex::new(config),
            deadline,
            running: Mutex::new(None),
            state: Mutex::new(LifecycleState::Stopped),
        }
    }

    /// Open one in-process connection to the running supervisor. Requests, responses and
    /// events are the local-bus frames the desktop socket carries.
    ///
    /// # Errors
    /// Returns an error when the supervisor is not running, or when the caller is not
    /// inside a Tokio runtime (the client spawns its reader and writer tasks on it).
    pub fn connect(&self) -> Result<LocalBusClient, SdkError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(SdkError::LocalBus(
                "in-process client must be created inside a Tokio runtime".to_owned(),
            ));
        }
        let running = self.running.lock().map_err(poisoned)?;
        let Some(running) = running.as_ref() else {
            return Err(SdkError::LocalBus("embedded supervisor is not running".to_owned()));
        };
        let (reader, writer) = tokio::io::split(running.connector.connect()?);
        Ok(LocalBusClient::from_io(reader, writer))
    }

    fn set_state(&self, state: LifecycleState) -> Result<(), SdkError> {
        *self.state.lock().map_err(poisoned)? = state;
        Ok(())
    }

    fn launch(&self) -> Result<Running, SdkError> {
        prepare_data_root(&self.data_root)?;
        let (connector, listener) = in_process::pair();
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (ready_tx, ready_rx) = sync_channel(1);
        let (done_tx, done) = sync_channel(1);
        let config = self.config.lock().map_err(poisoned)?.clone();
        let thread =
            std::thread::Builder::new().name("ramflux-embedded-bus".to_owned()).spawn(move || {
                let result = crate::bus::embedded::run_thread(config, shutdown_rx, listener, ready_tx);
                let _ = done_tx.send(result);
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Running { shutdown, connector, done, thread }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                Err(done.try_recv().ok().and_then(Result::err).unwrap_or_else(|| {
                    SdkError::LocalBus("embedded supervisor exited before it was ready".to_owned())
                }))
            }
        }
    }

    /// Stop the supervisor thread if one runs, then observe the released data root.
    fn halt(&self, slot: &mut Option<Running>) -> Result<SuspendReport, SdkError> {
        let started = Instant::now();
        let until = started + self.deadline;
        if let Some(running) = slot.as_ref() {
            let _ = running.shutdown.send(true);
            match running.done.recv_timeout(self.deadline) {
                Ok(Ok(())) => {}
                // The thread is gone and its stores are closed; the drain error is logged
                // and the release is still verified below.
                Ok(Err(error)) => {
                    tracing::warn!(%error, "embedded supervisor reported an error while draining");
                }
                Err(RecvTimeoutError::Disconnected) => {
                    tracing::warn!("embedded supervisor thread ended without a result");
                }
                Err(RecvTimeoutError::Timeout) => {
                    // The thread still owns the stores. Keep the handle so the host can
                    // call again; the state stays `Running`.
                    return Err(SdkError::LocalBus(
                        "embedded supervisor did not drain before the suspension deadline"
                            .to_owned(),
                    ));
                }
            }
        }
        if let Some(running) = slot.take() {
            drop(running.connector);
            if running.thread.join().is_err() {
                tracing::warn!("embedded supervisor thread panicked");
            }
        }
        let data_root_lock_released = wait_for_lock_release(&self.data_root, until);
        Ok(SuspendReport {
            supervisor_joined: true,
            data_root_lock_released,
            elapsed: started.elapsed(),
        })
    }

    fn transition(&self, transition: LifecycleTransition) -> Result<SuspendReport, SdkError> {
        let mut running = self.running.lock().map_err(poisoned)?;
        let current = *self.state.lock().map_err(poisoned)?;
        let next = current.after(transition).ok_or_else(|| illegal(current, transition))?;
        match transition {
            LifecycleTransition::Start | LifecycleTransition::Resume => {
                *running = Some(self.launch()?);
                self.set_state(next)?;
                Ok(SuspendReport {
                    supervisor_joined: false,
                    data_root_lock_released: false,
                    elapsed: Duration::ZERO,
                })
            }
            LifecycleTransition::Suspend | LifecycleTransition::Stop => {
                let report = self.halt(&mut running)?;
                // The supervisor thread is gone whatever the checks below say.
                self.set_state(next)?;
                if !report.data_root_lock_released {
                    return Err(SdkError::DataRootInUse);
                }
                if let Some(open) = open_descriptors_under(&self.data_root)
                    && open > 0
                {
                    return Err(SdkError::LocalBus(format!(
                        "{open} descriptors under the data root are still open after the supervisor stopped"
                    )));
                }
                Ok(report)
            }
        }
    }
}

impl HostLifecycle for EmbeddedSupervisor {
    fn start(&self) -> Result<(), SdkError> {
        self.transition(LifecycleTransition::Start).map(|_| ())
    }

    fn suspend(&self) -> Result<SuspendReport, SdkError> {
        self.transition(LifecycleTransition::Suspend)
    }

    fn resume(&self) -> Result<(), SdkError> {
        self.transition(LifecycleTransition::Resume).map(|_| ())
    }

    fn stop(&self) -> Result<(), SdkError> {
        self.transition(LifecycleTransition::Stop).map(|_| ())
    }

    fn state(&self) -> LifecycleState {
        self.state.lock().map_or(LifecycleState::Stopped, |state| *state)
    }
}

impl Drop for EmbeddedSupervisor {
    fn drop(&mut self) {
        // A dropped handle must not leave a thread holding the store. The thread also
        // leaves when the shutdown sender is dropped; this makes the request explicit.
        if let Ok(running) = self.running.lock()
            && let Some(running) = running.as_ref()
        {
            let _ = running.shutdown.send(true);
        }
    }
}

/// Create the data root owner-only and apply the platform's storage rules to it.
fn prepare_data_root(root: &Path) -> Result<(), SdkError> {
    std::fs::create_dir_all(root)?;
    super::fs::set_owner_only_dir(root)?;
    #[cfg(target_os = "ios")]
    super::apple_container::protect_data_root(root)?;
    #[cfg(target_os = "android")]
    super::android::storage::require_private_data_root(root)?;
    Ok(())
}

/// True when a fresh descriptor can take and drop the exclusive data-root lock.
fn lock_is_free(root: &Path) -> std::io::Result<bool> {
    let file = match super::fs::open_owner_only_read_write(&root.join("daemon.lock")) {
        Ok(file) => file,
        Err(SdkError::Io(error)) => return Err(error),
        Err(error) => return Err(std::io::Error::other(error.to_string())),
    };
    match super::fs::try_lock_exclusive(&file) {
        Ok(()) => {
            super::fs::unlock(&file)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error),
    }
}

/// A detached custody commit worker may keep the lock for a moment after the supervisor
/// thread exits. Wait for it, but never beyond the suspension deadline.
fn wait_for_lock_release(root: &Path, until: Instant) -> bool {
    loop {
        match lock_is_free(root) {
            Ok(true) => return true,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, "data-root lock probe failed");
            }
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(LOCK_PROBE_INTERVAL);
    }
}

/// Number of this process's open descriptors that point under `root`, where the platform
/// exposes a descriptor table (`/proc/self/fd` on Linux and Android). `None` elsewhere:
/// Apple platforms have no such listing without an unsafe descriptor walk, so there the
/// lock probe and the thread join are the evidence.
#[must_use]
pub(crate) fn open_descriptors_under(root: &Path) -> Option<usize> {
    let root = std::fs::canonicalize(root).ok()?;
    let entries = std::fs::read_dir("/proc/self/fd").ok()?;
    let mut open = 0_usize;
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path())
            && target.starts_with(&root)
        {
            open = open.saturating_add(1);
        }
    }
    Some(open)
}

#[cfg(test)]
mod tests;
