// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Socket ownership and request admission for blocking listeners.

use super::{InFlightGuard, RUNTIME, ShutdownRuntime, begin_service_request};
use crate::NodeCoreError;
use std::collections::BTreeMap;
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Default hard bound on live connections owned by one listener.
pub const DEFAULT_CONNECTION_LIMIT: usize = 1024;

struct Entry {
    socket: TcpStream,
    active: bool,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<u64, Entry>,
    next_id: u64,
    stopping: bool,
    last_rejection: Option<Instant>,
}

/// A listener's bounded socket registry. Connection threads are detached, never accumulated.
pub struct ConnectionSet {
    state: Mutex<State>,
    empty: Condvar,
    limit: usize,
}

/// Membership must outlive every store/context clone owned by the connection.
pub struct ConnectionGuard {
    set: Arc<ConnectionSet>,
    id: u64,
}

/// Resources drop in declaration order; membership is deliberately the last field.
struct ConnectionOwner<T> {
    context: T,
    guard: ConnectionGuard,
}

/// One admitted request, including its response write, on a blocking connection.
pub struct ConnectionRequestGuard {
    connection: Option<(Arc<ConnectionSet>, u64)>,
    _request: InFlightGuard,
}

impl ConnectionSet {
    /// Create and register a bounded listener registry with the process coordinator.
    #[must_use]
    pub fn new(limit: usize) -> Arc<Self> {
        let set =
            Arc::new(Self { state: Mutex::new(State::default()), empty: Condvar::new(), limit });
        if let Some(runtime) = RUNTIME.get() {
            let mut sets =
                runtime.connections.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            sets.retain(|set| set.strong_count() != 0);
            sets.push(Arc::downgrade(&set));
        }
        set
    }

    /// Clone and register an accepted socket, or close it when admission is unavailable.
    ///
    /// # Errors
    /// Returns a socket clone/option error. `None` means shutdown or the hard cap refused it.
    pub fn register(
        self: &Arc<Self>,
        socket: &TcpStream,
    ) -> std::io::Result<Option<ConnectionGuard>> {
        socket.set_nonblocking(false)?;
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopping
            || super::service_shutdown_token().is_cancelled()
            || state.entries.len() >= self.limit
        {
            let now = Instant::now();
            if state
                .last_rejection
                .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(1))
            {
                tracing::warn!(limit = self.limit, "connection admission unavailable");
                state.last_rejection = Some(now);
            }
            let _ = socket.shutdown(Shutdown::Both);
            return Ok(None);
        }
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        state.entries.insert(id, Entry { socket: socket.try_clone()?, active: false });
        Ok(Some(ConnectionGuard { set: Arc::clone(self), id }))
    }

    /// Spawn a detached connection with context-before-membership destruction, even on panic.
    /// The callback borrows its context so closure capture splitting cannot reorder its drop.
    /// Returns `false` when the listener cap or process shutdown refuses admission.
    ///
    /// # Errors
    /// Returns a socket registration or thread-spawn error.
    pub fn spawn<T, F>(
        self: &Arc<Self>,
        socket: &TcpStream,
        context: T,
        worker: F,
    ) -> Result<bool, NodeCoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut T, &ConnectionGuard) + Send + 'static,
    {
        let Some(guard) = self
            .register(socket)
            .map_err(|error| NodeCoreError::ServiceShutdown(error.to_string()))?
        else {
            return Ok(false);
        };
        let owner = ConnectionOwner { context, guard };
        std::thread::Builder::new()
            .name("mesh-connection".into())
            .spawn(move || {
                let mut owner = owner;
                worker(&mut owner.context, &owner.guard);
                drop(owner);
            })
            .map_err(|error| NodeCoreError::ServiceShutdown(error.to_string()))?;
        Ok(true)
    }

    /// Number of connections still owning resources.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries.len()
    }

    /// Whether all connection resources have been released.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(super) fn stop_idle(&self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.stopping = true;
        for entry in state.entries.values().filter(|entry| !entry.active) {
            let _ = entry.socket.shutdown(Shutdown::Read);
        }
    }

    pub(super) fn force_close(&self) {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for entry in state.entries.values() {
            let _ = entry.socket.shutdown(Shutdown::Both);
        }
    }

    pub(super) fn wait_empty(&self, deadline: Instant) -> usize {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        while !state.entries.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (next, _) = self
                .empty
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
        state.entries.len()
    }
}

impl ConnectionGuard {
    /// Other live sockets on this listener, for integration-test churn assertions.
    #[cfg(feature = "itest-http")]
    #[must_use]
    pub fn other_connection_count(&self) -> usize {
        self.set.len().saturating_sub(1)
    }

    /// Admit a parsed request atomically with idle-socket cancellation.
    #[must_use]
    pub fn begin_request(&self) -> Option<ConnectionRequestGuard> {
        let mut state = self.set.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopping {
            return None;
        }
        let request = begin_service_request()?;
        state.entries.get_mut(&self.id)?.active = true;
        Some(ConnectionRequestGuard {
            connection: Some((Arc::clone(&self.set), self.id)),
            _request: request,
        })
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut state = self.set.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.entries.remove(&self.id);
        self.set.empty.notify_all();
    }
}

impl Drop for ConnectionRequestGuard {
    fn drop(&mut self) {
        let Some((connection, id)) = &self.connection else {
            return;
        };
        let mut state = connection.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let stopping = state.stopping;
        if let Some(entry) = state.entries.get_mut(id) {
            entry.active = false;
            if stopping {
                let _ = entry.socket.shutdown(Shutdown::Read);
            }
        }
    }
}

pub(super) fn registered_sets(runtime: &ShutdownRuntime) -> Vec<Arc<ConnectionSet>> {
    runtime
        .connections
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter_map(std::sync::Weak::upgrade)
        .collect()
}

/// Admit a parsed request in a connection worker, or a directly invoked test handler.
#[must_use]
pub fn begin_connection_request(
    connection: Option<&ConnectionGuard>,
) -> Option<ConnectionRequestGuard> {
    match connection {
        Some(connection) => connection.begin_request(),
        None => {
            Some(ConnectionRequestGuard { connection: None, _request: begin_service_request()? })
        }
    }
}
