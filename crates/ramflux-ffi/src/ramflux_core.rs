// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The one object a host holds: lifecycle, `execute` and `subscribe`.
//!
//! The host never frees an account and never holds a second core for the same data root.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ceremony::AccountCeremony;
use crate::error::{CoreError, code};
use crate::listener::UpdateListener;
use crate::port::{CorePort, PortRequest, UpdateSink};
use crate::subscription::{self, Shared, Subscription};
use crate::types::{
    CoreConfig, CoreRequest, CoreState, ExecuteOutcome, NetworkChange, Negotiated,
    SubscribeFilter, SubscriptionEnd, SuspendEvidence,
};
use crate::version;
use crate::wait::{self, CancelHandle};

/// Longest deadline a request may ask for (ten minutes).
const MAX_DEADLINE_MS: u64 = 600_000;
/// Largest request body the binding forwards (the core API frame limit).
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// The in-process core. One per application process.
#[derive(uniffi::Object)]
pub struct RamfluxCore {
    port: Arc<dyn CorePort>,
    negotiated: Negotiated,
    max_pending_updates: u32,
    closed: AtomicBool,
    streams: Mutex<Vec<Weak<Shared>>>,
}

impl RamfluxCore {
    /// Build a core over an explicit port. Used by the embedded adapter and by tests.
    ///
    /// # Errors
    /// `UnsupportedVersion` when the host handshake is not compatible with this library.
    pub fn with_port(port: Arc<dyn CorePort>, config: &CoreConfig) -> Result<Arc<Self>, CoreError> {
        let negotiated = version::negotiate(&config.handshake)?;
        if config.max_pending_updates == 0 {
            return Err(CoreError::plain(code::INVALID_ARGUMENT, "max_pending_updates must be > 0"));
        }
        Ok(Arc::new(Self {
            port,
            negotiated,
            max_pending_updates: config.max_pending_updates,
            closed: AtomicBool::new(false),
            streams: Mutex::new(Vec::new()),
        }))
    }

    fn ensure_open(&self) -> Result<(), CoreError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CoreError::plain(code::INVALID_ARGUMENT, "core is closed"));
        }
        Ok(())
    }

    fn end_streams(&self, end: SubscriptionEnd) {
        let streams = match self.streams.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        for stream in streams {
            if let Some(shared) = stream.upgrade() {
                shared.finish(end);
            }
        }
    }
}

#[uniffi::export]
impl RamfluxCore {
    /// Create the core for this process. Nothing is opened until `start`.
    ///
    /// # Errors
    /// `UnsupportedVersion` (3) when the host bindings and this library are not compatible;
    /// `CapabilityRejected` (4) when the library was built without the embedded SDK.
    #[uniffi::constructor]
    pub fn open(config: CoreConfig) -> Result<Arc<Self>, CoreError> {
        // Negotiate first so an incompatible host never touches the data root.
        version::negotiate(&config.handshake)?;
        let port = crate::embedded_port(&config)?;
        Self::with_port(port, &config)
    }

    /// The negotiated versions, fingerprint and capabilities.
    #[must_use]
    pub fn negotiated(&self) -> Negotiated {
        self.negotiated.clone()
    }

    /// Acquire the data-root lock and start the supervisor. Blocking; call it off the main
    /// thread.
    ///
    /// # Errors
    /// `AccountBusy` (18) when another holder owns the data root; otherwise the core's error.
    pub fn start(&self) -> Result<(), CoreError> {
        self.ensure_open()?;
        self.port.start()
    }

    /// Leave the foreground: end every stream, close every store, release every file lock.
    /// Returns only after the release was observed. Call it inside the platform's background
    /// task and end that task after it returns. Blocking.
    ///
    /// # Errors
    /// The core's error when the supervisor did not drain or a lock is still held.
    pub fn suspend(&self) -> Result<SuspendEvidence, CoreError> {
        self.ensure_open()?;
        self.end_streams(SubscriptionEnd::Suspended);
        self.port.suspend()
    }

    /// Return to the foreground: reacquire the lock and restart. Subscribe again afterwards.
    ///
    /// # Errors
    /// The core's error when it is not suspended or cannot restart.
    pub fn resume(&self) -> Result<(), CoreError> {
        self.ensure_open()?;
        self.port.resume()
    }

    /// Stop for good. Idempotent: a second call does nothing and succeeds.
    ///
    /// # Errors
    /// The core's error when the supervisor did not drain on the first call.
    pub fn close(&self) -> Result<(), CoreError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.end_streams(SubscriptionEnd::Closed);
        self.port.stop()
    }

    #[must_use]
    pub fn state(&self) -> CoreState {
        self.port.state()
    }

    /// Report a default-network change from the platform path monitor. Never blocks.
    pub fn network_changed(&self, change: NetworkChange) {
        if !self.closed.load(Ordering::Acquire) {
            self.port.network_changed(change);
        }
    }

    /// Run one request. The future completes with the reply, or when `cancel` is cancelled,
    /// or at the deadline, whichever is first. See [`ExecuteOutcome`] for what a cancelled or
    /// timed-out call does and does not prove.
    ///
    /// # Errors
    /// A [`CoreError`] is either a refusal before admission (no effect) or the core's typed
    /// reply to an executed request.
    pub async fn execute(
        &self,
        request: CoreRequest,
        cancel: Arc<CancelHandle>,
    ) -> Result<ExecuteOutcome, CoreError> {
        self.ensure_open()?;
        if request.method.is_empty() {
            return Err(CoreError::plain(code::INVALID_ARGUMENT, "method is empty"));
        }
        if request.deadline_ms == 0 || request.deadline_ms > MAX_DEADLINE_MS {
            return Err(CoreError::plain(
                code::INVALID_ARGUMENT,
                format!("deadline_ms must be in 1..={MAX_DEADLINE_MS}"),
            ));
        }
        if request.body_json.len() > MAX_BODY_BYTES {
            return Err(CoreError::plain(code::INVALID_ARGUMENT, "request body exceeds 1 MiB"));
        }
        if request.operation_id.as_deref().is_some_and(str::is_empty) {
            return Err(CoreError::plain(code::INVALID_ARGUMENT, "operation_id is empty"));
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX));
        let (waiter, gate, reply) = wait::waiter(
            &cancel,
            Duration::from_millis(request.deadline_ms),
            request.operation_id.clone(),
        );
        let deadline_unix_ms = now_ms.saturating_add(request.deadline_ms);
        // A refused admission has no effect; the error is returned as it is. The reply sender
        // is consumed by the port either way.
        self.port.submit(PortRequest { request, deadline_unix_ms, gate, reply })?;
        waiter.await
    }

    /// Begin creating an account. `node_id` binds a confirmed home node to the new account.
    ///
    /// # Errors
    /// `CapabilityRejected` (4) when the core cannot carry the ceremony on this carrier;
    /// otherwise the core's refusal (unknown node, invalid name, unavailable vault).
    pub async fn begin_account_creation(
        &self,
        display_name: String,
        node_id: Option<String>,
    ) -> Result<Arc<AccountCeremony>, CoreError> {
        self.ensure_open()?;
        let (pending, port) = self.port.begin_account(display_name, node_id).await?;
        Ok(AccountCeremony::new(pending, port))
    }

    /// Open an update stream. Rows are delivered to `listener` within the granted credit.
    ///
    /// # Errors
    /// The core's refusal (scope, unknown topic, not running), or `Internal` when the
    /// delivery thread cannot start.
    pub fn subscribe(
        &self,
        filter: SubscribeFilter,
        listener: Arc<dyn UpdateListener>,
    ) -> Result<Arc<Subscription>, CoreError> {
        self.ensure_open()?;
        let stream = subscription::open(
            listener,
            filter.initial_credit,
            filter.after_journal_sequence,
            self.max_pending_updates,
        )?;
        let sink: Arc<dyn UpdateSink> = Arc::clone(stream.shared()) as Arc<dyn UpdateSink>;
        match self.port.subscribe(filter, sink) {
            Ok(port) => subscription::attach(&stream, port),
            Err(error) => {
                stream.shared().finish(SubscriptionEnd::Failed);
                return Err(error);
            }
        }
        let mut streams = match self.streams.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        streams.retain(|known| known.strong_count() > 0);
        streams.push(Arc::downgrade(stream.shared()));
        Ok(stream)
    }
}
