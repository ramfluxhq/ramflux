// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The Rust-side seam between the binding and an in-process core.
//!
//! The binding owns no account state and executes nothing itself. Everything goes through one
//! `CorePort`, which is the embedded supervisor in a phone app and a scripted fake in tests.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::ceremony::{CreatedAccount, PendingCeremony};
use crate::error::{CoreError, code};
use crate::types::{
    CoreRequest, CoreState, NetworkChange, SubscribeFilter, SubscriptionEnd, SuspendEvidence,
    UpdateRow,
};
use crate::wait::{ClaimGate, ReplySender};

/// One admitted-or-refused request on its way into the core.
pub struct PortRequest {
    pub request: CoreRequest,
    /// Absolute deadline, Unix milliseconds. The core checks it before applying the request.
    pub deadline_unix_ms: u64,
    /// The core MUST call `gate.try_claim(..)` immediately before the first effect and drop
    /// the request, with no effect, when it returns `false`.
    pub gate: Arc<ClaimGate>,
    /// Reply path. The execution result stands even when nobody listens any more.
    pub reply: ReplySender,
}

/// What the binding gives the core to push update rows into.
pub trait UpdateSink: Send + Sync {
    /// Offer one row in journal order. Never blocks. A row the sink cannot hold is counted
    /// as lag and reported to the host with the journal resume point; it is not lost.
    fn offer(&self, row: UpdateRow);
    /// The core ends the stream.
    fn end(&self, end: SubscriptionEnd);
}

/// Core-side handle of one subscription.
pub trait PortSubscription: Send + Sync {
    /// Stop producing rows. Idempotent.
    fn cancel(&self);
}

/// A boxed future returned by the asynchronous port methods.
pub type PortFuture<T> = Pin<Box<dyn Future<Output = Result<T, CoreError>> + Send>>;

/// Core side of one account-creation ceremony, bound to its own dedicated connection.
pub trait CeremonyPort: Send + Sync {
    fn show_once(&self) -> PortFuture<String>;
    fn hidden_challenge(&self) -> PortFuture<Vec<u8>>;
    fn confirm(&self, words: Vec<String>, passphrase: String) -> PortFuture<CreatedAccount>;
    fn cancel(&self) -> PortFuture<()>;
}

/// An in-process core.
pub trait CorePort: Send + Sync {
    /// Acquire the data-root lock and start the supervisor.
    ///
    /// # Errors
    /// `AccountBusy` when another holder owns the data root; otherwise the core's error.
    fn start(&self) -> Result<(), CoreError>;

    /// Close every store and release every file lock; returns after the release was observed.
    ///
    /// # Errors
    /// Returns the core's error when the release could not be observed.
    fn suspend(&self) -> Result<SuspendEvidence, CoreError>;

    /// Reacquire the lock and restart after a suspension.
    ///
    /// # Errors
    /// Returns the core's error when the supervisor is not suspended or cannot restart.
    fn resume(&self) -> Result<(), CoreError>;

    /// Stop for good. Legal from every state.
    ///
    /// # Errors
    /// Returns the core's error when the supervisor did not drain.
    fn stop(&self) -> Result<(), CoreError>;

    fn state(&self) -> CoreState;

    /// Report a default-network change. Never blocks and never fails.
    fn network_changed(&self, change: NetworkChange);

    /// Hand one request to the core. Never blocks on execution.
    ///
    /// # Errors
    /// An error means the request was NOT admitted and has no effect.
    fn submit(&self, request: PortRequest) -> Result<(), CoreError>;

    /// Open an update stream.
    ///
    /// # Errors
    /// Returns the core's refusal (scope, unknown topic, not running).
    fn subscribe(
        &self,
        filter: SubscribeFilter,
        sink: Arc<dyn UpdateSink>,
    ) -> Result<Box<dyn PortSubscription>, CoreError>;

    /// Begin an account-creation ceremony on a dedicated connection.
    ///
    /// The default refuses: a port offers creation only when its core can carry the
    /// ceremony without putting secrets into ordinary request frames.
    fn begin_account(
        &self,
        _display_name: String,
        _node_id: Option<String>,
    ) -> PortFuture<(PendingCeremony, Arc<dyn CeremonyPort>)> {
        Box::pin(async {
            Err(CoreError::plain(
                code::CAPABILITY_REJECTED,
                "this core does not offer the account-creation ceremony on this carrier",
            ))
        })
    }
}
