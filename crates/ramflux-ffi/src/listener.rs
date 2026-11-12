// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The host-implemented update listener. A stream is a listener plus an explicit cancel.

use crate::types::{SubscriptionEnd, UpdateRow};

/// Failure of a host listener method. Returning it from `on_updates` or `on_lag` ends the
/// stream with `SubscriptionEnd::Failed`; the rows stay in the journal.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum ListenerError {
    /// The host could not apply the call.
    #[error("listener failed: {message}")]
    Failed { message: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for ListenerError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        // Without this conversion an unexpected foreign exception would panic in the core.
        Self::Failed { message: error.reason }
    }
}

/// Implemented by the host (Swift class / Kotlin object). Methods are called on a delivery
/// thread owned by the subscription, one call at a time and in journal order, never on the
/// supervisor thread and never on the host's main thread.
///
/// Back-pressure: the core delivers at most as many rows as the host has granted. A row
/// consumes one credit when it is handed to `on_updates`. The host grants more with
/// `Subscription::grant` after it has applied the rows.
#[uniffi::export(with_foreign)]
pub trait UpdateListener: Send + Sync {
    /// A batch of rows in journal order. Its length never exceeds the outstanding credit.
    fn on_updates(&self, rows: Vec<UpdateRow>) -> Result<(), ListenerError>;

    /// The host fell behind and rows were not delivered. Nothing is lost: the rows are in
    /// the journal. The host re-reads from `resume_after_journal_sequence` (its last applied
    /// row) and the subscription continues at the live edge.
    fn on_lag(
        &self,
        resume_after_journal_sequence: u64,
        skipped_rows: u64,
    ) -> Result<(), ListenerError>;

    /// Terminal. No call follows. An error returned here is ignored.
    fn on_end(&self, end: SubscriptionEnd) -> Result<(), ListenerError>;
}
