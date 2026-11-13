// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wall-clock supervision for real account, vault and database component cases.
use std::{future::Future, pin::Pin};

/// Bound setup and execution without requiring a `Send` future or moving profile guards.
/// # Errors
/// The awaited watchdog returns an elapsed error if the component case exceeds its deadline.
pub(crate) fn within<F: Future>(future: F) -> tokio::time::Timeout<Pin<Box<F>>> {
    tokio::time::timeout(std::time::Duration::from_secs(120), Box::pin(future))
}
