// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

/// Typed refusal of every large-group crypto operation (no panics in production paths).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LgError {
    #[error("large-group format rejected: {0}")]
    Format(&'static str),
    #[error("large-group randomness unavailable")]
    Random,
    #[error("large-group crypto operation failed: {0}")]
    Crypto(&'static str),
    #[error("large-group verification failed: {0}")]
    Verify(&'static str),
    /// POPRF `Error::Protocol`: an RNG failure on create/issue, or the `InverseError` rotation path.
    #[error("poprf protocol error")]
    PoprfProtocol,
    #[error("poprf operation failed: {0}")]
    Poprf(&'static str),
    #[error("large-group key file rejected: {0}")]
    KeyFile(&'static str),
}
