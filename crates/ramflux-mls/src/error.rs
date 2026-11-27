// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::storage::kv::MlsKvError;

/// Typed failures of the MLS crate. [`MlsError::code`] gives the stable wire code.
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    /// A (credential, leaf signature key) pair, device set, revocation, successor or duplicate
    /// device check failed.
    #[error("credential rejected: {0}")]
    CredentialRejected(String),
    /// Suite, kind, proposal type, sender type, kind limit, commit right or roster check failed.
    #[error("policy rejected: {0}")]
    PolicyRejected(String),
    /// An input exceeded its byte bound before parsing.
    #[error("too large: {0}")]
    TooLarge(String),
    /// The message belongs to another epoch than the group's.
    #[error("wrong epoch")]
    WrongEpoch,
    /// The message could not be decrypted (including replays).
    #[error("decrypt failed")]
    DecryptFailed,
    /// The group, key or row does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The own device-set record does not fit the credential size cap.
    #[error("device set too large: {bytes} bytes, cap {max}")]
    DeviceSetTooLarge {
        /// Size of the encoded credential.
        bytes: usize,
        /// Cap in bytes.
        max: usize,
    },
    /// A debug-only path was used in a build without `itest-mls-debug`.
    #[error("debug disabled")]
    DebugDisabled,
    /// The operating system random source failed its start-up probe.
    #[error("rng unavailable")]
    RngUnavailable,
    /// Storage backend or codec failure.
    #[error("storage: {0}")]
    Storage(#[from] MlsKvError),
    /// An openmls call failed for a reason that is not one of the typed cases above.
    #[error("mls: {0}")]
    Mls(String),
    /// An internal invariant was broken.
    #[error("internal: {0}")]
    Internal(String),
}

impl MlsError {
    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::CredentialRejected(_) => "credential_rejected",
            Self::PolicyRejected(_) => "policy_rejected",
            Self::TooLarge(_) => "too_large",
            Self::WrongEpoch => "wrong_epoch",
            Self::DecryptFailed => "decrypt_failed",
            Self::NotFound(_) => "not_found",
            Self::DeviceSetTooLarge { .. } => "device_set_too_large",
            Self::DebugDisabled => "debug_disabled",
            Self::RngUnavailable => "rng_unavailable",
            Self::Storage(_) => "storage",
            Self::Mls(_) => "mls",
            Self::Internal(_) => "internal",
        }
    }

    pub(crate) fn mls(error: impl std::fmt::Display) -> Self {
        Self::Mls(error.to_string())
    }

    pub(crate) fn internal(what: &str) -> Self {
        Self::Internal(what.to_owned())
    }
}
