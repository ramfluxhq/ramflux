// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The binding error enum. Its cases are the stable numeric codes of C ABI v1.
//!
//! Hosts match on the case (or on [`ErrorDetail::code`]). The message is diagnostic text and
//! is never matched. Adding a case is a minor bump of the binding API; renumbering or removing
//! one is a major bump.

/// Diagnostic payload carried by every [`CoreError`] case.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ErrorDetail {
    /// Stable numeric code, equal to the C ABI `RamfluxErrorCode` value of the case.
    pub code: i32,
    /// Human-readable diagnostic. Not stable, not localized, never matched by a host.
    pub message: String,
    /// Stable machine-readable sub-reason when the core supplied one.
    pub reason_code: Option<String>,
    /// Earliest useful retry, in milliseconds, when the core supplied one.
    pub retry_after_ms: Option<u64>,
}

/// Typed error of every fallible binding call.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("invalid argument (1): {}", detail.message)]
    InvalidArgument { detail: ErrorDetail },
    #[error("invalid canonical JSON (2): {}", detail.message)]
    InvalidCanonicalJson { detail: ErrorDetail },
    #[error("unsupported version (3): {}", detail.message)]
    UnsupportedVersion { detail: ErrorDetail },
    #[error("capability rejected (4): {}", detail.message)]
    CapabilityRejected { detail: ErrorDetail },
    #[error("authentication failed (5): {}", detail.message)]
    AuthFailed { detail: ErrorDetail },
    #[error("device revoked (6): {}", detail.message)]
    DeviceRevoked { detail: ErrorDetail },
    #[error("crypto failed (7): {}", detail.message)]
    CryptoFailed { detail: ErrorDetail },
    #[error("storage failed (8): {}", detail.message)]
    StorageFailed { detail: ErrorDetail },
    #[error("transport unavailable (9): {}", detail.message)]
    TransportUnavailable { detail: ErrorDetail },
    #[error("timeout (10): {}", detail.message)]
    Timeout { detail: ErrorDetail },
    #[error("replay rejected (11): {}", detail.message)]
    ReplayRejected { detail: ErrorDetail },
    #[error("permission denied (12): {}", detail.message)]
    PermissionDenied { detail: ErrorDetail },
    #[error("MCP grant rejected (13): {}", detail.message)]
    McpGrantRejected { detail: ErrorDetail },
    #[error("object transfer failed (14): {}", detail.message)]
    ObjectTransferFailed { detail: ErrorDetail },
    #[error("rate limited (15): {}", detail.message)]
    RateLimited { detail: ErrorDetail },
    #[error("internal error (16): {}", detail.message)]
    Internal { detail: ErrorDetail },
    #[error("panic aborted (17): {}", detail.message)]
    PanicAborted { detail: ErrorDetail },
    #[error("account busy (18): {}", detail.message)]
    AccountBusy { detail: ErrorDetail },
    #[error("object erased (19): {}", detail.message)]
    ObjectErased { detail: ErrorDetail },
    #[error("object identity conflict (20): {}", detail.message)]
    ObjectIdentityConflict { detail: ErrorDetail },
    #[error("object ownership unverified (21): {}", detail.message)]
    ObjectOwnershipUnverified { detail: ErrorDetail },
    #[error("custody fork fenced (22): {}", detail.message)]
    CustodyForkFenced { detail: ErrorDetail },
    #[error("schema reset required (23): {}", detail.message)]
    SchemaResetRequired { detail: ErrorDetail },
}

/// Stable numeric codes. Values equal `RamfluxErrorCode` in the SDK C ABI.
pub mod code {
    pub const INVALID_ARGUMENT: i32 = 1;
    pub const INVALID_CANONICAL_JSON: i32 = 2;
    pub const UNSUPPORTED_VERSION: i32 = 3;
    pub const CAPABILITY_REJECTED: i32 = 4;
    pub const AUTH_FAILED: i32 = 5;
    pub const DEVICE_REVOKED: i32 = 6;
    pub const CRYPTO_FAILED: i32 = 7;
    pub const STORAGE_FAILED: i32 = 8;
    pub const TRANSPORT_UNAVAILABLE: i32 = 9;
    pub const TIMEOUT: i32 = 10;
    pub const REPLAY_REJECTED: i32 = 11;
    pub const PERMISSION_DENIED: i32 = 12;
    pub const MCP_GRANT_REJECTED: i32 = 13;
    pub const OBJECT_TRANSFER_FAILED: i32 = 14;
    pub const RATE_LIMITED: i32 = 15;
    pub const INTERNAL: i32 = 16;
    pub const PANIC_ABORTED: i32 = 17;
    pub const ACCOUNT_BUSY: i32 = 18;
    pub const OBJECT_ERASED: i32 = 19;
    pub const OBJECT_IDENTITY_CONFLICT: i32 = 20;
    pub const OBJECT_OWNERSHIP_UNVERIFIED: i32 = 21;
    pub const CUSTODY_FORK_FENCED: i32 = 22;
    pub const SCHEMA_RESET_REQUIRED: i32 = 23;
}

impl CoreError {
    /// Build the case for a stable numeric code. An unknown code becomes `Internal` and keeps
    /// the received number in the diagnostic, so a newer core never crashes an older host.
    #[must_use]
    pub fn from_code(
        code: i32,
        message: impl Into<String>,
        reason_code: Option<String>,
        retry_after_ms: Option<u64>,
    ) -> Self {
        let message = message.into();
        let detail = |code: i32, message: String| ErrorDetail {
            code,
            message,
            reason_code: reason_code.clone(),
            retry_after_ms,
        };
        match code {
            code::INVALID_ARGUMENT => Self::InvalidArgument { detail: detail(code, message) },
            code::INVALID_CANONICAL_JSON => {
                Self::InvalidCanonicalJson { detail: detail(code, message) }
            }
            code::UNSUPPORTED_VERSION => Self::UnsupportedVersion { detail: detail(code, message) },
            code::CAPABILITY_REJECTED => Self::CapabilityRejected { detail: detail(code, message) },
            code::AUTH_FAILED => Self::AuthFailed { detail: detail(code, message) },
            code::DEVICE_REVOKED => Self::DeviceRevoked { detail: detail(code, message) },
            code::CRYPTO_FAILED => Self::CryptoFailed { detail: detail(code, message) },
            code::STORAGE_FAILED => Self::StorageFailed { detail: detail(code, message) },
            code::TRANSPORT_UNAVAILABLE => {
                Self::TransportUnavailable { detail: detail(code, message) }
            }
            code::TIMEOUT => Self::Timeout { detail: detail(code, message) },
            code::REPLAY_REJECTED => Self::ReplayRejected { detail: detail(code, message) },
            code::PERMISSION_DENIED => Self::PermissionDenied { detail: detail(code, message) },
            code::MCP_GRANT_REJECTED => Self::McpGrantRejected { detail: detail(code, message) },
            code::OBJECT_TRANSFER_FAILED => {
                Self::ObjectTransferFailed { detail: detail(code, message) }
            }
            code::RATE_LIMITED => Self::RateLimited { detail: detail(code, message) },
            code::PANIC_ABORTED => Self::PanicAborted { detail: detail(code, message) },
            code::ACCOUNT_BUSY => Self::AccountBusy { detail: detail(code, message) },
            code::OBJECT_ERASED => Self::ObjectErased { detail: detail(code, message) },
            code::OBJECT_IDENTITY_CONFLICT => {
                Self::ObjectIdentityConflict { detail: detail(code, message) }
            }
            code::OBJECT_OWNERSHIP_UNVERIFIED => {
                Self::ObjectOwnershipUnverified { detail: detail(code, message) }
            }
            code::CUSTODY_FORK_FENCED => Self::CustodyForkFenced { detail: detail(code, message) },
            code::SCHEMA_RESET_REQUIRED => {
                Self::SchemaResetRequired { detail: detail(code, message) }
            }
            code::INTERNAL => Self::Internal { detail: detail(code, message) },
            other => Self::Internal {
                detail: detail(code::INTERNAL, format!("unmapped core code {other}: {message}")),
            },
        }
    }

    /// Shorthand for a binding-side error without sub-reason.
    #[must_use]
    pub fn plain(code: i32, message: impl Into<String>) -> Self {
        Self::from_code(code, message, None, None)
    }

    /// The payload of the case.
    #[must_use]
    pub fn detail(&self) -> &ErrorDetail {
        match self {
            Self::InvalidArgument { detail }
            | Self::InvalidCanonicalJson { detail }
            | Self::UnsupportedVersion { detail }
            | Self::CapabilityRejected { detail }
            | Self::AuthFailed { detail }
            | Self::DeviceRevoked { detail }
            | Self::CryptoFailed { detail }
            | Self::StorageFailed { detail }
            | Self::TransportUnavailable { detail }
            | Self::Timeout { detail }
            | Self::ReplayRejected { detail }
            | Self::PermissionDenied { detail }
            | Self::McpGrantRejected { detail }
            | Self::ObjectTransferFailed { detail }
            | Self::RateLimited { detail }
            | Self::Internal { detail }
            | Self::PanicAborted { detail }
            | Self::AccountBusy { detail }
            | Self::ObjectErased { detail }
            | Self::ObjectIdentityConflict { detail }
            | Self::ObjectOwnershipUnverified { detail }
            | Self::CustodyForkFenced { detail }
            | Self::SchemaResetRequired { detail } => detail,
        }
    }

    /// Stable numeric code of the case.
    #[must_use]
    pub fn code(&self) -> i32 {
        self.detail().code
    }
}

#[cfg(test)]
mod tests {
    use super::{CoreError, code};

    #[test]
    fn every_stable_code_round_trips_to_its_own_case() {
        for value in 1..=23 {
            let error = CoreError::plain(value, "x");
            assert_eq!(error.code(), value);
        }
    }

    #[test]
    fn unknown_core_code_becomes_internal_and_keeps_the_number_in_the_diagnostic() {
        let error = CoreError::plain(4711, "future");
        assert_eq!(error.code(), code::INTERNAL);
        assert!(error.detail().message.contains("4711"));
    }

    #[test]
    fn schema_reset_required_is_code_23() {
        assert!(matches!(
            CoreError::plain(code::SCHEMA_RESET_REQUIRED, "reset"),
            CoreError::SchemaResetRequired { .. }
        ));
    }
}
