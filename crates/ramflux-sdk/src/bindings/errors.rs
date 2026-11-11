// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Permanent generated API errors (OV2-RD-ERR). Legacy C entrypoints keep their ABI.
use crate::SdkError;
use serde::{Deserialize, Serialize};

/// Permanent numeric codes shared by every generated product adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum GeneratedErrorCode {
    InvalidArgument = 1,
    InvalidJson = 2,
    PeerUpgradeRequired = 3,
    StorageCapacity = 4,
    SchemaResetRequired = 5,
    ResyncRequired = 6,
    EditConflict = 7,
    NotAuthorized = 8,
    TargetNotFound = 9,
    TargetDeleted = 10,
    PayloadTooLarge = 11,
    RateLimited = 12,
    EphemeralUnavailable = 13,
    CryptoFailure = 14,
    NotConnected = 15,
    Internal = 16,
}

impl GeneratedErrorCode {
    const ALL: [Self; 16] = [
        Self::InvalidArgument,
        Self::InvalidJson,
        Self::PeerUpgradeRequired,
        Self::StorageCapacity,
        Self::SchemaResetRequired,
        Self::ResyncRequired,
        Self::EditConflict,
        Self::NotAuthorized,
        Self::TargetNotFound,
        Self::TargetDeleted,
        Self::PayloadTooLarge,
        Self::RateLimited,
        Self::EphemeralUnavailable,
        Self::CryptoFailure,
        Self::NotConnected,
        Self::Internal,
    ];
    /// Stable wire name; never derived from diagnostic text.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidJson => "invalid_json",
            Self::PeerUpgradeRequired => "peer_upgrade_required",
            Self::StorageCapacity => "storage_capacity",
            Self::SchemaResetRequired => "schema_reset_required",
            Self::ResyncRequired => "resync_required",
            Self::EditConflict => "edit_conflict",
            Self::NotAuthorized => "not_authorized",
            Self::TargetNotFound => "target_not_found",
            Self::TargetDeleted => "target_deleted",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RateLimited => "rate_limited",
            Self::EphemeralUnavailable => "ephemeral_unavailable",
            Self::CryptoFailure => "crypto_failure",
            Self::NotConnected => "not_connected",
            Self::Internal => "internal",
        }
    }
}

impl TryFrom<i32> for GeneratedErrorCode {
    type Error = &'static str;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::ALL
            .into_iter()
            .find(|code| *code as i32 == value)
            .ok_or("unknown generated error code")
    }
}

/// Typed details for errors with normative structured context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum ErrorDetails {
    ResyncRequired { cursor: u64, floor: u64, head: u64 },
    EditConflict { target: String, expected: u64, received: u64 },
    StorageCapacity { scope: String, source: String },
    Empty {},
}

/// Shared JSON error, including the permanent code and typed context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, thiserror::Error)]
#[error("{name}: {message}")]
pub struct AdapterError {
    pub code: i32,
    pub name: &'static str,
    pub message: String,
    pub details: ErrorDetails,
}

impl<'de> Deserialize<'de> for AdapterError {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireError {
            code: i32,
            name: String,
            message: String,
            details: ErrorDetails,
        }
        let wire = WireError::deserialize(deserializer)?;
        let code = GeneratedErrorCode::try_from(wire.code).map_err(D::Error::custom)?;
        let details_match = matches!(
            (&code, &wire.details),
            (GeneratedErrorCode::StorageCapacity, ErrorDetails::StorageCapacity { .. })
                | (GeneratedErrorCode::ResyncRequired, ErrorDetails::ResyncRequired { .. })
                | (GeneratedErrorCode::EditConflict, ErrorDetails::EditConflict { .. })
        );
        let requires_details = matches!(
            code,
            GeneratedErrorCode::StorageCapacity
                | GeneratedErrorCode::ResyncRequired
                | GeneratedErrorCode::EditConflict
        );
        if wire.name != code.name()
            || (requires_details && !details_match)
            || (!requires_details && !matches!(&wire.details, ErrorDetails::Empty {}))
        {
            return Err(D::Error::custom("generated error code/name/details mismatch"));
        }
        Ok(Self {
            code: wire.code,
            name: code.name(),
            message: wire.message,
            details: wire.details,
        })
    }
}

impl AdapterError {
    pub const INVALID_ARGUMENT: i32 = GeneratedErrorCode::InvalidArgument as i32;
    pub const INVALID_JSON: i32 = GeneratedErrorCode::InvalidJson as i32;

    /// Construct an error without additional context.
    #[must_use]
    pub fn new(code: GeneratedErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code as i32,
            name: code.name(),
            message: message.into(),
            details: ErrorDetails::Empty {},
        }
    }

    /// Construct the typed stale-cursor response used by readers and subscriptions.
    #[must_use]
    pub fn resync(cursor: u64, floor: u64, head: u64) -> Self {
        Self {
            details: ErrorDetails::ResyncRequired { cursor, floor, head },
            ..Self::new(GeneratedErrorCode::ResyncRequired, "refresh account snapshot")
        }
    }

    /// Preserve typed failures; classify native failures without inspecting diagnostic strings.
    #[must_use]
    pub fn from_sdk(error: &SdkError) -> Self {
        let code = match error {
            SdkError::GeneratedApi(error) => return (**error).clone(),
            SdkError::LifecycleShared(error) => return Self::from_sdk(error),
            SdkError::LocalBusRefused { body, .. } => {
                return serde_json::from_value((**body).clone()).unwrap_or_else(|_| {
                    Self::new(GeneratedErrorCode::Internal, "invalid generated error response")
                });
            }
            SdkError::EditConflict { target, expected, received } => {
                return Self {
                    details: ErrorDetails::EditConflict {
                        target: target.clone(),
                        expected: *expected,
                        received: *received,
                    },
                    ..Self::new(GeneratedErrorCode::EditConflict, error.to_string())
                };
            }
            SdkError::StorageCapacity { source_anchor, scope } => {
                return Self {
                    details: ErrorDetails::StorageCapacity {
                        scope: match scope {
                            ramflux_storage::RawInnerQuotaScope::Source => "source",
                            ramflux_storage::RawInnerQuotaScope::Account => "account",
                        }
                        .into(),
                        source: source_anchor.clone(),
                    },
                    ..Self::new(GeneratedErrorCode::StorageCapacity, error.to_string())
                };
            }
            SdkError::Json(_) => GeneratedErrorCode::InvalidJson,
            SdkError::Storage(ramflux_storage::StorageError::SchemaResetRequired { .. }) => {
                GeneratedErrorCode::SchemaResetRequired
            }
            SdkError::Storage(ramflux_storage::StorageError::MessageNotFound(_)) => {
                GeneratedErrorCode::TargetNotFound
            }
            SdkError::Storage(ramflux_storage::StorageError::AuthorizationRejected)
            | SdkError::LocalBusPermissionDenied
            | SdkError::GeneratedRefused { .. } => GeneratedErrorCode::NotAuthorized,
            SdkError::ObjectErased | SdkError::AttachmentDeleted => {
                GeneratedErrorCode::TargetDeleted
            }
            SdkError::PayloadTooLarge | SdkError::SurfaceDeliveryTooLarge { .. } => {
                GeneratedErrorCode::PayloadTooLarge
            }
            SdkError::Crypto(_) | SdkError::HistoryEvidence(_) => GeneratedErrorCode::CryptoFailure,
            SdkError::NoNodeSelected
            | SdkError::NodeUnreachable { .. }
            | SdkError::NodeTimeout { .. }
            | SdkError::Transport(_) => GeneratedErrorCode::NotConnected,
            SdkError::LocalBus(_) | SdkError::InvalidOfflineRetention(_) => {
                GeneratedErrorCode::InvalidArgument
            }
            _ => GeneratedErrorCode::Internal,
        };
        Self::new(code, error.to_string())
    }
}

#[cfg(test)]
pub(crate) fn test_error_vector(code: GeneratedErrorCode) -> AdapterError {
    let details = match code {
        GeneratedErrorCode::StorageCapacity => {
            ErrorDetails::StorageCapacity { scope: "source".into(), source: "peer".into() }
        }
        GeneratedErrorCode::ResyncRequired => {
            ErrorDetails::ResyncRequired { cursor: 2, floor: 4, head: 8 }
        }
        GeneratedErrorCode::EditConflict => {
            ErrorDetails::EditConflict { target: "m".into(), expected: 2, received: 3 }
        }
        _ => ErrorDetails::Empty {},
    };
    AdapterError { details, ..AdapterError::new(code, "vector") }
}
