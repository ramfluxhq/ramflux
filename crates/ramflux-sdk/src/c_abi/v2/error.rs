// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Major-2 failures: the stable major-1 number plus what the host needs to reconcile.

use super::super::{RamfluxBuffer, RamfluxErrorCode, sdk_error_code, write_buffer};
use crate::{LocalBusErrorBody, SdkError};
use serde_json::{Value, json};

/// What a failed call may have changed. Hosts match this, never the message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Effect {
    /// The request never reached the supervisor.
    None,
    /// The supervisor answered with a refusal.
    Refused,
    /// The frame was handed over and no answer was seen. The request may have run; the
    /// host reconciles with the same operation id and must not send a new one.
    Unknown,
}

impl Effect {
    const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Refused => "refused",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug)]
pub(super) struct V2Error {
    pub(super) code: RamfluxErrorCode,
    pub(super) message: String,
    pub(super) effect: Effect,
    pub(super) reason_code: Option<String>,
    pub(super) bus_code: Option<String>,
    pub(super) retry_after_ms: Option<u64>,
    pub(super) details: Option<Value>,
}

pub(super) type V2Result<T> = Result<T, V2Error>;

impl V2Error {
    pub(super) fn new(code: RamfluxErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            effect: Effect::None,
            reason_code: None,
            bus_code: None,
            retry_after_ms: None,
            details: None,
        }
    }

    pub(super) fn with_effect(mut self, effect: Effect) -> Self {
        self.effect = effect;
        self
    }

    pub(super) fn with_reason(mut self, reason: &str) -> Self {
        self.reason_code = Some(reason.to_owned());
        self
    }

    /// A cancelled waiter. OPEN-VALUE: the stable enum has no `Cancelled` discriminant, so
    /// the number is `Timeout` and the reason says which.
    pub(super) fn cancelled(effect: Effect) -> Self {
        Self::new(RamfluxErrorCode::Timeout, "request was cancelled by the host")
            .with_effect(effect)
            .with_reason("cancelled")
    }

    pub(super) fn deadline(effect: Effect) -> Self {
        Self::new(RamfluxErrorCode::Timeout, "request deadline exceeded")
            .with_effect(effect)
            .with_reason("deadline_exceeded")
    }

    pub(super) fn closed(effect: Effect) -> Self {
        Self::new(RamfluxErrorCode::TransportUnavailable, "supervisor connection is closed")
            .with_effect(effect)
            .with_reason("closed")
    }

    /// A failure of the in-process transport or of local validation.
    pub(super) fn from_sdk(error: &SdkError, effect: Effect) -> Self {
        let text = error.to_string();
        let code = if text.contains("deadline exceeded") {
            RamfluxErrorCode::Timeout
        } else {
            sdk_error_code(error)
        };
        Self::new(code, text).with_effect(effect)
    }

    /// A refusal frame from the supervisor.
    pub(super) fn from_refusal(error: Option<LocalBusErrorBody>) -> Self {
        let Some(error) = error else {
            return Self::new(RamfluxErrorCode::Internal, "supervisor refusal carried no error")
                .with_effect(Effect::Refused);
        };
        Self {
            code: refusal_code(&error.code),
            message: error.message,
            effect: Effect::Refused,
            reason_code: error.reason_code,
            bus_code: Some(error.code),
            retry_after_ms: error.retry_after_ms,
            details: error.details.map(|details| *details),
        }
    }

    pub(super) fn to_json(&self) -> Value {
        json!({
            "code": self.code as i32,
            "name": self.code.name(),
            "message": self.message,
            "effect": self.effect.name(),
            "reason_code": self.reason_code,
            "bus_code": self.bus_code,
            "retry_after_ms": self.retry_after_ms,
            "details": self.details,
        })
    }
}

impl From<super::super::CAbiError> for V2Error {
    fn from(error: super::super::CAbiError) -> Self {
        Self::new(error.code, error.message)
    }
}

/// Stable number for a local-bus refusal code.
///
/// OPEN-VALUE: the design fixes the numbers, not this table. An unlisted refusal is
/// `Internal` and keeps its text in `bus_code`, so a new refusal never borrows the meaning
/// of an existing number.
pub(super) fn refusal_code(code: &str) -> RamfluxErrorCode {
    match code {
        "account_busy" | "DataRootInUse" => RamfluxErrorCode::AccountBusy,
        "ObjectErased" | "AttachmentDeleted" => RamfluxErrorCode::ObjectErased,
        "ObjectIdentityConflict" => RamfluxErrorCode::ObjectIdentityConflict,
        "ObjectOwnershipUnverified" => RamfluxErrorCode::ObjectOwnershipUnverified,
        "CustodyForkFenced" => RamfluxErrorCode::CustodyForkFenced,
        "SchemaResetRequired" => RamfluxErrorCode::SchemaResetRequired,
        "AccountSchemaTooNew" => RamfluxErrorCode::UnsupportedVersion,
        "CapabilityDenied" => RamfluxErrorCode::CapabilityRejected,
        "authorization_rejected" | "RemoteAppApprovalRequired" | "GrantInvalidated" => {
            RamfluxErrorCode::PermissionDenied
        }
        "storage_unavailable" | "ManifestUnreadable" => RamfluxErrorCode::StorageFailed,
        "ValidationFailed" | "too_large" | "InvalidOfflineRetention" | "CustodySetupInvalid"
        | "TaskDeliveryTooLarge" => RamfluxErrorCode::InvalidArgument,
        "SignatureVerificationFailed" | "AnchorMismatch" | "CustodyVaultUnavailable"
        | "CustodyRandomUnavailable" => RamfluxErrorCode::CryptoFailed,
        "ReplayMismatch" => RamfluxErrorCode::ReplayRejected,
        "NetworkingPending" | "Unavailable" | "NoNodeSelected" | "AccountRestorePending" => {
            RamfluxErrorCode::TransportUnavailable
        }
        "TaskDeliveryTimeout" => RamfluxErrorCode::Timeout,
        "CallControlReceiptCapacity" | "GroupStateCapacity" => RamfluxErrorCode::RateLimited,
        _ => RamfluxErrorCode::Internal,
    }
}

/// Write the diagnostic JSON to the optional error out-parameter.
pub(super) fn write_error(out_error_json: *mut *mut RamfluxBuffer, error: &V2Error) {
    if out_error_json.is_null() {
        return;
    }
    let bytes = serde_json::to_vec(&error.to_json()).unwrap_or_else(|_source| {
        br#"{"code":16,"name":"Internal","message":"failed to serialize error","effect":"unknown"}"#
            .to_vec()
    });
    let _ignored = write_buffer(out_error_json, bytes);
}
