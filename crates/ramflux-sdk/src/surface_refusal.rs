// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stable machine-readable surface refusals, independent of English diagnostics.
use crate::SdkError;
use ramflux_protocol::SurfaceReject;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceRefusalCode {
    StaleVersion,
    StaleHash,
    NotAuthor,
    NotOutOfSync,
    RateLimited,
    TooLarge,
    NotFound,
    OutOfSync,
    NotActionExecutor,
    AlreadyUsed,
    Closed,
    NotPermitted,
    InvalidRequest,
}
impl SurfaceRefusalCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleVersion => "stale_version",
            Self::StaleHash => "stale_hash",
            Self::NotAuthor => "not_author",
            Self::NotOutOfSync => "not_out_of_sync",
            Self::RateLimited => "rate_limited",
            Self::TooLarge => "too_large",
            Self::NotFound => "not_found",
            Self::OutOfSync => "out_of_sync",
            Self::NotActionExecutor => "not_action_executor",
            Self::AlreadyUsed => "already_used",
            Self::Closed => "closed",
            Self::NotPermitted => "not_permitted",
            Self::InvalidRequest => "invalid_request",
        }
    }
    pub(crate) fn error(self, message: impl Into<String>) -> SdkError {
        SdkError::SurfaceRefused { reason: self, message: message.into() }
    }
    pub(crate) fn renderer(error: &serde_json::Value) -> Self {
        if let Ok(reject) = serde_json::from_value::<SurfaceReject>(error["reject"].clone()) {
            return match reject {
                SurfaceReject::Version { .. } | SurfaceReject::Stale => Self::StaleVersion,
                SurfaceReject::Conflict
                | SurfaceReject::ResultHashMismatch
                | SurfaceReject::ArgumentsHashMismatch => Self::StaleHash,
                SurfaceReject::Closed | SurfaceReject::BlockClosed => Self::Closed,
                SurfaceReject::NotCreated => Self::NotFound,
                SurfaceReject::LimitExceeded { .. } => Self::TooLarge,
                _ => Self::InvalidRequest,
            };
        }
        match error["code"].as_str() {
            Some("non_author_update" | "action_not_for_author") => Self::NotAuthor,
            Some("unknown_surface") => Self::NotFound,
            Some("action_already_used" | "message_id_conflict") => Self::AlreadyUsed,
            Some("awaiting_action_executor") => Self::NotActionExecutor,
            Some("surface_author_or_conversation_mismatch") => Self::NotPermitted,
            Some("snapshot_required" | "snapshot_rejected" | "out_of_sync") => Self::OutOfSync,
            _ => Self::InvalidRequest,
        }
    }
}
pub(crate) fn map_surface_error(error: SdkError) -> SdkError {
    match error {
        SdkError::LocalBus(message) => SurfaceRefusalCode::InvalidRequest.error(message),
        SdkError::Protocol(error) => SurfaceRefusalCode::InvalidRequest.error(error.to_string()),
        SdkError::Json(error) => SurfaceRefusalCode::InvalidRequest.error(error.to_string()),
        other => other,
    }
}
