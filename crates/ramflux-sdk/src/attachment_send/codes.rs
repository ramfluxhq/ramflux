// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stable refusal codes. Callers match the code, not the text.

use crate::SdkError;

pub(crate) const CODE_PATH_REFUSED: &str = "path_refused";
pub(crate) const CODE_FILE_TOO_LARGE: &str = "file_too_large";
pub(crate) const CODE_MANIFEST_TOO_LARGE: &str = "manifest_too_large";
pub(crate) const CODE_STREAM_CLOSED: &str = "stream_closed";
pub(crate) const CODE_STREAM_OFFSET: &str = "stream_offset";
pub(crate) const CODE_DIGEST_MISMATCH: &str = "digest_mismatch";
pub(crate) const CODE_QUOTA_EXCEEDED: &str = "quota_exceeded";
pub(crate) const CODE_DISK_FULL: &str = "disk_full";
pub(crate) const CODE_PEER_UPGRADE: &str = "peer_upgrade_required";
pub(crate) const CODE_RECIPIENT_LIMIT: &str = "recipient_limit";
pub(crate) const CODE_AUTHORITY_UNAVAILABLE: &str = "authority_unavailable";
pub(crate) const CODE_RECIPIENT_EMPTY: &str = "recipient_empty";
pub(crate) const CODE_NOT_GRANTEE: &str = "not_grantee";
pub(crate) const CODE_LAYOUT_INVALID: &str = "layout_invalid";
pub(crate) const CODE_SEAL_FAILED: &str = "seal_failed";
pub(crate) const CODE_UPLOAD_REJECTED: &str = "upload_rejected";
pub(crate) const CODE_EXPIRED: &str = "expired";
pub(crate) const CODE_STALE_GENERATION: &str = "stale_generation";
pub(crate) const CODE_NOT_OWNER: &str = "not_owner";
pub(crate) const CODE_NOT_READY: &str = "not_ready";
pub(crate) const CODE_CANCELLED: &str = "cancelled";
pub(crate) const CODE_DUPLICATE: &str = "duplicate_operation";
pub(crate) const CODE_ATTACHMENT_DELETED: &str = "attachment_deleted";
pub(crate) const CODE_RETIREMENT_PENDING: &str = "retirement_pending";
pub(crate) const CODE_DISABLED: &str = "large_attachments";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub code: &'static str,
}

impl Refusal {
    #[must_use]
    pub(crate) const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

/// # Errors
/// Returns the stable code carried by an owner result. A missing code is a normal result.
pub(crate) fn owner_result_code(code: Option<&str>) -> Result<(), Refusal> {
    match code {
        None => Ok(()),
        Some(CODE_QUOTA_EXCEEDED) => Err(Refusal::new(CODE_QUOTA_EXCEEDED)),
        Some(CODE_RETIREMENT_PENDING) => Err(Refusal::new(CODE_RETIREMENT_PENDING)),
        Some(CODE_EXPIRED) => Err(Refusal::new(CODE_EXPIRED)),
        Some(_) => Err(Refusal::new(CODE_UPLOAD_REJECTED)),
    }
}

impl From<Refusal> for SdkError {
    fn from(refusal: Refusal) -> Self {
        SdkError::LocalBusRefused {
            code: refusal.code.to_owned(),
            message: refusal.code.to_owned(),
            body: Box::new(serde_json::json!({ "code": refusal.code })),
        }
    }
}
