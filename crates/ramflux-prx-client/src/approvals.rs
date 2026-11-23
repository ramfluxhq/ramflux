// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `POST /api/sessions/{id}/approvals/{approval_id}` (`run_approvals_v1`).
//! The body is `{"decision":"approved"|"denied"}`. The same decision is an idempotent echo.

use crate::capabilities::{Capabilities, RUN_APPROVALS_V1, require};
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, decode_ok, local_refusal, protocol};
use reqwest::Method;
use serde::Deserialize;
use serde_json::json;

/// The 200 body of one approval decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalReceipt {
    pub approval_id: String,
    pub run_id: String,
    pub decision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReceipt {
    approval_id: String,
    run_id: String,
    decision: String,
}

fn path_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

impl PrxClient {
    /// Decides one live run approval. Needs `run_approvals_v1`.
    /// `409 approval_decided` and `409 approval_run_mismatch` are API errors.
    /// `404 approval_unknown` and `410 approval_expired` are API errors.
    /// A repeated `decision` returns the same receipt.
    ///
    /// # Errors
    /// Returns `Unsupported` or a local `field_invalid` before any request, or the API error.
    pub async fn decide_run_approval(
        &self,
        caps: &Capabilities,
        session_id: &str,
        approval_id: &str,
        decision: &str,
    ) -> Result<ApprovalReceipt, PrxError> {
        require(caps, RUN_APPROVALS_V1)?;
        if !path_id(session_id) || !path_id(approval_id) {
            return Err(local_refusal(ApiCode::FieldInvalid));
        }
        if decision != "approved" && decision != "denied" {
            return Err(local_refusal(ApiCode::FieldInvalid));
        }
        let path = format!("/api/sessions/{session_id}/approvals/{approval_id}");
        let raw = self
            .transport
            .call(Method::POST, &path, None, Some(&json!({"decision": decision})))
            .await?;
        let wire: WireReceipt = decode_ok(&raw.body)?;
        if wire.approval_id != approval_id || wire.decision != decision || !path_id(&wire.run_id) {
            return Err(protocol("approval decision does not match the request"));
        }
        Ok(ApprovalReceipt {
            approval_id: wire.approval_id,
            run_id: wire.run_id,
            decision: wire.decision,
        })
    }
}
