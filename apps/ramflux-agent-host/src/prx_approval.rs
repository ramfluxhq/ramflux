// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Posts one owner decision to `POST /api/sessions/{id}/approvals/{approval_id}`.
//! Typed PRX codes come back as `Ok`. Transport failures stay retryable.

use crate::engine::RunApprovalPost;
use crate::{Error, Result};
use ramflux_prx_client::{ApiCode, PrxClient, PrxError};

/// # Errors
/// Returns [`Error::Bus`] when PRX cannot be reached, and [`Error::EngineRejected`] when the
/// client cannot be used. A coded PRX refusal is `Ok` with `code` set.
pub async fn post(
    client: &PrxClient,
    session: &str,
    approval_id: &str,
    decision: &str,
) -> Result<RunApprovalPost> {
    let caps = client.capabilities().await.map_err(|error| map_transport(&error))?;
    match client.decide_run_approval(&caps, session, approval_id, decision).await {
        Ok(receipt) => Ok(RunApprovalPost {
            approval_id: receipt.approval_id,
            run_id: receipt.run_id,
            decision: receipt.decision,
            code: None,
            cause: None,
        }),
        Err(PrxError::Api { code, .. }) => Ok(coded(approval_id, decision, &code)),
        Err(error) => Err(map_transport(&error)),
    }
}

fn coded(approval_id: &str, decision: &str, code: &ApiCode) -> RunApprovalPost {
    let name = code_name(code);
    let cause = (name == "approval_expired").then(|| "expired".to_owned());
    RunApprovalPost {
        approval_id: approval_id.to_owned(),
        run_id: String::new(),
        decision: decision.to_owned(),
        code: Some(name),
        cause,
    }
}

fn code_name(code: &ApiCode) -> String {
    match code {
        ApiCode::ApprovalDecided => "approval_decided".to_owned(),
        ApiCode::ApprovalRunMismatch => "approval_run_mismatch".to_owned(),
        ApiCode::ApprovalUnknown => "approval_unknown".to_owned(),
        ApiCode::ApprovalExpired => "approval_expired".to_owned(),
        ApiCode::FieldInvalid => "field_invalid".to_owned(),
        ApiCode::Unknown(text) if code_ok(text) => text.clone(),
        _ => "prx_refused".to_owned(),
    }
}

fn code_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

fn map_transport(error: &PrxError) -> Error {
    match error {
        PrxError::Unavailable | PrxError::Timeout | PrxError::RateLimited { .. } => Error::Bus,
        _ => Error::EngineRejected,
    }
}
