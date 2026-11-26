// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Helpers the owner agent methods share: the account, the PRX client of the desktop daemon, and the
//! refusals of the JSON agent methods (`LocalBusRefused` with `{reason_code, details}`).

use crate::prelude::*;
use ramflux_prx_client::{ApiCode, PrxClient, PrxError};
use serde_json::{Value, json};

pub(super) fn prx_client(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<std::sync::Arc<PrxClient>, SdkError> {
    account(request, state).map(|_| ())?;
    state
        .config
        .prx
        .clone()
        .ok_or_else(|| refused("prx_unconfigured", "the desktop daemon has no PRX client"))
}

pub(super) fn account<'a>(
    request: &LocalBusFrame,
    state: &'a mut LocalBusDaemonState,
) -> Result<&'a RamfluxClient, SdkError> {
    Ok(&local_bus_account_mut(state, request_account_id(request)?)?.client)
}

pub(super) fn field_invalid(key: &str) -> SdkError {
    refused("field_invalid", key)
}

pub(super) fn map_prx(error: &PrxError) -> SdkError {
    match error {
        PrxError::Api { code: ApiCode::CronJobUnknown, .. } => {
            refused("cron_job_unknown", "no such cron job")
        }
        PrxError::Api { code: ApiCode::XinTaskUnknown, .. } => {
            refused("xin_task_unknown", "no such xin task")
        }
        PrxError::Api { code: ApiCode::XinGoalUnknown, .. } => {
            refused("xin_goal_unknown", "no such xin goal")
        }
        PrxError::Api { code: ApiCode::AgentUnknown, .. } => {
            refused("agent_unknown", "agent_unknown")
        }
        PrxError::Api { code: ApiCode::ModelCapabilitiesUnknown, .. } => {
            refused("model_capabilities_unknown", "model_capabilities_unknown")
        }
        PrxError::Api { code: ApiCode::AuthFailed, .. } => refused("auth_failed", "auth_failed"),
        PrxError::Api { code: ApiCode::FieldInvalid | ApiCode::AgentToolsInvalid, .. } => {
            refused("field_invalid", "field_invalid")
        }
        PrxError::Api { code: ApiCode::AgentInvalid, .. } => {
            refused("agent_invalid", "agent_invalid")
        }
        PrxError::Api { code: ApiCode::StorageUnavailable, .. } => {
            refused("storage_unavailable", "storage_unavailable")
        }
        PrxError::Unsupported { .. } => refused("prx_unsupported", "prx_unsupported"),
        PrxError::Unavailable | PrxError::Timeout => refused("prx_unavailable", "prx_unavailable"),
        _ => refused("prx_rejected", "prx_rejected"),
    }
}

pub(super) fn refused(code: &str, detail: &str) -> SdkError {
    refused_with(code, json!({"cause": detail}))
}

/// A refusal whose `details` object is `details` (for example `current_revision` and `current`).
pub(super) fn refused_with(code: &str, details: Value) -> SdkError {
    SdkError::LocalBusRefused {
        code: code.to_owned(),
        message: code.to_owned(),
        body: Box::new(json!({"reason_code": code, "details": details})),
    }
}
