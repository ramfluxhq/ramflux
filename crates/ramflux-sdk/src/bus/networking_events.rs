// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persist networking transitions while leaving countdown reads write-free.
use super::state::LocalBusAccountState;
use crate::{AccountNetworkingReason, SdkError, custody::BornAccount};
use serde_json::Value;

pub(super) fn record(
    account: &LocalBusAccountState,
    native: &BornAccount,
    now: u64,
) -> Result<bool, SdkError> {
    let mut body = custody_body(account, native, now)?;
    let db = account.client.account_db()?;
    let previous = db.load_actor_state::<Value>("account/networking")?;
    if let Some(session) = previous.as_ref().and_then(|body| body.get("session")) {
        body["session"] = session.clone();
    }
    persist(account, previous.as_ref(), &body)
}

fn custody_body(
    account: &LocalBusAccountState,
    native: &BornAccount,
    now: u64,
) -> Result<Value, SdkError> {
    let id = &account.client.account_db()?.local_account_id;
    let binding = account.gateway_config.custody.as_ref().map(|config| {
        crate::custody::capacity_hint::node_identity(&config.node_id, &config.node_public_key)
    });
    Ok(serde_json::json!({
        "account_id":id,
        "state":native.state(),
        "node_binding":binding,
        "networking_reason":native.networking_view(now),
    }))
}

#[allow(dead_code)] // Wired to runtime observations in the following part.
pub(super) fn record_session(
    account: &LocalBusAccountState,
    snapshot: &super::connection_manager::NetworkingSnapshot,
) -> Result<bool, SdkError> {
    let previous = account.client.account_db()?.load_actor_state::<Value>("account/networking")?;
    let mut body = match previous.clone() {
        Some(body) => body,
        None => custody_body(
            account,
            account.client.born_v3_account.as_deref().ok_or(SdkError::AccountDbNotUnlocked)?,
            crate::custody::network_now()?,
        )?,
    };
    body["session"] = serde_json::json!({
        "state": snapshot.state,
        "phase": snapshot.phase,
        "generation": snapshot.generation,
        "cause": snapshot.cause,
        "retry_after_ms": snapshot.retry_after_ms,
    });
    persist(account, previous.as_ref(), &body)
}

fn persist(
    account: &LocalBusAccountState,
    previous: Option<&Value>,
    body: &Value,
) -> Result<bool, SdkError> {
    if previous.map(cause_and_binding) == Some(cause_and_binding(body)) {
        return Ok(false);
    }
    account.client.account_db()?.persist_actor_state("account/networking", body)?;
    Ok(true)
}

fn cause_and_binding(body: &Value) -> Value {
    let mut key = body.clone();
    if key["networking_reason"]["kind"] == "node_busy"
        && let Some(cause) = key["networking_reason"].as_object_mut()
    {
        let shared_deadline = cause.contains_key("remaining_ms");
        cause.insert("shared_capacity_deadline".into(), Value::Bool(shared_deadline));
        // These describe the countdown at capture time; they are not a new cause.
        for field in ["retry_after_ms", "remaining_ms", "resets_at", "clamped"] {
            cause.remove(field);
        }
    }
    if let Some(session) = key.get_mut("session").and_then(Value::as_object_mut) {
        session.remove("generation");
        session.remove("retry_after_ms");
        if let Some(cause) = session.get_mut("cause").and_then(Value::as_object_mut) {
            cause.remove("retry_after_ms");
        }
    }
    key
}

pub(super) fn refresh_expired(account: &LocalBusAccountState) -> Result<bool, SdkError> {
    if account.client.born_v3_account.is_none() {
        return Ok(false);
    }
    refresh_expired_at(account, crate::custody::network_now()?)
}

pub(super) fn refresh_expired_at(
    account: &LocalBusAccountState,
    now: u64,
) -> Result<bool, SdkError> {
    let Some(native) = account.client.born_v3_account.as_deref() else {
        return Ok(false);
    };
    if matches!(native.networking_reason(), Some(AccountNetworkingReason::NodeBusy { .. })) {
        // A short hint may expire before the retry floor; publish that cause
        // change too, then publish the end of the floor when it is reached.
        return record(account, native, now);
    }
    Ok(false)
}

#[cfg(test)]
mod tests;
