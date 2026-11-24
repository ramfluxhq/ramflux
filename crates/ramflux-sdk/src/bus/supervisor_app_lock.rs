// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! App-lock policy on the supervisor. An open session of the named account authorizes a change.

use super::super::lifecycle;
use super::Supervisor;
use crate::bus::io::request_account_id;
use crate::prelude::*;
use ramflux_storage::{AppLockPolicy, StorageError, WrappedAccountDbKey};

impl Supervisor {
    /// Clears leftover silent wraps before any account can open. A failure is logged;
    /// the open path still refuses an account whose stored policy is on.
    pub(super) fn reconcile_app_lock_wraps(&self) {
        if let Err(error) = self.index.strip_enabled_app_lock_wraps() {
            tracing::warn!(%error, "app lock wrap reconcile did not finish");
        }
    }

    pub(super) async fn configure_app_lock(
        &self,
        request: &LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<super::ActorResponse, SdkError> {
        let account_id = self.authorize_app_lock_change(request, connection)?;
        let enabled = required_bool(&request.body)?;
        let timeout_ms = required_timeout(&request.body)?;
        let policy = if enabled {
            self.write_app_lock(account_id, true, timeout_ms, None).await?
        } else {
            let actor =
                self.accounts.borrow().get(&account_id).cloned().ok_or_else(unauthorized)?;
            let wrap = actor.silent_device_wrap().await?;
            self.write_app_lock(account_id, false, timeout_ms, Some(wrap)).await?
        };
        Ok(super::reply(state_body(&policy, true)))
    }

    pub(super) async fn app_lock_state(
        &self,
        request: &LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<super::ActorResponse, SdkError> {
        let account_id = request_account_id(request)?.to_owned();
        refuse_attended(connection, &account_id)?;
        let index = self.index.clone();
        let id = account_id.clone();
        let policy = lifecycle::spawn_blocking(move || read_policy(&index, &id))
            .await
            .map_err(|error| SdkError::LocalBus(format!("index reader failed: {error}")))??;
        let open =
            self.accounts.borrow().get(&account_id).is_some_and(super::AccountActor::is_open);
        Ok(super::reply(match policy {
            PolicyRead::Ready(policy) => state_body(&policy, open),
            PolicyRead::Unreadable => unavailable_body(),
        }))
    }

    fn authorize_app_lock_change(
        &self,
        request: &LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<String, SdkError> {
        let account_id = request_account_id(request)?.to_owned();
        refuse_body_account(&request.body, &account_id)?;
        refuse_attended(connection, &account_id)?;
        let open =
            self.accounts.borrow().get(&account_id).is_some_and(super::AccountActor::is_open);
        if !open {
            return Err(unauthorized());
        }
        Ok(account_id)
    }

    async fn write_app_lock(
        &self,
        account_id: String,
        enabled: bool,
        timeout_ms: u64,
        wrap: Option<WrappedAccountDbKey>,
    ) -> Result<AppLockPolicy, SdkError> {
        let index = self.index.clone();
        lifecycle::spawn_blocking(move || commit(&index, &account_id, enabled, timeout_ms, wrap))
            .await
            .map_err(|error| SdkError::LocalBus(format!("index writer failed: {error}")))?
    }
}

enum PolicyRead {
    Ready(AppLockPolicy),
    Unreadable,
}

fn commit(
    index: &ramflux_storage::AccountIndex,
    account_id: &str,
    enabled: bool,
    timeout_ms: u64,
    wrap: Option<WrappedAccountDbKey>,
) -> Result<AppLockPolicy, SdkError> {
    if enabled {
        Ok(index.enable_app_lock(account_id, timeout_ms)?)
    } else {
        let wrap =
            wrap.ok_or(StorageError::Integrity("app lock disable requires a device wrap"))?;
        Ok(index.disable_app_lock(account_id, timeout_ms, &wrap)?)
    }
}

fn read_policy(
    index: &ramflux_storage::AccountIndex,
    account_id: &str,
) -> Result<PolicyRead, SdkError> {
    index.account(account_id)?;
    match index.app_lock_policy(account_id) {
        Ok(policy) => Ok(PolicyRead::Ready(policy)),
        Err(StorageError::AccountNotFound(missing)) => {
            Err(SdkError::Storage(StorageError::AccountNotFound(missing)))
        }
        Err(_) => Ok(PolicyRead::Unreadable),
    }
}

fn state_body(policy: &AppLockPolicy, open: bool) -> serde_json::Value {
    let (state, reason) = if open {
        ("unlocked", "authenticated")
    } else if policy.enabled {
        ("locked", "cold_start")
    } else {
        ("locked", "manual")
    };
    serde_json::json!({
        "enabled": policy.enabled,
        "timeout_ms": policy.timeout_ms,
        "state": state,
        "reason": reason,
        "remaining_ms": 0,
        "presence_available": false,
        "generation": policy.generation,
    })
}

fn unavailable_body() -> serde_json::Value {
    serde_json::json!({
        "enabled": false,
        "timeout_ms": 0,
        "state": "unavailable",
        "reason": "custody_unavailable",
        "remaining_ms": 0,
        "presence_available": false,
        "generation": 0,
    })
}

fn required_bool(body: &serde_json::Value) -> Result<bool, SdkError> {
    body.get("enabled").and_then(serde_json::Value::as_bool).ok_or_else(invalid_argument)
}

fn required_timeout(body: &serde_json::Value) -> Result<u64, SdkError> {
    let timeout_ms =
        body.get("timeout_ms").and_then(serde_json::Value::as_u64).ok_or_else(invalid_argument)?;
    if timeout_ms > ramflux_storage::APP_LOCK_MAX_TIMEOUT_MS {
        return Err(invalid_argument());
    }
    Ok(timeout_ms)
}

fn refuse_body_account(body: &serde_json::Value, account_id: &str) -> Result<(), SdkError> {
    for key in ["account_id", "local_account_id"] {
        if body
            .get(key)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|named| named != account_id)
        {
            return Err(unauthorized());
        }
    }
    Ok(())
}

fn refuse_attended(connection: &LocalBusConnectionState, account_id: &str) -> Result<(), SdkError> {
    if connection.attended_account_id.as_deref().is_some_and(|attended| attended != account_id) {
        return Err(unauthorized());
    }
    Ok(())
}

fn unauthorized() -> SdkError {
    SdkError::LocalBusRefused {
        code: "app_lock_unauthorized".to_owned(),
        message: "app lock policy requires the unlocked account".to_owned(),
        body: Box::new(serde_json::json!({"reason_code": "app_lock_unauthorized"})),
    }
}

fn invalid_argument() -> SdkError {
    SdkError::LocalBusRefused {
        code: "invalid_argument".to_owned(),
        message: "app lock timeout must be from 0 through 86400000 milliseconds".to_owned(),
        body: Box::new(serde_json::json!({"reason_code": "invalid_argument"})),
    }
}
