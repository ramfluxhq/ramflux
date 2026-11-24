// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! App-lock policy on the supervisor. An open session of the named account authorizes a change.

use super::super::lifecycle;
use super::Supervisor;
use crate::bus::io::request_account_id;
use crate::prelude::*;
use ramflux_storage::{AppLockPolicy, StorageError, WrappedAccountDbKey};
use std::sync::Arc;

impl Supervisor {
    pub(super) async fn app_control_guard(
        &self,
        method: &str,
    ) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        if matches!(
            method,
            "account.app_lock.configure"
                | "account.app_lock.lock"
                | "account.unlock"
                | "account.lock"
                | "account.sign_out"
        ) {
            Some(self.app_control.lock().await)
        } else {
            None
        }
    }
    pub(super) async fn finish_hard_app_lock(&self, id: &str) -> Result<(), SdkError> {
        let _drained = Arc::clone(&self.app_fences.delivery).write_owned().await;
        let request = LocalBusFrame::request(
            "",
            Some(id.into()),
            "account",
            "account.lock",
            serde_json::json!({}),
        );
        self.emit_app_lock_change(&request, id)
    }

    pub(in crate::bus) fn admit_app_access(&self, request: &LocalBusFrame) -> Result<(), SdkError> {
        if super::super::app_lock_fence::control(&request.method) {
            return Ok(());
        }
        self.app_fences
            .token(super::super::app_lock_fence::scope(
                &request.method,
                request.account_id.as_deref(),
            ))?
            .check()
    }
    pub(super) fn app_unlocked(&self, id: &str) -> Result<(), SdkError> {
        let policy = self.index.app_lock_policy(id)?;
        if policy.enabled {
            self.app_fences.transition(id, true, false, "authenticated")?;
            let request = LocalBusFrame::request(
                "",
                Some(id.into()),
                "account",
                "account.unlock",
                serde_json::json!({}),
            );
            self.emit_app_lock_change(&request, id)?;
        }
        Ok(())
    }
    fn app_lock_body(
        &self,
        policy: &AppLockPolicy,
        id: &str,
    ) -> Result<serde_json::Value, SdkError> {
        let open = self.accounts.borrow().get(id).is_some_and(super::AccountActor::is_open);
        let epoch = self.app_fences.epoch(id)?;
        let mut body = state_body(policy, open && !epoch.locked);
        let fields = body.as_object_mut().ok_or(SdkError::CustodySetupInvalid)?;
        fields.insert("generation".into(), epoch.generation.into());
        if !epoch.reason.is_empty() {
            fields.insert("reason".into(), epoch.reason.into());
        }
        Ok(body)
    }
    pub(super) fn emit_app_lock_change(
        &self,
        request: &LocalBusFrame,
        id: &str,
    ) -> Result<(), SdkError> {
        let epoch = self.app_fences.epoch(id)?;
        let frame = local_bus_event(
            request,
            id,
            "account",
            "account.app_lock.changed",
            serde_json::json!({
                "state": if epoch.locked { "locked" } else { "unlocked" },
                "reason": epoch.reason, "generation": epoch.generation, "remaining_ms": 0,
            }),
        );
        self.controls.borrow_mut().retain(|_, outbound| outbound.try_send(frame.clone()).is_ok());
        Ok(())
    }
    pub(super) async fn lock_app_access(
        &self,
        request: &LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<super::ActorResponse, SdkError> {
        let id = request_account_id(request)?.to_owned();
        refuse_attended(connection, &id)?;
        let policy = self.index.app_lock_policy(&id)?;
        if !policy.enabled {
            return Err(SdkError::LocalBusRefused {
                code: "app_lock_disabled".into(),
                message: "app lock is disabled".into(),
                body: Box::new(serde_json::json!({"reason_code":"app_lock_disabled"})),
            });
        }
        self.app_fences.transition(&id, true, true, "manual")?;
        self.close_app_subscriptions(&id);
        self.backup_jobs.app_lock_account(&id).await?;
        self.lock_account_session(&id).await?;
        // Every transport write admitted before the epoch change must finish before acknowledgement.
        let _drained = Arc::clone(&self.app_fences.delivery).write_owned().await;
        self.emit_app_lock_change(request, &id)?;
        Ok(super::reply(self.app_lock_body(&policy, &id)?))
    }
    pub(super) fn close_app_subscriptions(&self, id: &str) {
        let ids = self
            .subscribers
            .borrow()
            .iter()
            .filter_map(|(key, subscriber)| (subscriber.account_id == id).then_some(*key))
            .collect::<Vec<_>>();
        for key in ids {
            self.clear_stream(key);
        }
        // Journal streams do not all have an ephemeral subscriber. Their producer epoch fences
        // delivery even if a tail has already enqueued a page; abort the account-bound tails.
        let ids = self
            .stream_accounts
            .borrow()
            .iter()
            .filter_map(|(key, account)| {
                account.as_deref().is_none_or(|account| account == id).then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in ids {
            self.clear_stream(key);
        }
        self.subscribers.borrow_mut().retain(|_, subscriber| subscriber.account_id != id);
    }

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
            self.write_app_lock(account_id.clone(), true, timeout_ms, None).await?
        } else {
            let actor =
                self.accounts.borrow().get(&account_id).cloned().ok_or_else(unauthorized)?;
            let wrap = actor.silent_device_wrap().await?;
            self.write_app_lock(account_id.clone(), false, timeout_ms, Some(wrap)).await?
        };
        self.app_fences.transition(&account_id, policy.enabled, false, "configured")?;
        self.emit_app_lock_change(request, &account_id)?;
        Ok(super::reply(self.app_lock_body(&policy, &account_id)?))
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
        Ok(super::reply(match policy {
            PolicyRead::Ready(policy) => self.app_lock_body(&policy, &account_id)?,
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
