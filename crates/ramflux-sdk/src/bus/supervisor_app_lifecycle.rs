// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One monotonic app-lock deadline per account, shared by every frontend and suspend owner.

use super::Supervisor;
use crate::bus::io::request_account_id;
use crate::platform::app_lock_clock::Deadline;
use crate::prelude::*;

impl Supervisor {
    pub(super) async fn app_lifecycle(
        &self,
        request: &LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<super::ActorResponse, SdkError> {
        let id = request_account_id(request)?;
        super::app_lock::refuse_attended(connection, id)?;
        let state = request.body.get("state").and_then(serde_json::Value::as_str);
        if !matches!(state, Some("background" | "foreground" | "device_locked")) {
            return Err(SdkError::LocalBusRefused {
                code: "invalid_argument".into(),
                message: "lifecycle state must be background, foreground or device_locked".into(),
                body: Box::new(serde_json::json!({"reason_code":"invalid_argument"})),
            });
        }
        let policy = self.index.app_lock_policy(id)?;
        if policy.enabled {
            if state == Some("foreground") {
                self.cancel_app_deadline(request, id).await?;
            } else {
                self.arm_app_deadline(request, id, policy.timeout_ms).await?;
            }
        }
        Ok(super::reply(self.app_lock_body(&policy, id)?))
    }

    async fn arm_app_deadline(
        &self,
        request: &LocalBusFrame,
        id: &str,
        timeout_ms: u64,
    ) -> Result<(), SdkError> {
        let epoch = self.app_fences.epoch(id)?;
        if epoch.locked || epoch.deadline.is_some() {
            return Ok(());
        }
        let Ok(deadline) = Deadline::new(timeout_ms) else {
            return self.close_app_access(request, id, "timeout").await;
        };
        self.app_fences.deadline(id, Some(deadline.clone()))?;
        if deadline.remaining().is_zero() {
            return self.close_app_access(request, id, "timeout").await;
        }
        self.emit_app_lock_change(request, id)?;
        self.app_timer_wake.notify_one();
        Ok(())
    }

    async fn cancel_app_deadline(&self, request: &LocalBusFrame, id: &str) -> Result<(), SdkError> {
        // Caller expires all elapsed deadlines first. Foreground cannot revive a locked epoch.
        let epoch = self.app_fences.epoch(id)?;
        if epoch.expired() {
            return self.close_app_access(request, id, "timeout").await;
        }
        if epoch.deadline.is_some() {
            self.app_fences.deadline(id, None)?;
            self.emit_app_lock_change(request, id)?;
            self.app_timer_wake.notify_one();
        }
        Ok(())
    }

    pub(in crate::bus) async fn expire_app_deadlines(&self) -> Result<(), SdkError> {
        for (id, epoch) in self.app_fences.armed()? {
            if epoch.expired() {
                self.close_app_access(&lifecycle_request(&id), &id, "timeout").await?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "c-abi")]
    pub(in crate::bus) async fn arm_app_suspend(&self) -> Result<(), SdkError> {
        self.expire_app_deadlines().await?;
        let ids = self.accounts.borrow().keys().cloned().collect::<Vec<_>>();
        for id in ids {
            let policy = self.index.app_lock_policy(&id)?;
            if policy.enabled {
                self.arm_app_deadline(&lifecycle_request(&id), &id, policy.timeout_ms).await?;
            }
        }
        Ok(())
    }

    pub(super) fn start_app_timer(self: &Rc<Self>) {
        if self.app_timer.borrow().is_some() {
            return;
        }
        let owner = Rc::downgrade(self);
        let wake = self.app_timer_wake.clone();
        *self.app_timer.borrow_mut() = Some(tokio::task::spawn_local(async move {
            loop {
                let Some(supervisor) = owner.upgrade() else { break };
                let delay = supervisor.app_timer_pass().await;
                drop(supervisor);
                tokio::select! {
                    () = wake.notified() => {},
                    () = wait_deadline(delay) => {},
                }
            }
        }));
    }

    async fn app_timer_pass(&self) -> Option<Duration> {
        let _control = self.app_control.lock().await;
        if let Err(error) = self.expire_app_deadlines().await {
            tracing::warn!(%error, "app lock timeout teardown failed; access remains fenced");
        }
        self.app_fences.armed().ok().and_then(|epochs| {
            epochs
                .into_iter()
                .filter_map(|(_, epoch)| epoch.deadline)
                .map(|deadline| deadline.remaining().min(Duration::from_millis(250)))
                .min()
        })
    }
}

fn lifecycle_request(id: &str) -> LocalBusFrame {
    LocalBusFrame::request(
        "",
        Some(id.into()),
        "account",
        "account.app_lock.lifecycle",
        serde_json::json!({}),
    )
}

async fn wait_deadline(delay: Option<Duration>) {
    if let Some(delay) = delay {
        tokio::time::sleep(delay).await;
    } else {
        std::future::pending::<()>().await;
    }
}
