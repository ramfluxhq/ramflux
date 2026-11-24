// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Suspend keeps unlocked accounts in memory and releases every process file they hold.

use crate::prelude::*;

#[cfg(feature = "c-abi")]
use super::actor::AccountActor;
#[cfg(feature = "c-abi")]
use super::supervisor::Supervisor;
#[cfg(feature = "c-abi")]
use std::sync::atomic::Ordering;

pub(crate) fn client_suspended() -> SdkError {
    SdkError::LocalBusRefused {
        code: "ClientSuspended".into(),
        message: "client is suspended".into(),
        body: Box::new(serde_json::Value::Null),
    }
}

#[cfg(feature = "c-abi")]
impl Supervisor {
    pub(super) async fn suspend_for_background(&self) -> Result<(), SdkError> {
        let control = self.app_control.lock().await;
        if self.config.background.load(Ordering::Acquire) && self.root_lease.borrow().is_none() {
            ramflux_transport::drain_abandoned_quic().await;
            return Ok(());
        }
        self.arm_app_suspend().await?;
        self.config.background.store(true, Ordering::Release);
        let node = self.node_actor.clone();
        let accounts = self.accounts.borrow().values().cloned().collect::<Vec<_>>();
        let parked = self.park_actors(&node, &accounts).await;
        let released = parked.and_then(|()| self.index.release_files().map_err(SdkError::from));
        // Stop has dropped every QUIC client. Return only after those UDP sockets close.
        ramflux_transport::drain_abandoned_quic().await;
        if let Err(error) = released {
            // Release can fail after earlier actors (or SQLite itself) have closed files.
            // Keep admission fenced until every owner has been reopened.
            drop(control);
            let rollback = self.resume_for_background().await;
            return Err(SdkError::LocalBusRefused {
                code: "SuspendFailed".into(),
                message: "suspend failed; call resume to recover".into(),
                body: Box::new(serde_json::json!({
                    "reason": if rollback.is_ok() {
                        "suspend_release_failed"
                    } else {
                        "suspend_rollback_failed"
                    },
                    "release_stage": if matches!(error, SdkError::Storage(_)) {
                        "storage"
                    } else {
                        "actor"
                    }
                })),
            });
        }
        self.root_lease.borrow_mut().take();
        Ok(())
    }

    pub(super) async fn resume_for_background(&self) -> Result<(), SdkError> {
        let _control = self.app_control.lock().await;
        if !self.config.background.load(Ordering::Acquire) && self.root_lease.borrow().is_some() {
            return Ok(());
        }
        self.reacquire_root().await?;
        self.index.reopen_files().map_err(SdkError::from)?;
        self.expire_app_deadlines().await?;
        let node = self.node_actor.clone();
        let accounts = self.accounts.borrow().values().cloned().collect::<Vec<_>>();
        // Try every actor: one refusal must not strand the remaining parked owners.
        let mut reopened = node.reopen_files().await;
        for actor in &accounts {
            let result = actor.reopen_files().await;
            if reopened.is_ok() {
                reopened = result;
            }
        }
        reopened?;
        self.expire_app_deadlines().await?;
        // Resume can be a background wake on a locked device. Only an explicit
        // foreground lifecycle signal may cancel a deadline that has not expired.
        self.config.background.store(false, Ordering::Release);
        Ok(())
    }

    async fn park_actors(
        &self,
        node: &AccountActor,
        accounts: &[AccountActor],
    ) -> Result<(), SdkError> {
        node.release_files().await?;
        for actor in accounts {
            actor.release_files().await?;
        }
        Ok(())
    }

    async fn reacquire_root(&self) -> Result<(), SdkError> {
        if self.root_lease.borrow().is_some() {
            return Ok(());
        }
        let lease = match self.config.session_lease {
            Some(lease) => super::session_lease::acquire(&self.config.data_root, lease).await?,
            None => super::data_root_lock::DataRootLock::acquire(&self.config.data_root)?,
        };
        *self.root_lease.borrow_mut() = Some(lease);
        Ok(())
    }
}
