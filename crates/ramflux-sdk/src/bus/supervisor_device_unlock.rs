// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Silent native unlock through the device wrap: at daemon start, on switch, after idle.
//!
//! Only accounts that were not explicitly locked and still hold a device wrap open this way;
//! an explicit lock removes the device wrap, so the account code is needed again.

use super::{AccountActor, RestoreState, Supervisor};
use crate::bus::native_account::NativeUnlockSecret;
use crate::prelude::*;

impl Supervisor {
    /// Whether `id` is native account data that may open without user input.
    pub(super) fn silently_unlockable(&self, id: &str) -> Result<bool, SdkError> {
        if !crate::custody::account_exists(&self.config.data_root, id)? {
            return Ok(false);
        }
        let Ok(account) = self.index.account(id) else {
            return Ok(false);
        };
        if account.account_state == "locked" {
            return Ok(false);
        }
        if self.index.app_lock_policy(id)?.enabled {
            return Ok(false);
        }
        Ok(self.index.load_device_wrapped_db_key(id)?.is_some())
    }

    /// Opens a native account through its device wrap without changing the active account.
    pub(super) async fn unlock_native_silently(
        &self,
        id: &str,
    ) -> Result<crate::LocalBusCreatedAccount, SdkError> {
        self.refuse_unusable_agent(id)?;
        self.start_event_router();
        let existing = self.accounts.borrow().get(id).cloned();
        let (actor, started) = if let Some(actor) = existing {
            (actor, false)
        } else {
            let actor = AccountActor::start(
                id.into(),
                self.config.clone(),
                self.nodes.borrow().clone(),
                self.index.clone(),
                self.events.clone(),
            )?;
            self.accounts.borrow_mut().insert(id.into(), actor.clone());
            (actor, true)
        };
        let result = match actor.unlock_native(NativeUnlockSecret::Device, None).await {
            Ok(result) => result,
            Err(error) => {
                if started {
                    self.accounts.borrow_mut().remove(id);
                    if let Err(stop) = actor.stop().await {
                        tracing::warn!(%stop, "silent unlock actor did not stop cleanly");
                    }
                }
                return Err(error);
            }
        };
        self.set_unlocked(id, true).await?;
        self.advance_after_unlock(id).await;
        Ok(result)
    }

    /// Daemon start: reopen native accounts that were open (not explicitly locked) before.
    pub(super) fn hydrate_native(
        self: &Rc<Self>,
        account_id: String,
        tasks: &mut tokio::task::JoinSet<()>,
    ) -> Result<(), SdkError> {
        if !self.silently_unlockable(&account_id)? {
            return Ok(());
        }
        self.restore_states
            .borrow_mut()
            .insert(account_id.clone(), RestoreState::Pending(watch::channel(()).0));
        let supervisor = Rc::clone(self);
        tasks.spawn_local(async move {
            let request = LocalBusFrame::request(
                "restore",
                Some(account_id.clone()),
                "account",
                "account.unlock",
                serde_json::json!({}),
            );
            let body = match supervisor.unlock_native_silently(&account_id).await {
                Ok(_) => serde_json::json!({"state":"unlocked"}),
                Err(error) => {
                    tracing::warn!(%error, "native account did not reopen silently");
                    serde_json::json!({"state":"locked", "reason_code": local_bus_error_code(&error)})
                }
            };
            // A failed silent reopen leaves the account locked, never blocked: its code still
            // opens it when the device secret is present.
            supervisor.restore_states.borrow_mut().remove(&account_id);
            supervisor.broadcast(&[local_bus_event(
                &request,
                &account_id,
                "account",
                "account.restore.finished",
                body,
            )]);
        });
        Ok(())
    }

    /// Explicit lock: drop the device wrap so only the account code opens the account again.
    pub(super) async fn clear_device_wrap(&self, id: &str) -> Result<(), SdkError> {
        let index = self.index.clone();
        let id = id.to_owned();
        super::super::lifecycle::spawn_blocking(move || index.clear_device_wrapped_db_key(&id))
            .await
            .map_err(|error| SdkError::LocalBus(format!("index writer failed: {error}")))??;
        Ok(())
    }
}
