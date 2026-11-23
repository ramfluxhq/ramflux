// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Suspend keeps unlocked accounts in memory and releases every process file they hold.

use super::actor::AccountActor;
use super::supervisor::Supervisor;
use crate::prelude::*;
use std::sync::atomic::Ordering;

pub(crate) fn client_suspended() -> SdkError {
    SdkError::LocalBusRefused {
        code: "ClientSuspended".into(),
        message: "client is suspended".into(),
        body: Box::new(serde_json::Value::Null),
    }
}

impl Supervisor {
    pub(super) async fn suspend_for_background(&self) -> Result<(), SdkError> {
        if self.config.background.load(Ordering::Acquire) && self.root_lease.borrow().is_none() {
            return Ok(());
        }
        self.config.background.store(true, Ordering::Release);
        let node = self.node_actor.clone();
        let accounts = self.accounts.borrow().values().cloned().collect::<Vec<_>>();
        self.park_actors(&node, &accounts).await?;
        self.index.release_files().map_err(SdkError::from)?;
        self.root_lease.borrow_mut().take();
        Ok(())
    }

    pub(super) async fn resume_for_background(&self) -> Result<(), SdkError> {
        if !self.config.background.load(Ordering::Acquire) && self.root_lease.borrow().is_some() {
            return Ok(());
        }
        self.reacquire_root()?;
        self.index.reopen_files().map_err(SdkError::from)?;
        let node = self.node_actor.clone();
        let accounts = self.accounts.borrow().values().cloned().collect::<Vec<_>>();
        node.reopen_files().await?;
        for actor in &accounts {
            actor.reopen_files().await?;
        }
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

    fn reacquire_root(&self) -> Result<(), SdkError> {
        if self.root_lease.borrow().is_some() {
            return Ok(());
        }
        let lease = super::data_root_lock::DataRootLock::acquire(&self.config.data_root)?;
        *self.root_lease.borrow_mut() = Some(lease);
        Ok(())
    }
}
