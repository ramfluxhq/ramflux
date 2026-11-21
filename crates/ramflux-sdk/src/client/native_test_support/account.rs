// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]

//! Synchronous native generation-1 account for tests that only need a real unlocked account.
use super::Fixture;
use crate::SdkError;

/// Builds the same phrase-created native account as `Fixture::with_device` on a private,
/// current-thread runtime so plain `#[test]` functions can use it. It must not be called from
/// inside an async test; those use `Fixture::with_device` directly.
pub(crate) fn blocking(id: &str, device: &str) -> Result<Fixture, SdkError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| SdkError::LocalBus(format!("test: fixture runtime: {error}")))?;
    runtime
        .block_on(Box::pin(Fixture::with_device(id, device)))
        .map_err(|error| SdkError::LocalBus(format!("test: native fixture: {error}")))
}

impl Fixture {
    /// Locks and reopens the account database exactly as a restart does, then re-certifies the
    /// local branch from the same vault.
    pub(crate) async fn reopen(&mut self) -> super::TestResult {
        let id = self.client.account_db()?.local_account_id.clone();
        self.client.active_account_db = None;
        self.client.unlock_account(&id, b"native fixture data passphrase")?;
        self.client.initialize_born_v3_branch(&self.config.device_id, self.vault.clone()).await?;
        Ok(())
    }
}
