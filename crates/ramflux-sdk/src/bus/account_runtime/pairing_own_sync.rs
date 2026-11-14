// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Enrollment completion schedules one ordinary history attempt, independent of pairing success.
use super::AccountRuntime;
use crate::{SdkError, bus::io::local_bus_error_code};
impl AccountRuntime {
    pub(super) async fn service_pairing_own_sync(&mut self) -> Result<bool, SdkError> {
        let mut shutdown = self.shutdown.clone();
        let mut preempt = self.preempt.clone();
        let budget = self.timeouts.sync;
        if *shutdown.borrow() || preempt.has_changed().unwrap_or(true) {
            return Ok(false);
        }
        let Some(account) = self.state.accounts.get_mut(&self.id) else { return Ok(false) };
        if account.client.node_relay_options.is_none() || account.client.born_v3_account.is_none() {
            return Ok(false);
        }
        let Some(job) = account.client.account_db()?.next_pairing_own_sync()? else {
            return Ok(false);
        };
        let Ok(mut engine) = account.live_session_client() else { return Ok(false) };
        let pool = account.relay_quic_pool()?;
        if !account.client.account_db()?.claim_pairing_own_sync(&job)? {
            return Ok(false);
        }
        let result = tokio::select! {
            biased;
            _ = shutdown.changed() => Err(SdkError::PairingCode("Retired")),
            _ = preempt.changed() => Err(SdkError::PairingCode("Retired")),
            result = tokio::time::timeout(budget,Box::pin(account.client.export_pairing_history(&mut engine,&pool,&job))) => {
                result.unwrap_or_else(|_| Err(SdkError::PairingCode("ResumeRequired")))
            }
        };
        account.apply_session_metadata(engine);
        let error = result.as_ref().err().map(local_bus_error_code);
        account.client.account_db()?.finish_pairing_own_sync(&job, error)?;
        if let Some(error) = error {
            tracing::warn!(
                error_code = error,
                "pairing history synchronization incomplete; retry with device sync export"
            );
        }
        Ok(true)
    }
    pub(super) async fn maintain_pairing_own_sync(&mut self) {
        if let Err(error) = self.service_pairing_own_sync().await {
            tracing::debug!(
                error_code = local_bus_error_code(&error),
                "pairing history synchronization deferred"
            );
        }
    }
}
