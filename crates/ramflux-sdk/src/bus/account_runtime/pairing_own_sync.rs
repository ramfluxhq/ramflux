// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Enrollment completion schedules one ordinary history attempt, independent of pairing success.
use super::AccountRuntime;
use crate::{
    SdkError, bus::io::local_bus_error_code, client::own_device_sync::PairingHistoryProgress,
};
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
        // This service runs one attempt at a time, so an attempt still marked as started here was
        // interrupted by a crash or restart. The durable transfer makes running it again idempotent.
        account.client.account_db()?.requeue_interrupted_pairing_own_sync()?;
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
            _ = shutdown.changed() => Ok(PairingHistoryProgress::Pending),
            _ = preempt.changed() => Ok(PairingHistoryProgress::Pending),
            result = tokio::time::timeout(budget,Box::pin(account.client.export_pairing_history(&mut engine,&pool,&job))) => {
                result.unwrap_or(Ok(PairingHistoryProgress::Pending))
            }
        };
        account.apply_session_metadata(engine);
        // A head publication (for example this account's own layer renewal) that is mid
        // installation is transient: the durable transfer resumes once it settles.
        if matches!(
            result,
            Ok(PairingHistoryProgress::Pending) | Err(SdkError::PairingCode("PublicationPending"))
        ) {
            // The history courier continues the durable transfer; check again on a later pass.
            account.client.account_db()?.requeue_pairing_own_sync(&job)?;
            return Ok(true);
        }
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
