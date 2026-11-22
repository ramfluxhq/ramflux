// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Renew the live native grant when one third of its cap remains.

use super::SessionContext;
use crate::SdkError;
use std::time::Duration;
use tokio::time::{Instant, sleep_until};

/// Matches `NATIVE_SESSION_GRANT_SECONDS` in ramflux-node-core. The SDK library
/// cannot depend on that crate.
const NATIVE_SESSION_GRANT_SECONDS: u64 = 300;
const RENEW_LEAD_SECONDS: u64 = NATIVE_SESSION_GRANT_SECONDS / 3;
const RETRY_PAUSE: Duration = Duration::from_secs(1);

fn stop_on_error(context: &SessionContext, error: &SdkError) -> bool {
    context.generation != context.connection_generation()
        || matches!(error, SdkError::NetworkingPendingContext { .. } | SdkError::NetworkingPending)
}

fn native_expiry(context: &SessionContext) -> Option<u64> {
    context.connection.metadata().and_then(|meta| meta.config.native_grant_expires_at)
}

fn renew_delay(expires_at: u64) -> Duration {
    let now = crate::gateway::helpers::gateway_heartbeat_now();
    let seconds = expires_at
        .saturating_sub(now)
        .saturating_sub(RENEW_LEAD_SECONDS)
        .min(NATIVE_SESSION_GRANT_SECONDS);
    Duration::from_secs(seconds)
}

async fn wait_until(cancel: &mut tokio::sync::watch::Receiver<bool>, due: Instant) -> bool {
    tokio::select! {
        biased;
        _ = cancel.changed() => false,
        () = sleep_until(due) => true,
    }
}

impl SessionContext {
    pub(super) async fn renew_native_grant(&self) -> Result<u64, SdkError> {
        let timeout = self.connection.shared.timeouts.call;
        self.connection
            .call_class_generation(
                |engine| Box::pin(async move { engine.renew_native_grant().await }),
                Instant::now() + timeout,
                self.generation,
                super::CallClass::Bulk,
                Some(timeout),
            )
            .await
    }
}

pub(super) async fn run(context: SessionContext) {
    let Some(mut expires_at) = native_expiry(&context) else { return };
    let mut cancel = context.cancel.clone();
    if *cancel.borrow() {
        return;
    }
    loop {
        if !wait_until(&mut cancel, Instant::now() + renew_delay(expires_at)).await {
            return;
        }
        match context.renew_native_grant().await {
            Ok(next) => expires_at = next,
            Err(error) if stop_on_error(&context, &error) => return,
            Err(_) => {
                if !wait_until(&mut cancel, Instant::now() + RETRY_PAUSE).await {
                    return;
                }
            }
        }
    }
}
