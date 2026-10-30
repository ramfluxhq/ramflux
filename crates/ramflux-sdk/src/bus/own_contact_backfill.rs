// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Detect new active siblings and backfill accepted contacts through the bounded own-device queue.
use crate::prelude::*;

const MANIFEST_REFRESH_WINDOW: Duration = Duration::from_secs(5);

pub(crate) async fn drive(account: &LocalBusAccountState) -> Result<usize, SdkError> {
    let client = &account.client;
    let db = client.account_db()?;
    let now = now_unix_timestamp();
    let last = db.load_actor_state::<i64>("own-contact/last-refresh")?.unwrap_or(0);
    if now.saturating_sub(last)
        >= i64::try_from(MANIFEST_REFRESH_WINDOW.as_secs()).unwrap_or(i64::MAX)
    {
        // Record attempts too, so a network outage cannot create an unbounded retry loop.
        db.persist_actor_state("own-contact/last-refresh", &now)?;
        let root = client.owned_device_identity()?.root_commitment().to_owned();
        let gateway =
            account.engine.as_ref().map_or(&account.gateway_config, |engine| &engine.config);
        let started = std::time::Instant::now();
        // A fresh authenticated directory request must have the full attempt interval to
        // finish; cancelling it every 250ms can prevent sibling discovery on a slow gateway.
        let refreshed = tokio::time::timeout(
            MANIFEST_REFRESH_WINDOW,
            client.cache_verified_device_manifest(gateway, &root, "own-contact-backfill"),
        )
        .await
        .map_err(|_| {
            SdkError::InboundPending("own manifest refresh attempt budget exhausted".into())
        })
        .and_then(std::convert::identity);
        if let Err(error) = &refreshed {
            // The persisted attempt timestamp limits this warning to once per five seconds.
            tracing::warn!(
                error_code = local_bus_error_code(error),
                elapsed_ms = started.elapsed().as_millis(),
                "own-device manifest refresh deferred"
            );
        }
        refreshed?;
    }
    if let Some(root) = client.claim_contact_backfill_refresh(now)? {
        let gateway =
            account.engine.as_ref().map_or(&account.gateway_config, |engine| &engine.config);
        let started = std::time::Instant::now();
        match tokio::time::timeout(
            MANIFEST_REFRESH_WINDOW,
            client.cache_verified_device_manifest(gateway, &root, "own-contact-peer-backfill"),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::warn!(
                error_code = local_bus_error_code(&error),
                elapsed_ms = started.elapsed().as_millis(),
                "contact peer manifest refresh deferred"
            ),
            Err(_) => tracing::warn!(
                error_code = "ManifestRefreshTimeout",
                elapsed_ms = started.elapsed().as_millis(),
                "contact peer manifest refresh deferred"
            ),
        }
    }
    client.stage_contact_backfill_batch()
}

#[cfg(test)]
#[path = "own_contact_backfill/tests.rs"]
pub(crate) mod tests;
