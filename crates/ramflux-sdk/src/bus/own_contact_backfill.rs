// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Detect new active siblings and backfill accepted contacts through the bounded own-device queue.
use crate::prelude::*;

pub(crate) async fn drive(account: &LocalBusAccountState) -> Result<usize, SdkError> {
    let client = &account.client;
    let db = client.account_db()?;
    let now = now_unix_timestamp();
    let last = db.load_actor_state::<i64>("own-contact/last-refresh")?.unwrap_or(0);
    if now.saturating_sub(last) >= 5 {
        // Record attempts too, so a network outage cannot create an unbounded retry loop.
        db.persist_actor_state("own-contact/last-refresh", &now)?;
        let root = client.owned_device_identity()?.root_commitment().to_owned();
        let gateway =
            account.engine.as_ref().map_or(&account.gateway_config, |engine| &engine.config);
        tokio::time::timeout(
            Duration::from_millis(250),
            client.cache_verified_device_manifest(gateway, &root, "own-contact-backfill"),
        )
        .await
        .map_err(|_| {
            SdkError::InboundPending("own contact refresh tick budget exhausted".into())
        })??;
    }
    if let Some(root) = client.claim_contact_backfill_refresh(now)? {
        let gateway =
            account.engine.as_ref().map_or(&account.gateway_config, |engine| &engine.config);
        match tokio::time::timeout(
            Duration::from_millis(250),
            client.cache_verified_device_manifest(gateway, &root, "own-contact-peer-backfill"),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::debug!(%error, "contact peer manifest refresh deferred"),
            Err(_) => tracing::debug!("contact peer manifest refresh tick budget exhausted"),
        }
    }
    client.stage_contact_backfill_batch()
}
