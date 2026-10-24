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
        tokio::time::timeout(
            Duration::from_millis(250),
            client.cache_verified_device_manifest(
                &account.gateway_config,
                &root,
                "own-contact-backfill",
            ),
        )
        .await
        .map_err(|_| {
            SdkError::InboundPending("own contact refresh tick budget exhausted".into())
        })??;
    }
    client.stage_contact_backfill_batch()
}
