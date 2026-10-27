// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Background expiry scheduling for persisted relay chunks.

use crate::config::now_unix_seconds;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub(crate) fn start_expire_scheduler(
    store: Arc<ramflux_node_core::RelayRedbStore>,
    state: Arc<Mutex<ramflux_node_core::RelayCacheState>>,
) {
    let interval = ramflux_node_core::environment::var("RAMFLUX_RELAY_GC_SWEEP_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60)
        .max(60);
    thread::spawn(move || {
        loop {
            if let Err(error) = expire_relay_chunks_once(&store, &state) {
                tracing::warn!(%error, "relay background object chunk expiry failed");
            }
            thread::sleep(Duration::from_secs(interval));
        }
    });
}

pub(crate) fn expire_relay_chunks_once(
    store: &ramflux_node_core::RelayRedbStore,
    state: &Mutex<ramflux_node_core::RelayCacheState>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    // Persist-before-publish: redb rows are batch-deleted before the resident metadata is removed and
    // its charge released. On persist failure the resident entries stay put but reads reject them by
    // expires_at, so a restart cannot resurrect a servable payload.
    let mutation = ramflux_node_core::relay_store_expire(store, state, now_unix_seconds())
        .map_err(ramflux_node_core::RelayStoreOpError::into_node_core)?;
    tracing::info!(
        expired = mutation.expired_count(),
        "relay background object chunk expiry completed"
    );
    Ok(())
}
