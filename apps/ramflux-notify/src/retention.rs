// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wakes and provider diagnostics have independent bounded retention lifetimes.
pub(crate) fn start(
    store: std::sync::Arc<ramflux_node_core::NotifyRedbStore>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    store.sweep_retention(ramflux_node_core::now_unix_seconds())?;
    let revocations = std::sync::Arc::clone(&store);
    std::thread::Builder::new()
        .name("notify-route-revocation".into())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(30));
                if let Err(error) = revocations.sweep_push_route_revocations() {
                    tracing::warn!(%error, "push route revocation sweep deferred");
                }
            }
        })
        .map_err(|error| ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()))?;
    std::thread::Builder::new()
        .name("notify-retention".into())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(30));
                if let Err(error) = store.sweep_retention(ramflux_node_core::now_unix_seconds()) {
                    tracing::warn!(%error,"notify retention deferred");
                }
            }
        })
        .map_err(|error| ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()))?;
    Ok(())
}
