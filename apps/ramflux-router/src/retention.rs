// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Router-owned retention updates durable rows and the live delivery projection together.
use crate::router_runtime::RouterHandle;
pub(crate) fn sweep(
    router: &RouterHandle,
    request: &ramflux_node_core::RetentionGcSweepRequest,
) -> anyhow::Result<ramflux_node_core::RetentionGcSweepResponse> {
    anyhow::ensure!(request.owner_service == "router", "retention owner mismatch");
    let now = i64::try_from(request.now)?;
    if !request.dry_run {
        let changed = router.state().sweep_delivery_retention(now);
        for cursor in router.state().retention_cursors() {
            router.store().retain_cursor_checkpoint(&cursor)?;
        }
        if changed > 0 {
            router.state().persist_identity_registry(router.store())?;
        }
    }
    let removed = router.store().sweep_delivery_retention(now, request.dry_run)?;
    Ok(request.response(u64::try_from(removed)?))
}
pub(crate) fn start(router: std::sync::Arc<RouterHandle>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            let request = ramflux_node_core::RetentionGcSweepRequest {
                owner_service: "router".into(),
                sweep_id: "router-periodic".into(),
                now: ramflux_node_core::now_unix_seconds(),
                dry_run: false,
            };
            if let Err(error) = sweep(&router, &request) {
                tracing::warn!(%error,"router retention deferred");
            }
        }
    });
}
