// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Anonymous group wakes use federation's existing local central-push handoff. A batch is
//! attempted once; throttling, refusal and transport failures drop only the wakes. No answer
//! writes or deletes a route. The worker holds neither the router writer nor the queue lock
//! while talking to federation.

use std::sync::Arc;
use std::time::Duration;

use ramflux_node_core::NodePushConfig;
use ramflux_node_core::push_handoff::{
    CentralClass, HANDOFF_VERSION, HandoffRequest, HandoffStatus, exchange_handoff,
    read_push_central_state,
};

use crate::router_runtime::RouterHandle;

const WAKE_TICK: Duration = Duration::from_secs(1);

/// Start one bounded handoff worker when the router has central push configured.
pub(crate) fn start(
    config: Option<NodePushConfig>,
    router: Arc<RouterHandle>,
) -> anyhow::Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    ramflux_node_core::spawn_service_worker("router-group-wakes", move |_| {
        let mut state_unavailable = false;
        while ramflux_node_core::service_shutdown_sleep(WAKE_TICK) {
            let state = match read_push_central_state(&config.state_file) {
                Ok(Some(state)) if state.classes.contains(&CentralClass::X) => {
                    state_unavailable = false;
                    state
                }
                Ok(_) | Err(_) => {
                    if !state_unavailable {
                        tracing::warn!("group wakes waiting for central class X state");
                        state_unavailable = true;
                    }
                    continue;
                }
            };
            let Some(host) = router.group_host() else {
                return;
            };
            let wakes = match host.drain_due(
                router.store(),
                super::group_routes::now_ms(),
                state.ttl_max_s.x,
            ) {
                Ok(wakes) => wakes,
                Err(refusal) => {
                    tracing::warn!(code = refusal.code(), "group wake batch dropped");
                    continue;
                }
            };
            if wakes.is_empty() {
                continue;
            }
            let request = HandoffRequest { v: HANDOFF_VERSION, wakes };
            // No route, group, sealed token, wake id or remote reason enters these logs.
            match exchange_handoff(&config.handoff_socket, &request) {
                Ok(reply) if reply.status == HandoffStatus::Ok => {}
                Ok(reply) => tracing::debug!(status = ?reply.status, "group wake handoff dropped"),
                Err(_) => tracing::warn!("group wake handoff unavailable; batch dropped"),
            }
        }
    })?;
    Ok(())
}
