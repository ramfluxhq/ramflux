// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Mesh route and periodic sweep of the group host (MLS-SPEC r1.2 2). The gateway holds the
//! anonymous direct sessions and calls one op at a time; the call carries the session kind, the
//! group and the op body, never a source address, session id or account.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ramflux_node_core::large_group::host::{HostConfig, LargeGroupHost};
use ramflux_node_core::{GROUP_HOST_ROUTER_PATH, GroupHostCall};

use crate::handlers::MeshResponse;
use crate::router_runtime::RouterHandle;

const GATEWAY: &str = "ramflux-gateway";
/// Seconds between two sweeps (retention, join expiry, blob orphans, routes).
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Groups one sweep call looks at.
const SWEEP_BATCH: usize = 64;
/// Calls one sweep tick makes at most (`SWEEP_BATCH` groups each).
const SWEEP_CALLS_MAX: usize = 64;

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Dispatch a group host op from the gateway. Other paths return `None`.
///
/// # Errors
/// Encoding failures.
pub(crate) fn route(
    peer_service_id: &str,
    method: &str,
    path: &str,
    body: &[u8],
    router: &RouterHandle,
) -> anyhow::Result<Option<MeshResponse>> {
    if path != GROUP_HOST_ROUTER_PATH {
        return Ok(None);
    }
    if method != "POST" {
        return Ok(Some(MeshResponse::text("405 Method Not Allowed", "method not allowed")));
    }
    if peer_service_id != GATEWAY {
        return Ok(Some(MeshResponse::text("403 Forbidden", "route requires an admitted caller")));
    }
    let Some(host) = router.group_host() else {
        return Ok(Some(MeshResponse::text("503 Service Unavailable", "group host unavailable")));
    };
    let Ok(call) = ramflux_protocol::parse_i_json::<GroupHostCall>(body) else {
        return Ok(Some(MeshResponse::text("400 Bad Request", "request rejected")));
    };
    let reply = ramflux_node_core::run_group_op(host, router.store(), now_ms(), &call);
    Ok(Some(MeshResponse::json("200 OK", serde_json::to_vec(&reply)?)))
}

/// Opens the host beside the router state file and starts its periodic sweep.
///
/// # Errors
/// The key directory cannot be prepared or the host is installed twice.
pub(crate) fn start(
    config: &ramflux_node_core::NodeServiceConfig,
    router: Arc<RouterHandle>,
) -> anyhow::Result<()> {
    let push = ramflux_node_core::load_node_push_config(std::env::args().skip(1))?;
    let state = ramflux_node_core::effective_redb_path(config);
    let dir = state
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| std::path::PathBuf::from("."), std::path::Path::to_path_buf);
    let host = LargeGroupHost::open(
        &dir.join("large-group-keys"),
        HostConfig::new(config.node_id.clone()),
    )
    .map_err(|refusal| anyhow::anyhow!("group host unavailable: {refusal}"))?;
    router.install_group_host(Arc::new(host))?;
    crate::group_wakes::start(push, Arc::clone(&router))?;
    if let Err(error) = ramflux_node_core::spawn_service_worker("router-group-sweep", move |_| {
        while ramflux_node_core::service_shutdown_sleep(SWEEP_INTERVAL) {
            sweep_once(&router);
        }
    }) {
        tracing::error!(%error, "group host sweep worker unavailable");
    }
    Ok(())
}

fn sweep_once(router: &RouterHandle) {
    let Some(host) = router.group_host() else {
        return;
    };
    let mut cursor = None;
    for _ in 0..SWEEP_CALLS_MAX {
        match host.sweep(router.store(), now_ms(), cursor, SWEEP_BATCH) {
            Ok(None) => return,
            Ok(next) => cursor = next,
            Err(refusal) => {
                tracing::warn!(code = refusal.code(), "group host sweep deferred");
                return;
            }
        }
    }
}
