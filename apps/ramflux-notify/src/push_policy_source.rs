// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Where the node's push policy comes from (CENTRAL P2b K11).
//!
//! Central mode: federation owns the rfc-push-1 session and writes `dir.policy` into the push
//! state file. This poller applies it to the store once the state holds a key set (a reply
//! has been received). Direct mode has no centre, so the node applies a local default equal
//! to the centre's version-0 values.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Policy used in direct mode: the centre's version-0 values (`n_s` 120, `t_s` 10).
pub(crate) fn direct_mode_policy() -> ramflux_node_core::push_handoff::PushPolicy {
    ramflux_node_core::push_handoff::PushPolicy { version: 0, n_s: 120, t_s: 10 }
}

/// Applies the policy source for this process: the central poller when `[push_central]` is
/// set, otherwise the direct-mode default.
pub(crate) fn install(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    if let Some(push) = ramflux_node_core::load_node_push_config(std::env::args().skip(1))? {
        start_central(Arc::clone(store), push.state_file);
    } else {
        store.set_push_policy(direct_mode_policy());
        tracing::info!(
            target: "ramflux_notify_policy",
            event = "policy.direct_default",
            "direct push: local default policy applied"
        );
    }
    Ok(())
}

/// Polls the central push state file and applies its `dir.policy` to the store.
pub(crate) fn start_central(store: Arc<ramflux_node_core::NotifyRedbStore>, state_file: PathBuf) {
    let spawned = std::thread::Builder::new().name("notify-push-policy".into()).spawn(move || {
        let mut published: Option<ramflux_node_core::PolicyStatsHour> = None;
        loop {
            match ramflux_node_core::push_handoff::read_push_central_state(&state_file) {
                Ok(Some(state)) if state.ks.is_some() => {
                    store.set_push_policy(state.policy);
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::debug!(%error, "push policy state not readable yet");
                }
            }
            bridge_stats(&store, &state_file, &mut published);
            std::thread::sleep(POLL_INTERVAL);
        }
    });
    if let Err(error) = spawned {
        tracing::warn!(%error, "push policy poller not started; holds stay off");
    }
}

/// Publishes the newest completed, unacknowledged stats hour for federation's next `sync`, and
/// applies the acknowledgement federation wrote after an `ok` reply (CENTRAL P2b K11, A7.2).
fn bridge_stats(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    state_file: &std::path::Path,
    published: &mut Option<ramflux_node_core::PolicyStatsHour>,
) {
    match ramflux_node_core::push_policy_stats::take_stats_ack(state_file) {
        Ok(Some(from_ms)) => {
            if let Err(error) = store.ack_policy_stats(from_ms) {
                tracing::warn!(%error, "policy stats ack not recorded");
            }
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(%error, "policy stats ack unreadable"),
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0);
    let pending = match store.pending_policy_stats(now_ms) {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(%error, "policy stats unavailable");
            return;
        }
    };
    if pending == *published {
        return;
    }
    if let Err(error) = ramflux_node_core::push_policy_stats::write_pending_stats(
        state_file,
        pending.as_ref(),
    ) {
        tracing::warn!(%error, "policy stats file not written");
        return;
    }
    *published = pending;
}
