// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Central push delivery (`[push_central]`): one handoff batch per wake, sent to federation over
//! its Unix socket. Routes are sealed and the centre sends to the providers. Direct provider
//! retries do not apply here (N18).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use ramflux_node_core::push_handoff::{
    CentralClass, HandoffReply, HandoffRequest, HandoffStatus, HandoffWake, MAX_WAKES,
    PushCentralState, WakeOutcome, exchange_handoff, read_push_central_state,
};
use ramflux_node_core::{DevicePushRoute, NodePushConfig, NotifyQueueEntry, NotifyRedbStore};
use ramflux_protocol::NotificationDeliveryClass;

/// Hold time after an `unserved` answer (A6.4 and section 5, N11).
const UNSERVED_PAUSE_MS: u64 = 3_600_000;

static CENTRAL: OnceLock<CentralPush> = OnceLock::new();

/// Installs the central delivery path when `[push_central]` is configured. Absent means direct.
///
/// # Errors
/// Returns an error when the section was configured twice.
pub(crate) fn configure(config: Option<NodePushConfig>) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(config) = config else {
        return Ok(());
    };
    CENTRAL
        .set(CentralPush {
            state_file: config.state_file,
            handoff_socket: config.handoff_socket,
            first_send: Mutex::new(HashMap::new()),
        })
        .map_err(|_| {
            ramflux_node_core::NodeCoreError::InvalidConfiguration(
                "push_central configured twice".into(),
            )
        })
}

/// The installed central path, when the node runs in central mode.
pub(crate) fn active() -> Option<&'static CentralPush> {
    CENTRAL.get()
}

pub(crate) struct CentralPush {
    state_file: PathBuf,
    handoff_socket: PathBuf,
    /// First handoff time of each (queue entry, route tag, generation). Keeps the node's
    /// `handoff_deadline` fixed across resends (A1.2). It is not durable yet (see the U3 report).
    first_send: Mutex<HashMap<(String, String, u64), u64>>,
}

/// Maps a protocol delivery class to the central class. Classes outside the batch (for
/// example conference and AI wakes) are not sent centrally in this revision.
fn central_class(class: &NotificationDeliveryClass) -> Option<CentralClass> {
    match class {
        NotificationDeliveryClass::UserContentNotification => Some(CentralClass::M),
        NotificationDeliveryClass::CallWakeNotification => Some(CentralClass::Call),
        _ => None,
    }
}

fn now_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

impl CentralPush {
    /// Delivers one wake through the centre. Returns `Ok(true)` when the state changed and the
    /// entry should be looked at again at once.
    ///
    /// # Errors
    /// Returns storage errors. Handoff transport failures are logged and retried by the due time.
    pub(crate) fn deliver(
        &self,
        store: &NotifyRedbStore,
        entry: &NotifyQueueEntry,
    ) -> Result<bool, ramflux_node_core::NodeCoreError> {
        let Some(class) = central_class(&entry.wake.delivery_class) else {
            return Ok(false);
        };
        // No state file yet: no session has reported `dir.served`, so nothing is submitted (A6.4).
        let Some(state) = read_push_central_state(&self.state_file)? else {
            tracing::debug!("central push state not yet written; holding wake");
            return Ok(false);
        };
        let now_ms = now_unix_millis();
        let routes = store.central_candidate_routes(
            &entry.device_delivery_id,
            class,
            &state.served,
            now_ms,
        )?;
        let mut batch = Vec::new();
        for route in routes {
            if let Some(wake) = self.wake_for(entry, class, &state, &route, now_ms)? {
                batch.push((route, wake));
            }
        }
        let mut changed = false;
        for chunk in batch.chunks(MAX_WAKES) {
            let request = HandoffRequest {
                v: ramflux_node_core::push_handoff::HANDOFF_VERSION,
                wakes: chunk.iter().map(|(_, wake)| wake.clone()).collect(),
            };
            match exchange_handoff(&self.handoff_socket, &request) {
                Ok(reply) => changed |= self.apply_reply(store, chunk, &reply, now_ms)?,
                Err(error) => {
                    tracing::warn!(%error, "central handoff socket exchange failed");
                }
            }
        }
        Ok(changed)
    }

    fn wake_for(
        &self,
        entry: &NotifyQueueEntry,
        class: CentralClass,
        state: &PushCentralState,
        route: &DevicePushRoute,
        now_ms: u64,
    ) -> Result<Option<HandoffWake>, ramflux_node_core::NodeCoreError> {
        let cap_s = match class {
            CentralClass::M => state.ttl_max_s.m,
            CentralClass::Call => state.ttl_max_s.call,
            CentralClass::X => state.ttl_max_s.x,
            CentralClass::T => state.ttl_max_s.t,
        };
        let key = (entry.queue_id.clone(), route.route_tag.clone(), route.route_generation);
        let first = {
            let mut sent = self.first_send.lock().map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestJson(format!("first-send lock: {source}"))
            })?;
            *sent.entry(key).or_insert(now_ms)
        };
        let internal_ms = entry.expires_at.saturating_mul(1000);
        let deadline = internal_ms.min(first.saturating_add(cap_s.saturating_mul(1000)));
        let ttl = deadline.saturating_sub(now_ms) / 1000;
        if ttl == 0 {
            tracing::info!(route_tag = %route.route_tag, "central wake expired before send; dropped");
            return Ok(None);
        }
        Ok(Some(HandoffWake {
            w: entry.wake.wake_id.clone(),
            c: class,
            ttl,
            rt: route.route_tag.clone(),
            st: route.token.clone(),
        }))
    }

    /// Settles the batch. Results are matched by position (A8.5).
    fn apply_reply(
        &self,
        store: &NotifyRedbStore,
        chunk: &[(DevicePushRoute, HandoffWake)],
        reply: &HandoffReply,
        now_ms: u64,
    ) -> Result<bool, ramflux_node_core::NodeCoreError> {
        match reply.status {
            HandoffStatus::Ok if reply.results.len() == chunk.len() => {}
            HandoffStatus::Ok => {
                tracing::warn!("central handoff reply length mismatch; treated as transport failure");
                return Ok(false);
            }
            status => {
                tracing::warn!(?status, why = ?reply.why, "central handoff batch not accepted");
                return Ok(false);
            }
        }
        let mut changed = false;
        for ((route, _wake), result) in chunk.iter().zip(reply.results.iter()) {
            let snapshot = ramflux_node_core::CentralRouteSnapshot {
                route_tag: &route.route_tag,
                generation: route.route_generation,
                sealed_token: &route.token,
            };
            match result.r {
                WakeOutcome::Accepted | WakeOutcome::Duplicate => {}
                WakeOutcome::InvalidRoute => match result.at {
                    Some(at) => {
                        changed |= store.central_route_invalidate(
                            &route.device_delivery_id,
                            snapshot,
                            at,
                        )?;
                    }
                    // Without `at` the route is kept and the wake dropped (plan assumption 6).
                    None => tracing::info!("central invalid_route without at; route kept"),
                },
                WakeOutcome::Reseal => {
                    changed |= store.central_route_mark_reseal(&route.device_delivery_id, snapshot)?;
                }
                WakeOutcome::Unserved => {
                    changed |= store.central_route_pause(
                        &route.device_delivery_id,
                        snapshot,
                        now_ms.saturating_add(UNSERVED_PAUSE_MS),
                    )?;
                }
                WakeOutcome::Refused => {
                    tracing::info!(why = ?result.why, "central wake refused for one route");
                }
            }
        }
        Ok(changed)
    }
}
