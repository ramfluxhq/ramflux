// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Central push delivery (`[push_central]`): one handoff batch per wake, sent to federation over
//! its Unix socket. Routes are sealed and the centre sends to the providers. Direct provider
//! retries do not apply here (N18).

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use ramflux_node_core::push_handoff::{
    CentralClass, HandoffReply, HandoffRequest, HandoffStatus, HandoffWake, MAX_WAKES,
    PushCentralState, WakeOutcome, exchange_handoff, read_push_central_state,
};
use ramflux_node_core::{
    CentralRouteSnapshot, DevicePushRoute, NodePushConfig, NotifyQueueEntry, NotifyRedbStore,
};
use ramflux_protocol::NotificationDeliveryClass;

/// Hold time after an `unserved` answer (A6.4 and section 5, N11).
const UNSERVED_PAUSE_MS: u64 = 3_600_000;
/// Longest cap of any class (`m`); a first-send record older than this has no deadline left.
const FIRST_SEND_MAX_AGE_MS: u64 = 3_600_000;
/// Socket error back-off: 2 s, doubling, capped at 300 s (plan section 5).
const TRANSPORT_BACKOFF_FIRST_MS: u64 = 2_000;
const TRANSPORT_BACKOFF_CAP_MS: u64 = 300_000;
/// Default and bounds of a batch-level `retry_after_ms` (plan section 9.4).
const RETRY_AFTER_DEFAULT_MS: u64 = 2_000;
const RETRY_AFTER_MIN_MS: u64 = 1_000;
const RETRY_AFTER_MAX_MS: u64 = 3_600_000;
/// Wait after a `stopped` batch (federation has no session).
const STOPPED_WAIT_MS: u64 = 300_000;

static CENTRAL: OnceLock<CentralPush> = OnceLock::new();

/// Installs the central delivery path when `[push_central]` is configured. Absent means direct.
///
/// # Errors
/// Returns an error when the section was configured twice.
pub(crate) fn configure(
    config: Option<NodePushConfig>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(config) = config else {
        return Ok(());
    };
    CENTRAL
        .set(CentralPush {
            state_file: config.state_file,
            handoff_socket: config.handoff_socket,
            backoff: Mutex::new(Backoff::default()),
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

/// Back-off state of the handoff socket, shared by all delivery workers.
#[derive(Default)]
struct Backoff {
    /// No handoff is sent before this Unix ms time.
    until_ms: u64,
    /// Consecutive socket failures, for the doubling back-off.
    transport_failures: u32,
}

pub(crate) struct CentralPush {
    state_file: PathBuf,
    handoff_socket: PathBuf,
    backoff: Mutex<Backoff>,
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

/// Spreads a delay by -20 %..+20 % (plan section 5). Uses the clock's low bits as entropy.
fn with_jitter(delay_ms: u64, now_ms: u64) -> u64 {
    let percent = 80 + now_ms % 41;
    delay_ms.saturating_mul(percent) / 100
}

impl CentralPush {
    /// Delivers one wake through the centre. Returns `Ok(true)` when the state changed and the
    /// entry should be looked at again at once.
    ///
    /// # Errors
    /// Returns storage errors. Handoff transport failures are backed off, not returned.
    pub(crate) fn deliver(
        &self,
        store: &NotifyRedbStore,
        entry: &NotifyQueueEntry,
    ) -> Result<bool, ramflux_node_core::NodeCoreError> {
        let now_ms = now_unix_millis();
        if self.backoff_until() > now_ms {
            return Ok(false);
        }
        let Some(class) = central_class(&entry.wake.delivery_class) else {
            return Ok(false);
        };
        // No state file yet: no session has reported `dir.served`, so nothing is submitted (A6.4).
        let Some(state) = read_push_central_state(&self.state_file)? else {
            tracing::debug!("central push state not yet written; holding wake");
            return Ok(false);
        };
        let routes = store.central_candidate_routes(
            &entry.device_delivery_id,
            class,
            &state.served,
            now_ms,
        )?;
        let mut batch = Vec::new();
        for route in routes {
            let snapshot = CentralRouteSnapshot {
                route_tag: &route.route_tag,
                generation: route.route_generation,
                sealed_token: &route.token,
            };
            let Some((first, dropped)) = store.central_first_send(
                &route.device_delivery_id,
                snapshot,
                &entry.queue_id,
                now_ms,
                FIRST_SEND_MAX_AGE_MS,
            )?
            else {
                continue;
            };
            if dropped {
                continue;
            }
            if let Some(wake) = wake_for(entry, class, &state, &route, first, now_ms) {
                batch.push((route, wake));
            } else {
                tracing::info!(route_tag = %route.route_tag, "central wake expired before send; dropped");
            }
        }
        let mut changed = false;
        for chunk in batch.chunks(MAX_WAKES) {
            let request = HandoffRequest {
                v: ramflux_node_core::push_handoff::HANDOFF_VERSION,
                wakes: chunk.iter().map(|(_, wake)| wake.clone()).collect(),
            };
            match exchange_handoff(&self.handoff_socket, &request) {
                Ok(reply) => changed |= self.apply_reply(store, entry, chunk, &reply, now_ms)?,
                Err(error) => {
                    tracing::warn!(%error, "central handoff socket exchange failed");
                    self.back_off_transport(now_ms);
                    break;
                }
            }
        }
        Ok(changed)
    }

    fn backoff_until(&self) -> u64 {
        self.backoff.lock().map_or(0, |state| state.until_ms)
    }

    fn set_backoff(&self, until_ms: u64) {
        if let Ok(mut state) = self.backoff.lock() {
            state.until_ms = until_ms;
        }
    }

    fn back_off_transport(&self, now_ms: u64) {
        let Ok(mut state) = self.backoff.lock() else {
            return;
        };
        state.transport_failures = state.transport_failures.saturating_add(1);
        let exponent = state.transport_failures.saturating_sub(1).min(16);
        let delay = TRANSPORT_BACKOFF_FIRST_MS
            .saturating_mul(1_u64 << exponent)
            .min(TRANSPORT_BACKOFF_CAP_MS);
        state.until_ms = now_ms.saturating_add(with_jitter(delay, now_ms));
    }

    /// Settles the batch. Results are matched by position (A8.5).
    fn apply_reply(
        &self,
        store: &NotifyRedbStore,
        entry: &NotifyQueueEntry,
        chunk: &[(DevicePushRoute, HandoffWake)],
        reply: &HandoffReply,
        now_ms: u64,
    ) -> Result<bool, ramflux_node_core::NodeCoreError> {
        match reply.status {
            HandoffStatus::Ok => {
                // Results are matched by position and wake id (A8.5); otherwise a transport failure.
                let matched = reply.results.len() == chunk.len()
                    && chunk
                        .iter()
                        .zip(reply.results.iter())
                        .all(|((_, wake), result)| result.w == wake.w);
                if !matched {
                    tracing::warn!("central handoff reply does not match the batch; treated as transport failure");
                    self.back_off_transport(now_ms);
                    return Ok(false);
                }
                if let Ok(mut state) = self.backoff.lock() {
                    state.transport_failures = 0;
                }
            }
            HandoffStatus::Unavailable | HandoffStatus::Throttled => {
                let retry = reply
                    .retry_after_ms
                    .unwrap_or(RETRY_AFTER_DEFAULT_MS)
                    .clamp(RETRY_AFTER_MIN_MS, RETRY_AFTER_MAX_MS);
                self.set_backoff(now_ms.saturating_add(with_jitter(retry, now_ms)));
                tracing::warn!(status = ?reply.status, retry, "central handoff deferred by centre");
                return Ok(false);
            }
            HandoffStatus::Stopped => {
                self.set_backoff(now_ms.saturating_add(STOPPED_WAIT_MS));
                tracing::warn!("central handoff stopped: federation has no session");
                return Ok(false);
            }
            HandoffStatus::Rejected => {
                // The contract drops the batch: these wakes are never resent on these routes.
                for (route, _wake) in chunk {
                    let snapshot = CentralRouteSnapshot {
                        route_tag: &route.route_tag,
                        generation: route.route_generation,
                        sealed_token: &route.token,
                    };
                    store.central_drop_wake(
                        &route.device_delivery_id,
                        snapshot,
                        &entry.queue_id,
                        now_ms,
                    )?;
                }
                tracing::warn!(reason = ?reply.reason, "central handoff batch rejected; dropped");
                return Ok(true);
            }
        }
        let mut changed = false;
        for ((route, _wake), result) in chunk.iter().zip(reply.results.iter()) {
            let snapshot = CentralRouteSnapshot {
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

/// The wake for one route, or `None` when its deadline has passed (`ttl` 0, never sent).
/// `deadline = min(internal expiry, first send + cap[c])`, recomputed on every send (A1.2).
fn wake_for(
    entry: &NotifyQueueEntry,
    class: CentralClass,
    state: &PushCentralState,
    route: &DevicePushRoute,
    first_send_ms: u64,
    now_ms: u64,
) -> Option<HandoffWake> {
    let cap_s = match class {
        CentralClass::M => state.ttl_max_s.m,
        CentralClass::Call => state.ttl_max_s.call,
        CentralClass::X => state.ttl_max_s.x,
        CentralClass::T => state.ttl_max_s.t,
    };
    let internal_ms = entry.expires_at.saturating_mul(1000);
    let deadline = internal_ms.min(first_send_ms.saturating_add(cap_s.saturating_mul(1000)));
    let ttl = deadline.saturating_sub(now_ms) / 1000;
    (ttl > 0).then(|| HandoffWake {
        w: entry.wake.wake_id.clone(),
        c: class,
        ttl,
        rt: route.route_tag.clone(),
        st: route.token.clone(),
    })
}
