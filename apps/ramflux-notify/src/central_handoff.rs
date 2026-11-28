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
    CentralRouteSnapshot, DevicePushRoute, FirstSendState, NodeCoreError, NodePushConfig,
    NotifyQueueEntry, NotifyRedbStore, PolicyGate, PushProviderKind,
};
use ramflux_protocol::NotificationDeliveryClass;

/// Hold time after an `unserved` answer (A6.4 and section 5, N11).
const UNSERVED_PAUSE_MS: u64 = 3_600_000;
/// Socket error back-off: 2 s, doubling, capped at 300 s (plan section 5).
const TRANSPORT_BACKOFF_FIRST_MS: u64 = 2_000;
const TRANSPORT_BACKOFF_CAP_MS: u64 = 300_000;
/// Default and bounds of a batch-level `retry_after_ms` (plan section 9.4).
const RETRY_AFTER_DEFAULT_MS: u64 = 2_000;
const RETRY_AFTER_MIN_MS: u64 = 1_000;
const RETRY_AFTER_MAX_MS: u64 = 3_600_000;
/// Fixed re-check while no state file exists yet, and after a busy local store (H3, M2).
const HOLD_RECHECK_MS: u64 = 2_000;
const BUSY_RECHECK_MS: u64 = 1_000;
/// Hard caps of the TTL classes (N4 and section 1.1). The state file is clamped to these (M3).
const CAP_M_S: u64 = 3_600;
const CAP_CALL_S: u64 = 30;
const CAP_X_S: u64 = 3_600;
const CAP_T_S: u64 = 300;

static CENTRAL: OnceLock<CentralPush> = OnceLock::new();

/// Installs the central delivery path when `[push_central]` is configured. Absent means direct.
///
/// # Errors
/// Returns an error when the section was configured twice.
pub(crate) fn configure(config: Option<NodePushConfig>) -> Result<(), NodeCoreError> {
    let Some(config) = config else {
        return Ok(());
    };
    CENTRAL
        .set(CentralPush {
            state_file: config.state_file,
            handoff_socket: config.handoff_socket,
            backoff: Mutex::new(Backoff::default()),
        })
        .map_err(|_| NodeCoreError::InvalidConfiguration("push_central configured twice".into()))
}

/// The installed central path, when the node runs in central mode.
pub(crate) fn active() -> Option<&'static CentralPush> {
    CENTRAL.get()
}

/// What the delivery loop does with an entry after a central pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CentralDue {
    /// Routes changed; look at the entry again at once.
    Changed,
    /// Try again at this Unix second (never a spin: the loop clamps to at least one second).
    Retry(u64),
    /// Every candidate route is settled, or there is nothing to send.
    Idle,
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

/// Outcome of one handoff reply, applied to the routes of a batch.
#[derive(Default)]
struct Applied {
    /// Routes of the batch that are not settled by this reply.
    unsettled: usize,
    /// A route changed (invalidated, resealed or paused).
    changed: bool,
    /// At least one route accepted the wake.
    accepted: bool,
    /// The centre asked for a retry at this Unix second.
    retry: Option<u64>,
}

/// Maps a protocol delivery class to the central class. Classes outside the batch (for
/// example conference and AI wakes) are not sent centrally in this revision.
fn central_class(class: &NotificationDeliveryClass) -> Option<CentralClass> {
    match class {
        NotificationDeliveryClass::UserContentNotification => Some(CentralClass::M),
        NotificationDeliveryClass::CallWakeNotification => Some(CentralClass::Call),
        NotificationDeliveryClass::PushTestNotification => Some(CentralClass::T),
        _ => None,
    }
}

fn now_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

/// Milliseconds rounded up to whole Unix seconds.
fn ceil_secs(ms: u64) -> u64 {
    ms.div_ceil(1000)
}

/// Spreads a delay by -20 %..+20 % (plan section 5). Uses the clock's low bits as entropy.
fn with_jitter(delay_ms: u64, now_ms: u64) -> u64 {
    let percent = 80 + now_ms % 41;
    delay_ms.saturating_mul(percent) / 100
}

fn snapshot(route: &DevicePushRoute) -> CentralRouteSnapshot<'_> {
    CentralRouteSnapshot {
        route_tag: &route.route_tag,
        generation: route.route_generation,
        sealed_token: &route.token,
    }
}

fn is_busy(error: &NodeCoreError) -> bool {
    matches!(
        error,
        NodeCoreError::SendAuthority(ramflux_node_core::send_authority::SendAuthorityError::Busy)
    )
}

impl CentralPush {
    /// Whether `provider` is served by the centre (`dir.served`, A6.4). `None` means no state
    /// file yet: the registration is accepted and the wakes are held.
    ///
    /// # Errors
    /// Returns an error when the state file exists but cannot be read.
    pub(crate) fn served_for(
        &self,
        provider: &PushProviderKind,
    ) -> Result<Option<bool>, NodeCoreError> {
        let Some(state) = read_push_central_state(&self.state_file)? else {
            return Ok(None);
        };
        Ok(Some(match provider {
            PushProviderKind::Apns => state.served.apns,
            PushProviderKind::ApnsVoip => state.served.apns_voip,
            PushProviderKind::Fcm => state.served.fcm,
            PushProviderKind::WebPush => false,
        }))
    }

    /// Whether the centre advertises class `t` and serves `provider` (push test admission).
    /// `false` also covers a missing state file: nothing may be admitted then.
    ///
    /// # Errors
    /// Returns an error when the state file exists but cannot be read.
    pub(crate) fn test_class_ready(
        &self,
        provider: &PushProviderKind,
    ) -> Result<bool, NodeCoreError> {
        let Some(state) = read_push_central_state(&self.state_file)? else {
            return Ok(false);
        };
        let served = match provider {
            PushProviderKind::Apns => state.served.apns,
            PushProviderKind::ApnsVoip => state.served.apns_voip,
            PushProviderKind::Fcm => state.served.fcm,
            PushProviderKind::WebPush => false,
        };
        Ok(served && state.classes.contains(&CentralClass::T))
    }

    /// Delivers one wake through the centre and says when to look again.
    ///
    /// # Errors
    /// Returns storage errors that are not a busy local store (busy is a retry).
    pub(crate) fn deliver(
        &self,
        store: &NotifyRedbStore,
        entry: &NotifyQueueEntry,
    ) -> Result<CentralDue, NodeCoreError> {
        let now_ms = now_unix_millis();
        let now_seconds = now_ms / 1000;
        let backoff_until = self.backoff_until();
        if backoff_until > now_ms {
            return Ok(CentralDue::Retry(ceil_secs(backoff_until)));
        }
        let Some(class) = central_class(&entry.wake.delivery_class) else {
            // Not sent centrally in this revision: settle it so it leaves the pending set (L7).
            store.central_settle_unsupported(entry)?;
            return Ok(CentralDue::Idle);
        };
        // Policy (CENTRAL P2b K11/K12): a held wake waits for its hold to end; a muted or read
        // wake is withheld. Calls are never held (the store decides).
        match store.policy_gate(entry)? {
            PolicyGate::Send => {}
            PolicyGate::Held { not_before_ms } => {
                let at = ceil_secs(not_before_ms).min(entry.expires_at);
                return Ok(if at > now_seconds { CentralDue::Retry(at) } else { CentralDue::Idle });
            }
            PolicyGate::Withheld => return Ok(CentralDue::Idle),
        }
        // No state file yet: no session has reported `dir.served`, so nothing is submitted (A6.4).
        // Re-check on a fixed interval instead of waiting for another pulse (H3).
        let Some(state) = read_push_central_state(&self.state_file)? else {
            tracing::debug!("central push state not yet written; holding wake");
            return Ok(CentralDue::Retry(now_seconds + HOLD_RECHECK_MS.div_ceil(1000)));
        };
        match self.deliver_routes(store, entry, class, &state, now_ms) {
            Ok(due) => Ok(due),
            Err(error) if is_busy(&error) => {
                // The local writer is held elsewhere: retry shortly, never spin (M2).
                Ok(CentralDue::Retry(now_seconds + BUSY_RECHECK_MS.div_ceil(1000)))
            }
            Err(error) => Err(error),
        }
    }

    fn deliver_routes(
        &self,
        store: &NotifyRedbStore,
        entry: &NotifyQueueEntry,
        class: CentralClass,
        state: &PushCentralState,
        now_ms: u64,
    ) -> Result<CentralDue, NodeCoreError> {
        let mut routes = store.central_candidate_routes(
            &entry.device_delivery_id,
            class,
            state.served,
            now_ms,
        )?;
        // A push test is bound to exactly one of the caller's routes (never a fan-out).
        if let Some(tag) = ramflux_node_core::test_target_route_tag(&entry.wake) {
            routes.retain(|route| route.route_tag == tag);
        }
        let Some(provider) = routes.first().map(|route| route.provider.clone()) else {
            // Every route is paused: wake up when the earliest pause ends, never after the entry's
            // own expiry (plan section 5, unserved).
            let Some(until_ms) =
                store.central_next_pause_expiry(&entry.device_delivery_id, now_ms)?
            else {
                return Ok(CentralDue::Idle);
            };
            let at = ceil_secs(until_ms).min(entry.expires_at);
            return Ok(if at > now_ms / 1000 { CentralDue::Retry(at) } else { CentralDue::Idle });
        };
        let mut batch = Vec::new();
        let mut unsettled = 0_usize;
        for route in routes {
            let state_now = store.central_first_send(
                &route.device_delivery_id,
                snapshot(&route),
                &entry.queue_id,
                now_ms,
                entry.expires_at,
            )?;
            match state_now {
                Some(FirstSendState::Open { first_send_ms }) => {
                    match wake_for(entry, class, state, &route, first_send_ms, now_ms) {
                        Some(wake) => batch.push((route, wake)),
                        None => {
                            // ttl 0: the deadline has passed. Settle, never send (H4).
                            store.central_settle(
                                &route.device_delivery_id,
                                snapshot(&route),
                                &entry.queue_id,
                            )?;
                        }
                    }
                }
                // Already settled for this route, or no room for another record (M1): settled.
                Some(FirstSendState::Settled | FirstSendState::Full) | None => {}
            }
        }
        let mut accepted = false;
        let mut changed = false;
        let mut retry: Option<u64> = None;
        for chunk in batch.chunks(MAX_WAKES) {
            let request = HandoffRequest {
                v: ramflux_node_core::push_handoff::HANDOFF_VERSION,
                wakes: chunk.iter().map(|(_, wake)| wake.clone()).collect(),
            };
            match exchange_handoff(&self.handoff_socket, &request) {
                Ok(reply) => {
                    let applied = self.apply_reply(store, entry, chunk, &reply, now_ms)?;
                    unsettled += applied.unsettled;
                    changed |= applied.changed;
                    accepted |= applied.accepted;
                    retry = retry.or(applied.retry);
                }
                Err(error) => {
                    tracing::warn!(%error, "central handoff socket exchange failed");
                    self.back_off_transport(now_ms);
                    unsettled += chunk.len();
                    retry = Some(ceil_secs(self.backoff_until()));
                }
            }
        }
        if changed {
            return Ok(CentralDue::Changed);
        }
        if unsettled == 0 {
            // Every candidate route is settled: the entry leaves the pending set (H2, A8.6).
            store.central_record_entry_settled(entry, provider, accepted)?;
            return Ok(CentralDue::Idle);
        }
        Ok(CentralDue::Retry(retry.unwrap_or(now_ms / 1000 + HOLD_RECHECK_MS.div_ceil(1000))))
    }

    /// Sends the pending node-originated clears (wire class `x`). A clear is a node row, never a
    /// message wake: its wake id is generated here and it carries no sender or message signature;
    /// the federation session signs the request with the node identity, as for every frame.
    pub(crate) fn deliver_clears(
        &self,
        store: &NotifyRedbStore,
        now_ms: u64,
    ) -> Result<CentralDue, NodeCoreError> {
        let devices = store.pending_policy_clears(now_ms)?;
        if devices.is_empty() {
            return Ok(CentralDue::Idle);
        }
        if now_ms < self.backoff_until() {
            return Ok(CentralDue::Retry(ceil_secs(self.backoff_until())));
        }
        let Some(state) = read_push_central_state(&self.state_file)? else {
            return Ok(CentralDue::Idle);
        };
        let ttl = state.ttl_max_s.x.min(CAP_X_S);
        let mut batch: Vec<(String, HandoffWake)> = Vec::new();
        for device in &devices {
            let routes =
                store.central_candidate_routes(device, CentralClass::X, state.served, now_ms)?;
            for route in routes {
                let w = format!("clear-{now_ms}-{}", batch.len());
                batch.push((
                    device.clone(),
                    HandoffWake {
                        w,
                        c: CentralClass::X,
                        ttl,
                        rt: route.route_tag.clone(),
                        st: route.token.clone(),
                    },
                ));
            }
        }
        // A device with no candidate route has nothing to receive; its row is settled.
        for device in &devices {
            if !batch.iter().any(|(owner, _)| owner == device) {
                store.ack_policy_clear(device)?;
            }
        }
        let mut retry: Option<u64> = None;
        for chunk in batch.chunks(MAX_WAKES) {
            let request = HandoffRequest {
                v: ramflux_node_core::push_handoff::HANDOFF_VERSION,
                wakes: chunk.iter().map(|(_, wake)| wake.clone()).collect(),
            };
            let reply = match exchange_handoff(&self.handoff_socket, &request) {
                Ok(reply) => reply,
                Err(error) => {
                    tracing::warn!(%error, "central clear exchange failed");
                    self.back_off_transport(now_ms);
                    retry = Some(ceil_secs(self.backoff_until()));
                    continue;
                }
            };
            match reply.status {
                HandoffStatus::Ok => {
                    let matched = reply.results.len() == chunk.len()
                        && chunk
                            .iter()
                            .zip(reply.results.iter())
                            .all(|((_, wake), result)| result.w == wake.w);
                    if !matched {
                        tracing::warn!("central clear reply does not match the batch");
                        self.back_off_transport(now_ms);
                        retry = Some(ceil_secs(self.backoff_until()));
                        continue;
                    }
                    if let Ok(mut backoff) = self.backoff.lock() {
                        backoff.transport_failures = 0;
                    }
                    for (device, _) in chunk {
                        store.ack_policy_clear(device)?;
                    }
                    tracing::info!(
                        target: "ramflux_notify_policy",
                        event = "policy.clear_sent",
                        count = chunk.len(),
                        "node clear wakes handed to the centre"
                    );
                }
                HandoffStatus::Rejected => {
                    tracing::warn!(reason = ?reply.reason, "central clear batch rejected; dropped");
                    for (device, _) in chunk {
                        store.ack_policy_clear(device)?;
                    }
                }
                HandoffStatus::Unavailable | HandoffStatus::Throttled => {
                    let retry_ms = reply
                        .retry_after_ms
                        .unwrap_or(RETRY_AFTER_DEFAULT_MS)
                        .clamp(RETRY_AFTER_MIN_MS, RETRY_AFTER_MAX_MS);
                    let until = now_ms.saturating_add(with_jitter(retry_ms, now_ms));
                    self.set_backoff(until);
                    retry = Some(ceil_secs(until));
                }
                HandoffStatus::Stopped => {
                    self.back_off_transport(now_ms);
                    retry = Some(ceil_secs(self.backoff_until()));
                }
            }
        }
        Ok(retry.map_or(CentralDue::Idle, CentralDue::Retry))
    }

    fn backoff_until(&self) -> u64 {
        self.backoff.lock().map_or(0, |state| state.until_ms)
    }

    /// Extends the back-off. Never shortens one set by another worker (L8).
    fn set_backoff(&self, until_ms: u64) {
        if let Ok(mut state) = self.backoff.lock() {
            state.until_ms = state.until_ms.max(until_ms);
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

    /// Applies one reply to the routes of its batch. Results are matched by position and wake id
    /// (A8.5). Every result is applied even when one store write fails; the first error is
    /// returned after the loop (M2).
    fn apply_reply(
        &self,
        store: &NotifyRedbStore,
        entry: &NotifyQueueEntry,
        chunk: &[(DevicePushRoute, HandoffWake)],
        reply: &HandoffReply,
        now_ms: u64,
    ) -> Result<Applied, NodeCoreError> {
        let mut applied = Applied::default();
        match reply.status {
            HandoffStatus::Ok => {
                // An `invalid_route` without `at` is a bad reply (L1), never a settled route.
                let matched = reply.results.len() == chunk.len()
                    && chunk
                        .iter()
                        .zip(reply.results.iter())
                        .all(|((_, wake), result)| result.w == wake.w)
                    && reply
                        .results
                        .iter()
                        .all(|result| result.r != WakeOutcome::InvalidRoute || result.at.is_some());
                if !matched {
                    tracing::warn!(
                        "central handoff reply does not match the batch; treated as transport failure"
                    );
                    self.back_off_transport(now_ms);
                    applied.unsettled = chunk.len();
                    applied.retry = Some(ceil_secs(self.backoff_until()));
                    return Ok(applied);
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
                let until = now_ms.saturating_add(with_jitter(retry, now_ms));
                self.set_backoff(until);
                tracing::warn!(status = ?reply.status, retry, "central handoff deferred by centre");
                applied.unsettled = chunk.len();
                applied.retry = Some(ceil_secs(until));
                return Ok(applied);
            }
            HandoffStatus::Stopped => {
                // Same back-off as a socket failure: 2 s doubling, capped (L2).
                self.back_off_transport(now_ms);
                tracing::warn!("central handoff stopped: federation has no session");
                applied.unsettled = chunk.len();
                applied.retry = Some(ceil_secs(self.backoff_until()));
                return Ok(applied);
            }
            HandoffStatus::Rejected => {
                // The contract drops the batch: these wakes are never resent on these routes.
                tracing::warn!(reason = ?reply.reason, "central handoff batch rejected; dropped");
                for (route, _wake) in chunk {
                    store.central_settle(
                        &route.device_delivery_id,
                        snapshot(route),
                        &entry.queue_id,
                    )?;
                }
                return Ok(applied);
            }
        }
        let mut first_error: Option<NodeCoreError> = None;
        for ((route, _wake), result) in chunk.iter().zip(reply.results.iter()) {
            let settled = settle_result(store, entry, route, result.r, result.at, now_ms);
            match settled {
                Ok(outcome) => {
                    applied.changed |= outcome.changed;
                    applied.accepted |= outcome.accepted;
                }
                Err(error) => {
                    applied.unsettled += 1;
                    first_error.get_or_insert(error);
                }
            }
            if result.r == WakeOutcome::Refused {
                tracing::info!(reason = ?result.why, "central wake refused for one route");
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(applied),
        }
    }
}

/// What one result changed.
#[derive(Default)]
struct SettleOutcome {
    changed: bool,
    accepted: bool,
}

/// Applies one per-route result and settles the queue entry on that route (H2). Every outcome
/// settles: accepted and duplicate are queued at the centre; invalid, reseal and unserved change
/// the route and the wake is not resent to it; refused is dropped for this route.
fn settle_result(
    store: &NotifyRedbStore,
    entry: &NotifyQueueEntry,
    route: &DevicePushRoute,
    outcome: WakeOutcome,
    at: Option<u64>,
    now_ms: u64,
) -> Result<SettleOutcome, NodeCoreError> {
    let mut result = SettleOutcome::default();
    match outcome {
        WakeOutcome::Accepted | WakeOutcome::Duplicate => {
            result.accepted = true;
        }
        WakeOutcome::InvalidRoute => {
            if let Some(at) = at {
                result.changed |= store.central_route_invalidate(
                    &route.device_delivery_id,
                    snapshot(route),
                    at,
                )?;
            }
        }
        WakeOutcome::Reseal => {
            result.changed |=
                store.central_route_mark_reseal(&route.device_delivery_id, snapshot(route))?;
        }
        WakeOutcome::Unserved => {
            result.changed |= store.central_route_pause(
                &route.device_delivery_id,
                snapshot(route),
                now_ms.saturating_add(UNSERVED_PAUSE_MS),
            )?;
        }
        WakeOutcome::Refused => {}
    }
    store.central_settle(&route.device_delivery_id, snapshot(route), &entry.queue_id)?;
    Ok(result)
}

/// The wake for one route, or `None` when its deadline has passed (`ttl` 0, never sent).
/// `deadline = min(internal expiry, first send + cap[c])`, recomputed on every send (A1.2). The
/// caps are clamped to the contract values, so a state file cannot widen them (M3).
fn wake_for(
    entry: &NotifyQueueEntry,
    class: CentralClass,
    state: &PushCentralState,
    route: &DevicePushRoute,
    first_send_ms: u64,
    now_ms: u64,
) -> Option<HandoffWake> {
    let cap_s = match class {
        CentralClass::M => state.ttl_max_s.m.min(CAP_M_S),
        CentralClass::Call => state.ttl_max_s.call.min(CAP_CALL_S),
        CentralClass::X => state.ttl_max_s.x.min(CAP_X_S),
        CentralClass::T => state.ttl_max_s.t.min(CAP_T_S),
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
