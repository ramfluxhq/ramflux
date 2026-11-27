// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-device push test on the notify mesh path `PUSH_ROUTE_TEST_PATH`.
//!
//! The gateway has already authorised the caller and signed a wake of class `t` for the caller's
//! own device; the request also names one of the caller's own route tags. This module resolves
//! that route, applies the rate limit (one accepted test per device per 30 seconds), then runs
//! the same admission, WAL and queue as an offline wake. The queued wake is bound to the one
//! route, so delivery never fans out and never uses a `VoIP` route.

use super::{
    AdmittedWake, NotifyIngressState, S13WakeRequest, handle_s13_wake_async_accept,
    handle_s13_wake_value,
};
use ramflux_node_core::{
    NodeCoreError, PushProviderKind, PushRouteTestAnswer, PushRouteTestMeshRequest,
    TEST_ROUTE_TAG_EXT_KEY,
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Minimum spacing between accepted test wakes for one device.
const TEST_INTERVAL: Duration = Duration::from_secs(30);
/// Most devices tracked at once; a full table refuses new tests as `unavailable`.
const MAX_TRACKED_DEVICES: usize = 65_536;

enum Slot {
    Reserved,
    RateLimited(u64),
    Full,
}

fn accepted_at() -> &'static Mutex<HashMap<String, Instant>> {
    static ACCEPTED: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    ACCEPTED.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Check and take the device's 30 s slot in one step under the table lock. Entries older than the
/// interval are pruned on every call.
fn reserve(device: &str, now: Instant) -> Slot {
    let Ok(mut map) = accepted_at().lock() else {
        return Slot::Full;
    };
    map.retain(|_, taken| now.saturating_duration_since(*taken) < TEST_INTERVAL);
    if let Some(taken) = map.get(device) {
        let remaining = TEST_INTERVAL.saturating_sub(now.saturating_duration_since(*taken));
        let ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
        return Slot::RateLimited(ms.max(1));
    }
    if map.len() >= MAX_TRACKED_DEVICES {
        return Slot::Full;
    }
    map.insert(device.to_owned(), now);
    Slot::Reserved
}

fn release(device: &str) {
    if let Ok(mut map) = accepted_at().lock() {
        map.remove(device);
    }
}

/// Admit one push test wake and answer `queued` or `refused`.
///
/// # Errors
/// Returns storage or admission errors; refusals are answers, not errors.
pub(crate) fn handle(
    ingress: &NotifyIngressState,
    request: PushRouteTestMeshRequest,
) -> Result<PushRouteTestAnswer, NodeCoreError> {
    let device = request.device_delivery_id.clone();
    let Some(provider) = ingress.store.push_test_route_provider(&device, &request.route_tag)?
    else {
        return Ok(PushRouteTestAnswer::refused("rejected", None));
    };
    // PushKit has no test payload and Web Push refuses every class but `m`.
    if matches!(provider, PushProviderKind::ApnsVoip | PushProviderKind::WebPush) {
        return Ok(PushRouteTestAnswer::refused("unsupported_class", None));
    }
    if let Some(central) = super::central_handoff::active()
        && !central.test_class_ready(&provider)?
    {
        return Ok(PushRouteTestAnswer::refused("unavailable", None));
    }
    match reserve(&device, Instant::now()) {
        Slot::Reserved => {}
        Slot::RateLimited(ms) => {
            return Ok(PushRouteTestAnswer::refused("rate_limited", Some(ms)));
        }
        Slot::Full => return Ok(PushRouteTestAnswer::refused("unavailable", None)),
    }
    let answer = admit(ingress, request);
    if !matches!(&answer, Ok(answer) if answer.status == "queued") {
        release(&device);
    }
    answer
}

fn admit(
    ingress: &NotifyIngressState,
    request: PushRouteTestMeshRequest,
) -> Result<PushRouteTestAnswer, NodeCoreError> {
    let mut wake_request = S13WakeRequest {
        device_delivery_id: request.device_delivery_id,
        signed_wake: request.signed_wake,
        queued_at: None,
        dnd_active: None,
        admission: AdmittedWake::default(),
    };
    wake_request.admit(&ingress.wake_auth, &ingress.store)?;
    let AdmittedWake::Push(wake) = &mut wake_request.admission else {
        return Ok(PushRouteTestAnswer::refused("unavailable", None));
    };
    wake.ext.ext.insert(TEST_ROUTE_TAG_EXT_KEY.to_owned(), serde_json::json!(request.route_tag));
    let response = if ingress.async_accept {
        handle_s13_wake_async_accept(&ingress.store, &wake_request)?
    } else {
        handle_s13_wake_value(&ingress.store, &ingress.store_gate, &ingress.runtime, &wake_request)?
    };
    if response.entry.queue_id.is_empty() {
        return Ok(PushRouteTestAnswer::refused("unavailable", None));
    }
    Ok(PushRouteTestAnswer::queued())
}
