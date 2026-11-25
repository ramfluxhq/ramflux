// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-device push test on the notify mesh path `PUSH_ROUTE_TEST_PATH`.
//!
//! The gateway has already authorised the caller and signed a wake of class `t` for the caller's
//! own device. This module applies the rate limit (one accepted test per device per 30 seconds),
//! then runs the same admission, WAL and queue as an offline wake. Routes are chosen by the
//! normal selection, which never uses a VoIP route for a test wake.

use super::{
    S13WakeRequest, handle_s13_wake_async_accept, handle_s13_wake_value, NotifyIngressState,
};
use ramflux_node_core::{NodeCoreError, PushRouteTestAnswer};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Minimum spacing between accepted test wakes for one device.
const TEST_INTERVAL: Duration = Duration::from_secs(30);

fn accepted_at() -> &'static Mutex<HashMap<String, Instant>> {
    static ACCEPTED: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    ACCEPTED.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Milliseconds until the device may run another test, or `None` when it may.
fn retry_after_ms(device: &str, now: Instant) -> Option<u64> {
    let map = accepted_at().lock().ok()?;
    let last = *map.get(device)?;
    let elapsed = now.saturating_duration_since(last);
    (elapsed < TEST_INTERVAL)
        .then(|| u64::try_from((TEST_INTERVAL - elapsed).as_millis()).unwrap_or(u64::MAX))
}

fn record_accepted(device: &str, now: Instant) {
    if let Ok(mut map) = accepted_at().lock() {
        map.insert(device.to_owned(), now);
    }
}

/// Admit one push test wake and answer `queued` or `refused`.
///
/// # Errors
/// Returns storage or admission errors; configuration refusals are answers, not errors.
pub(crate) fn handle(
    ingress: &NotifyIngressState,
    mut request: S13WakeRequest,
) -> Result<PushRouteTestAnswer, NodeCoreError> {
    let device = request.device_delivery_id.clone();
    let now = Instant::now();
    if let Some(retry) = retry_after_ms(&device, now) {
        return Ok(PushRouteTestAnswer::refused("rate_limited", Some(retry)));
    }
    request.admit(&ingress.wake_auth, &ingress.store)?;
    if request.queued_provider_wake()?.is_none() {
        return Ok(PushRouteTestAnswer::refused("unavailable", None));
    }
    let response = if ingress.async_accept {
        handle_s13_wake_async_accept(&ingress.store, &request)?
    } else {
        handle_s13_wake_value(&ingress.store, &ingress.store_gate, &ingress.runtime, &request)?
    };
    if response.entry.queue_id.is_empty() {
        return Ok(PushRouteTestAnswer::refused("unavailable", None));
    }
    record_accepted(&device, now);
    Ok(PushRouteTestAnswer::queued())
}
