// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Decode a mesh envelope submission. A federation peer that sends a body which
//! is not an envelope receives a permanent typed refusal. Gateway decode stays an error.

use std::time::Instant;

enum Opened {
    Envelope(ramflux_protocol::Envelope),
    Refused(ramflux_node_core::EnvelopeSubmitResponse),
    Failed(anyhow::Error),
}

fn open_submitted(body: &[u8], origin: ramflux_node_core::RouterEnvelopeOrigin) -> Opened {
    match ramflux_protocol::decode_signed_envelope_ijson(body) {
        Ok(envelope) => Opened::Envelope(envelope),
        Err(_) if origin == ramflux_node_core::RouterEnvelopeOrigin::Federation => {
            Opened::Refused(malformed_delivery(body))
        }
        Err(error) => Opened::Failed(error.into()),
    }
}

fn malformed_delivery(body: &[u8]) -> ramflux_node_core::EnvelopeSubmitResponse {
    ramflux_node_core::EnvelopeSubmitResponse {
        migration_refusal: None,
        outcome: "rejected_malformed".to_owned(),
        target_delivery_id: malformed_target(body),
        inbox_seq: None,
        cursor: None,
        nack: None,
    }
}

fn malformed_target(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return String::new();
    };
    let Some(id) = value.get("target_delivery_id").and_then(serde_json::Value::as_str) else {
        return String::new();
    };
    if id.is_empty() || id.len() > 256 { String::new() } else { id.to_owned() }
}

fn mesh_refusal(
    delivery: ramflux_node_core::EnvelopeSubmitResponse,
) -> ramflux_node_core::SessionPushSubmitResponse {
    ramflux_node_core::SessionPushSubmitResponse {
        delivery,
        incarnation_id: None,
        retain_until: None,
    }
}

pub(crate) fn handle_mvp0_envelope_mesh_from(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
    let started = Instant::now();
    let envelope = match open_submitted(body, origin) {
        Opened::Envelope(envelope) => envelope,
        Opened::Refused(delivery) => return Ok(mesh_refusal(delivery)),
        Opened::Failed(error) => return Err(error),
    };
    if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security_mesh(&envelope));
    }
    router.submit_envelope_mesh_from(envelope, started, origin)
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_mvp0_envelope_from(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    let total_started = Instant::now();
    let decode_started = Instant::now();
    let envelope = match open_submitted(body, origin) {
        Opened::Envelope(envelope) => envelope,
        Opened::Refused(delivery) => return Ok(delivery),
        Opened::Failed(error) => return Err(error),
    };
    if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security(&envelope));
    }
    ramflux_node_core::record_router_submit_decode_us(elapsed_us(decode_started));
    router.submit_envelope_from(envelope, total_started, origin)
}

pub(crate) async fn handle_mvp0_envelope_async_from(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
    let total_started = Instant::now();
    let decode_started = Instant::now();
    let envelope = match open_submitted(body, origin) {
        Opened::Envelope(envelope) => envelope,
        Opened::Refused(delivery) => return Ok(mesh_refusal(delivery)),
        Opened::Failed(error) => return Err(error),
    };
    if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security_mesh(&envelope));
    }
    ramflux_node_core::record_router_submit_decode_us(elapsed_us(decode_started));
    router.submit_envelope_mesh_async_from(envelope, total_started, origin).await
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}
