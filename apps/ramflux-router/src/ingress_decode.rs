// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Decode a mesh envelope submission. A federation peer that sends a body which
//! is not an envelope receives a permanent typed refusal. Gateway decode stays an error.

use std::time::Instant;

struct Submitted {
    envelope: ramflux_protocol::Envelope,
    verified_source_node_id: Option<String>,
}

enum Opened {
    Envelope(Submitted),
    Refused(ramflux_node_core::EnvelopeSubmitResponse),
    Failed(anyhow::Error),
}

fn open_submitted(body: &[u8], origin: ramflux_node_core::RouterEnvelopeOrigin) -> Opened {
    if origin == ramflux_node_core::RouterEnvelopeOrigin::Federation
        && let Some(opened) = open_verified_source(body)
    {
        return opened;
    }
    match ramflux_protocol::decode_signed_envelope_ijson(body) {
        Ok(envelope) => Opened::Envelope(Submitted { envelope, verified_source_node_id: None }),
        Err(_) if origin == ramflux_node_core::RouterEnvelopeOrigin::Federation => {
            Opened::Refused(malformed_delivery(body))
        }
        Err(error) => Opened::Failed(error.into()),
    }
}

/// Federation-only wrapper. The peer id is authenticated mesh context, not an envelope field.
/// Absent keys fall through so a raw envelope still decodes. A present peer without an
/// envelope, or a reserved peer, is a permanent malformed refusal.
fn open_verified_source(body: &[u8]) -> Option<Opened> {
    let value = ramflux_protocol::parse_i_json::<serde_json::Value>(body).ok()?;
    let object = value.as_object()?;
    if !object.contains_key("verified_source_node_id") {
        return None;
    }
    let peer = object.get("verified_source_node_id").and_then(serde_json::Value::as_str);
    let Some(peer) = peer.filter(|peer| valid_verified_peer(peer)) else {
        return Some(Opened::Refused(malformed_delivery(body)));
    };
    let Some(envelope) = object.get("envelope") else {
        return Some(Opened::Refused(malformed_delivery(body)));
    };
    match serde_json::from_value(envelope.clone()) {
        Ok(envelope) => Some(Opened::Envelope(Submitted {
            envelope,
            verified_source_node_id: Some(peer.to_owned()),
        })),
        Err(_) => Some(Opened::Refused(malformed_delivery(body))),
    }
}

fn valid_verified_peer(peer: &str) -> bool {
    !peer.is_empty() && peer.len() <= 256 && peer != "unspecified" && peer != "legacy"
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
    bounded_target(value.get("target_delivery_id")).unwrap_or_else(|| {
        value
            .get("envelope")
            .and_then(|envelope| bounded_target(envelope.get("target_delivery_id")))
            .unwrap_or_default()
    })
}

fn bounded_target(value: Option<&serde_json::Value>) -> Option<String> {
    let id = value.and_then(serde_json::Value::as_str)?;
    if id.is_empty() || id.len() > 256 { None } else { Some(id.to_owned()) }
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
    let submitted = match open_submitted(body, origin) {
        Opened::Envelope(submitted) => submitted,
        Opened::Refused(delivery) => return Ok(mesh_refusal(delivery)),
        Opened::Failed(error) => return Err(error),
    };
    if ramflux_protocol::ephemeral::require_durable(&submitted.envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security_mesh(&submitted.envelope));
    }
    let Submitted { envelope, verified_source_node_id } = submitted;
    match verified_source_node_id {
        Some(peer) => {
            router.submit_envelope_mesh_from_source(envelope, started, origin, Some(&peer))
        }
        None => router.submit_envelope_mesh_from(envelope, started, origin),
    }
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_mvp0_envelope_from(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    let total_started = Instant::now();
    let decode_started = Instant::now();
    let submitted = match open_submitted(body, origin) {
        Opened::Envelope(submitted) => submitted,
        Opened::Refused(delivery) => return Ok(delivery),
        Opened::Failed(error) => return Err(error),
    };
    if ramflux_protocol::ephemeral::require_durable(&submitted.envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security(&submitted.envelope));
    }
    ramflux_node_core::record_router_submit_decode_us(elapsed_us(decode_started));
    let Submitted { envelope, verified_source_node_id } = submitted;
    match verified_source_node_id {
        Some(peer) => {
            router.submit_envelope_from_source(envelope, total_started, origin, Some(&peer))
        }
        None => router.submit_envelope_from(envelope, total_started, origin),
    }
}

pub(crate) async fn handle_mvp0_envelope_async_from(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
    let total_started = Instant::now();
    let decode_started = Instant::now();
    let submitted = match open_submitted(body, origin) {
        Opened::Envelope(submitted) => submitted,
        Opened::Refused(delivery) => return Ok(mesh_refusal(delivery)),
        Opened::Failed(error) => return Err(error),
    };
    if ramflux_protocol::ephemeral::require_durable(&submitted.envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security_mesh(&submitted.envelope));
    }
    ramflux_node_core::record_router_submit_decode_us(elapsed_us(decode_started));
    let Submitted { envelope, verified_source_node_id } = submitted;
    match verified_source_node_id {
        Some(peer) => {
            router
                .submit_envelope_mesh_async_from_source(envelope, total_started, origin, Some(peer))
                .await
        }
        None => router.submit_envelope_mesh_async_from(envelope, total_started, origin).await,
    }
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}
