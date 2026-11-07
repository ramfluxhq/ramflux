// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-node ephemeral forward and C4 §6.3 mapping. Never wakes.

use crate::GatewaySessionHub;
use ramflux_node_core::{SessionPushForwardOutcome, SessionPushForwardResponse};
use ramflux_protocol::Envelope;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Mesh path for same-node cross-gateway ephemeral delivery.
pub(crate) const PATH: &str = "/mvp0/gateway-forward-ephemeral";

static WAKE_COUNT: AtomicU64 = AtomicU64::new(0);

/// C4 enqueue result before §6.3 mesh mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub(crate) enum EphemeralEnqueueOutcome {
    Queued,
    QueueFull,
    RecipientUnsupported,
    Offline,
}

impl std::fmt::Display for EphemeralEnqueueOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Queued => "queued",
            Self::QueueFull => "queue_full",
            Self::RecipientUnsupported => "recipient_unsupported",
            Self::Offline => "offline",
        })
    }
}

/// Body of `POST /mvp0/gateway-forward-ephemeral`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct GatewayForwardEphemeralRequest {
    pub(crate) source_gateway_id: String,
    pub(crate) target_delivery_id: String,
    pub(crate) forwarded: bool,
    pub(crate) envelope: Envelope,
    pub(crate) expires_at_ms: u64,
}

/// Map a C4 result to the mesh reply. Ephemeral `full` / `unsupported` /
/// `expired` / `no_session` are `delivered=false` and never originate a wake.
#[must_use]
pub(crate) fn map_forward(outcome: EphemeralEnqueueOutcome) -> SessionPushForwardResponse {
    match outcome {
        EphemeralEnqueueOutcome::Queued => SessionPushForwardResponse {
            delivered: true,
            outcome: Some(SessionPushForwardOutcome::Queued),
        },
        EphemeralEnqueueOutcome::QueueFull => SessionPushForwardResponse {
            delivered: false,
            outcome: Some(SessionPushForwardOutcome::Full),
        },
        EphemeralEnqueueOutcome::RecipientUnsupported => SessionPushForwardResponse {
            delivered: false,
            outcome: Some(SessionPushForwardOutcome::Unsupported),
        },
        EphemeralEnqueueOutcome::Offline => SessionPushForwardResponse {
            delivered: false,
            outcome: Some(SessionPushForwardOutcome::NoSession),
        },
    }
}

/// Record that this ephemeral path did not wake. Durable `no_session` wakes live
/// on the durable forward; passing `ephemeral = false` here would count a wake.
pub(crate) fn finish_without_wake(outcome: EphemeralEnqueueOutcome) -> EphemeralEnqueueOutcome {
    maybe_wake(true);
    outcome
}

fn maybe_wake(ephemeral: bool) {
    if !ephemeral {
        WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) fn wake_count() -> u64 {
    WAKE_COUNT.load(Ordering::SeqCst)
}

#[cfg(test)]
pub(crate) fn reset_wake_count() {
    WAKE_COUNT.store(0, Ordering::SeqCst);
}

/// Admit a same-node ephemeral forward and run C4 on this hub.
///
/// # Errors
/// Returns an error when the forward marker is missing, an identity is empty,
/// or the G→C frame cannot be encoded.
pub(crate) async fn handle(
    hub: &GatewaySessionHub,
    request: GatewayForwardEphemeralRequest,
) -> anyhow::Result<SessionPushForwardResponse> {
    anyhow::ensure!(request.forwarded, "forward marker required");
    for id in [&request.source_gateway_id, &request.target_delivery_id] {
        anyhow::ensure!(!id.is_empty() && id.len() <= 256, "invalid forwarding identity");
    }
    let bytes = frame_bytes(&request.envelope, request.expires_at_ms)
        .ok_or_else(|| anyhow::anyhow!("ephemeral frame encode failed"))?;
    let outcome = hub
        .try_enqueue_ephemeral(
            &request.target_delivery_id,
            &request.target_delivery_id,
            &request.envelope.target_delivery_id,
            bytes,
            request.expires_at_ms,
        )
        .await;
    Ok(map_forward(outcome))
}

#[derive(Serialize)]
struct EphemeralWire<'a> {
    frame_type: &'static str,
    envelope: &'a Envelope,
    expires_at_ms: u64,
}

fn frame_bytes(envelope: &Envelope, expires_at_ms: u64) -> Option<Vec<u8>> {
    serde_json::to_vec(&EphemeralWire { frame_type: "ephemeral", envelope, expires_at_ms }).ok()
}

#[cfg(test)]
mod tests;
