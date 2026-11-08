// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-node ephemeral forward and C4 §6.3 mapping. Never wakes.

use crate::GatewaySessionHub;
use ramflux_node_core::{SessionPushForwardOutcome, SessionPushForwardResponse};
use ramflux_protocol::Envelope;
use ramflux_protocol::ephemeral::{EphemeralModeError, deadline};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Mesh path for same-node cross-gateway ephemeral delivery.
pub(crate) const PATH: &str = "/mvp0/gateway-forward-ephemeral";
/// Whole G→C JSON `{frame_type:"ephemeral", envelope, expires_at_ms}` byte cap.
pub(crate) const FRAME_BYTE_CAP: usize = 32_768;

/// C4 enqueue result before §6.3 mesh mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub(crate) enum EphemeralEnqueueOutcome {
    Queued,
    QueueFull,
    RecipientUnsupported,
    Offline,
    Expired,
    Invalid,
}

impl std::fmt::Display for EphemeralEnqueueOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Queued => "queued",
            Self::QueueFull => "queue_full",
            Self::RecipientUnsupported => "recipient_unsupported",
            Self::Offline => "offline",
            Self::Expired => "expired",
            Self::Invalid => "invalid",
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
/// `expired` / `no_session` / `invalid` are `delivered=false` and never originate a wake.
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
        EphemeralEnqueueOutcome::Expired => SessionPushForwardResponse {
            delivered: false,
            outcome: Some(SessionPushForwardOutcome::Expired),
        },
        EphemeralEnqueueOutcome::Invalid => SessionPushForwardResponse {
            delivered: false,
            outcome: Some(SessionPushForwardOutcome::Invalid),
        },
    }
}

/// Identity: ephemeral C4 never calls the durable notifier.
pub(crate) fn finish_without_wake(outcome: EphemeralEnqueueOutcome) -> EphemeralEnqueueOutcome {
    outcome
}

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Admit a same-node ephemeral forward and run C4 on this hub.
///
/// # Errors
/// Returns an error when the forward marker is missing, an identity is empty
/// or longer than 256 bytes, or the G→C frame cannot be encoded.
pub(crate) async fn handle(
    hub: &GatewaySessionHub,
    request: GatewayForwardEphemeralRequest,
) -> anyhow::Result<SessionPushForwardResponse> {
    handle_at(hub, request, wall_clock_ms()).await
}

/// Admit a same-node ephemeral forward at `now_ms`.
///
/// # Errors
/// Returns an error when the forward marker is missing, an identity is empty
/// or longer than 256 bytes, or the G→C frame cannot be encoded.
pub(crate) async fn handle_at(
    hub: &GatewaySessionHub,
    request: GatewayForwardEphemeralRequest,
    now_ms: u64,
) -> anyhow::Result<SessionPushForwardResponse> {
    anyhow::ensure!(request.forwarded, "forward marker required");
    for id in [&request.source_gateway_id, &request.target_delivery_id] {
        anyhow::ensure!(!id.is_empty() && id.len() <= 256, "invalid forwarding identity");
    }
    if let Some(outcome) = pre_enqueue_refusal(&request, now_ms, skip_deadline_equality(hub)) {
        return Ok(map_forward(finish_without_wake(outcome)));
    }
    let bytes = frame_bytes(&request.envelope, request.expires_at_ms)
        .ok_or_else(|| anyhow::anyhow!("ephemeral frame encode failed"))?;
    if bytes.len() > FRAME_BYTE_CAP {
        return Ok(map_forward(finish_without_wake(EphemeralEnqueueOutcome::Invalid)));
    }
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

fn skip_deadline_equality(
    #[cfg_attr(not(test), allow(unused_variables))] hub: &GatewaySessionHub,
) -> bool {
    #[cfg(test)]
    {
        hub.skip_deadline_equality()
    }
    #[cfg(not(test))]
    {
        false
    }
}

fn pre_enqueue_refusal(
    request: &GatewayForwardEphemeralRequest,
    now_ms: u64,
    skip_deadline_equality: bool,
) -> Option<EphemeralEnqueueOutcome> {
    match deadline(&request.envelope, now_ms) {
        Err(EphemeralModeError::Expired) => Some(EphemeralEnqueueOutcome::Expired),
        Err(_) => Some(EphemeralEnqueueOutcome::Invalid),
        Ok(computed) => {
            if skip_deadline_equality {
                return None;
            }
            if computed == request.expires_at_ms {
                None
            } else {
                Some(EphemeralEnqueueOutcome::Invalid)
            }
        }
    }
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
