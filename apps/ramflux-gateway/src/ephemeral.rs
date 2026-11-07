// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway ephemeral ingress: validate, rate, route, local enqueue, one result.

use crate::push_queue::TransientAdmission;
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
use ramflux_protocol::Envelope;
use ramflux_protocol::ephemeral::{
    EphemeralDropReason, EphemeralModeError, EphemeralSubmitOutcome, deadline,
};

/// Whole G→C `ephemeral` frame cap, inclusive (32,768 accepted, 32,769 refused).
pub(crate) const EPHEMERAL_FRAME_CAP: usize = 32_768;
/// Per-sender-session burst; any window `t` seconds allows `40 + 20t` admits.
pub(crate) const EPHEMERAL_RATE_BURST: u32 = 40;
/// Token refill interval matching 20 admits per second.
pub(crate) const EPHEMERAL_RATE_REFILL_MS: u64 = 50;

/// Whether source/signature authorization already passed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceCheck {
    Ok,
    Rejected,
}

/// Router decision after validation and rate (P06 supplies the mesh body; tests inject a recorder).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteDecision {
    Local,
    Remote,
    Dropped(EphemeralDropReason),
}

/// Per-session token bucket: burst 40, one token per 50 ms.
#[derive(Debug)]
pub(crate) struct EphemeralRateLimiter {
    tokens: u32,
    last_ms: Option<u64>,
}

impl Default for EphemeralRateLimiter {
    fn default() -> Self {
        Self { tokens: EPHEMERAL_RATE_BURST, last_ms: None }
    }
}

impl EphemeralRateLimiter {
    /// Refill from `now_ms` and consume one token.
    pub(crate) fn try_acquire(&mut self, now_ms: u64) -> bool {
        if let Some(last) = self.last_ms {
            let refill = now_ms.saturating_sub(last) / EPHEMERAL_RATE_REFILL_MS;
            if refill > 0 {
                let tokens = u64::from(self.tokens)
                    .saturating_add(refill)
                    .min(u64::from(EPHEMERAL_RATE_BURST));
                self.tokens = u32::try_from(tokens).unwrap_or(EPHEMERAL_RATE_BURST);
                self.last_ms =
                    Some(last.saturating_add(refill.saturating_mul(EPHEMERAL_RATE_REFILL_MS)));
            }
        } else {
            self.last_ms = Some(now_ms);
            self.tokens = EPHEMERAL_RATE_BURST;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens = self.tokens.saturating_sub(1);
        true
    }
}

pub(crate) trait EphemeralRoute {
    fn route(
        &mut self,
        envelope: &Envelope,
        expires_at_ms: u64,
    ) -> impl std::future::Future<Output = RouteDecision> + Send;
}

pub(crate) trait EphemeralEnqueue {
    fn enqueue(
        &mut self,
        target: &str,
        bytes: Vec<u8>,
        expires_at_ms: u64,
    ) -> impl std::future::Future<Output = TransientAdmission> + Send;
}

pub(crate) struct Admission<'a, R, E> {
    pub negotiated: bool,
    pub now_ms: u64,
    pub envelope: &'a Envelope,
    pub source: SourceCheck,
    pub rate: &'a mut EphemeralRateLimiter,
    pub route: &'a mut R,
    pub enqueue: &'a mut E,
}

/// Validate, rate, route, enqueue; return exactly one `ephemeral_result`.
#[must_use]
pub(crate) async fn admit<R, E>(input: Admission<'_, R, E>) -> ramflux_node_core::GatewayServerFrame
where
    R: EphemeralRoute,
    E: EphemeralEnqueue,
{
    let envelope_id = input.envelope.envelope_id.clone();
    if !input.negotiated {
        return dropped(envelope_id, EphemeralDropReason::Unsupported);
    }
    if input.source == SourceCheck::Rejected {
        return dropped(envelope_id, EphemeralDropReason::Invalid);
    }

    // Validation (mode, priority, clock, size) and rate run before any router I/O.
    let expires_at_ms = match deadline(input.envelope, input.now_ms) {
        Ok(deadline) => deadline,
        Err(error) => return dropped(envelope_id, mode_reason(error)),
    };
    let Some(bytes) = frame_bytes(input.envelope, expires_at_ms) else {
        return dropped(envelope_id, EphemeralDropReason::Invalid);
    };
    if bytes.len() > EPHEMERAL_FRAME_CAP {
        return dropped(envelope_id, EphemeralDropReason::Invalid);
    }
    if !input.rate.try_acquire(input.now_ms) {
        return dropped(envelope_id, EphemeralDropReason::RateLimited);
    }

    match input.route.route(input.envelope, expires_at_ms).await {
        RouteDecision::Dropped(reason) => dropped(envelope_id, reason),
        RouteDecision::Remote => dropped(envelope_id, EphemeralDropReason::NotLocal),
        RouteDecision::Local => match input
            .enqueue
            .enqueue(&input.envelope.target_delivery_id, bytes, expires_at_ms)
            .await
        {
            TransientAdmission::Queued => accepted(envelope_id),
            TransientAdmission::QueueFull => dropped(envelope_id, EphemeralDropReason::QueueFull),
            TransientAdmission::Closed => dropped(envelope_id, EphemeralDropReason::Offline),
        },
    }
}

/// Session ingress for a non-durable submit: one typed result, never the durable mesh.
pub(crate) async fn handle_submit(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> anyhow::Result<()> {
    if !runtime.ephemeral_negotiated() {
        crate::session::write_gateway_handle(
            send,
            &ramflux_node_core::GatewayServerFrame::Nack { reason: "unsupported".to_owned() },
        )
        .await?;
        return Ok(());
    }
    let (envelope, source) = match crate::submit_source::bind_source(runtime, &submit.envelope) {
        Ok(envelope) => (envelope, SourceCheck::Ok),
        Err(_) => (submit.envelope.clone(), SourceCheck::Rejected),
    };
    let source = match crate::session::validate_gateway_session_signed_request(
        context,
        runtime,
        &submit.signed_request,
        "POST",
        "/gateway/session/submit",
        &submit.envelope,
    ) {
        Ok(()) => source,
        Err(_) => SourceCheck::Rejected,
    };
    let mut rate = EphemeralRateLimiter::default();
    let mut route = MeshRoute { context };
    let mut enqueue = HubEnqueue { hub: &context.hub };
    let frame = admit(Admission {
        negotiated: true,
        now_ms: now_ms(),
        envelope: &envelope,
        source,
        rate: &mut rate,
        route: &mut route,
        enqueue: &mut enqueue,
    })
    .await;
    crate::session::write_gateway_handle(send, &frame).await
}

fn mode_reason(error: EphemeralModeError) -> EphemeralDropReason {
    match error {
        EphemeralModeError::Expired => EphemeralDropReason::Expired,
        _ => EphemeralDropReason::Invalid,
    }
}

fn accepted(envelope_id: String) -> ramflux_node_core::GatewayServerFrame {
    ramflux_node_core::GatewayServerFrame::EphemeralResult {
        envelope_id,
        outcome: EphemeralSubmitOutcome::Accepted,
        reason: None,
    }
}

fn dropped(
    envelope_id: String,
    reason: EphemeralDropReason,
) -> ramflux_node_core::GatewayServerFrame {
    ramflux_node_core::GatewayServerFrame::EphemeralResult {
        envelope_id,
        outcome: EphemeralSubmitOutcome::Dropped,
        reason: Some(reason),
    }
}

fn frame_bytes(envelope: &Envelope, expires_at_ms: u64) -> Option<Vec<u8>> {
    serde_json::to_vec(&ramflux_node_core::GatewayServerFrame::Ephemeral {
        envelope: envelope.clone(),
        expires_at_ms,
    })
    .ok()
}

fn now_ms() -> u64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn parse_drop_reason(reason: &str) -> EphemeralDropReason {
    match reason {
        "offline" => EphemeralDropReason::Offline,
        "queue_full" => EphemeralDropReason::QueueFull,
        "expired" => EphemeralDropReason::Expired,
        "rate_limited" => EphemeralDropReason::RateLimited,
        "not_local" => EphemeralDropReason::NotLocal,
        "target_refused" => EphemeralDropReason::TargetRefused,
        "recipient_unsupported" => EphemeralDropReason::RecipientUnsupported,
        "unsupported" => EphemeralDropReason::Unsupported,
        "replayed" => EphemeralDropReason::Replayed,
        _ => EphemeralDropReason::Invalid,
    }
}

struct MeshRoute<'a> {
    context: &'a GatewayQuicContext,
}

impl EphemeralRoute for MeshRoute<'_> {
    async fn route(&mut self, envelope: &Envelope, expires_at_ms: u64) -> RouteDecision {
        let body = serde_json::json!({
            "envelope": envelope,
            "expires_at_ms": expires_at_ms,
        });
        match crate::router_post_json_async(&self.context.router, "/mvp0/envelope-ephemeral", &body)
            .await
        {
            Ok(value) => parse_route_reply(&value, &self.context.gateway_id),
            Err(_) => RouteDecision::Dropped(EphemeralDropReason::Invalid),
        }
    }
}

fn parse_route_reply(value: &serde_json::Value, local_gateway_id: &str) -> RouteDecision {
    if let Some("online") = value.get("outcome").and_then(serde_json::Value::as_str) {
        let gateway_id = value.get("gateway_id").and_then(serde_json::Value::as_str).unwrap_or("");
        if gateway_id == local_gateway_id { RouteDecision::Local } else { RouteDecision::Remote }
    } else {
        let reason = value.get("reason").and_then(serde_json::Value::as_str).unwrap_or("invalid");
        RouteDecision::Dropped(parse_drop_reason(reason))
    }
}

struct HubEnqueue<'a> {
    hub: &'a crate::GatewaySessionHub,
}

impl EphemeralEnqueue for HubEnqueue<'_> {
    async fn enqueue(
        &mut self,
        target: &str,
        bytes: Vec<u8>,
        expires_at_ms: u64,
    ) -> TransientAdmission {
        self.hub.try_push_transient(target, bytes, expires_at_ms).await
    }
}

#[cfg(test)]
mod tests;
