// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable mesh projection, including compatibility with boolean-only peers.
use ramflux_node_core::{
    SessionPushForwardOutcome as Outcome, SessionPushForwardResponse as Response,
};
pub(crate) fn validate(request: &crate::GatewayForwardDeliverRequest) -> anyhow::Result<()> {
    anyhow::ensure!(request.forwarded, "forward marker required");
    for id in [&request.source_gateway_id, &request.target_delivery_id] {
        anyhow::ensure!(!id.is_empty() && id.len() <= 256, "invalid forwarding identity");
    }
    let ramflux_node_core::GatewayServerFrame::Deliver { entry } = &request.frame else {
        anyhow::bail!("durable Deliver required");
    };
    anyhow::ensure!(
        entry.target_delivery_id == request.target_delivery_id
            && entry.envelope.target_delivery_id == request.target_delivery_id
            && entry.inbox_seq > 0,
        "forward target/sequence mismatch"
    );
    match (&request.incarnation_id, request.retain_until) {
        (None, None) => Ok(()),
        (Some(id), Some(deadline))
            if ramflux_node_core::valid_inbox_incarnation(id) && deadline > 0 =>
        {
            Ok(())
        }
        _ => anyhow::bail!("invalid forward incarnation/deadline pair"),
    }
}
pub(crate) fn response(outcome: Outcome) -> Response {
    Response {
        delivered: matches!(outcome, Outcome::Queued | Outcome::Overflowed),
        outcome: Some(outcome),
    }
}
pub(crate) fn handled(reply: &Response) -> anyhow::Result<bool> {
    match reply.outcome {
        None => Ok(reply.delivered),
        Some(Outcome::Queued | Outcome::Overflowed) if reply.delivered => Ok(true),
        Some(Outcome::NoSession) if !reply.delivered => Ok(false),
        _ => anyhow::bail!("invalid durable mesh result"),
    }
}
#[cfg(test)]
mod tests;
