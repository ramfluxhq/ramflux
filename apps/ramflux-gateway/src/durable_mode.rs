// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed durable-origin refusal for gateway edge handlers.

pub(crate) const NACK_REASON: &str = "delivery_mode_refused";

pub(crate) fn rejected_security(
    envelope: &ramflux_protocol::Envelope,
) -> ramflux_node_core::EnvelopeSubmitResponse {
    ramflux_node_core::EnvelopeSubmitResponse {
        migration_refusal: None,
        outcome: "rejected_security:delivery_mode_refused".into(),
        target_delivery_id: envelope.target_delivery_id.clone(),
        inbox_seq: None,
        cursor: None,
        nack: None,
    }
}

pub(crate) fn nack_frame() -> ramflux_node_core::GatewayServerFrame {
    ramflux_node_core::GatewayServerFrame::Nack { reason: NACK_REASON.into() }
}
