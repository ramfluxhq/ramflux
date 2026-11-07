// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed durable-origin refusal for router edge and ingress handlers.

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

pub(crate) fn rejected_security_mesh(
    envelope: &ramflux_protocol::Envelope,
) -> ramflux_node_core::SessionPushSubmitResponse {
    ramflux_node_core::SessionPushSubmitResponse {
        delivery: rejected_security(envelope),
        incarnation_id: None,
        retain_until: None,
    }
}
