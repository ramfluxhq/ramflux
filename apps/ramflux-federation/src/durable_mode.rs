// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed durable-origin refusal for federation edge and ingress handlers.

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

pub(crate) fn refused_forward(
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
) -> ramflux_node_core::FederatedEnvelopeForwardResponse {
    ramflux_node_core::FederatedEnvelopeForwardResponse {
        accepted: false,
        source_node_id: request.source_node_id.clone(),
        target_node_id: request.target_node_id.clone(),
        delivery: rejected_security(&request.envelope),
    }
}
