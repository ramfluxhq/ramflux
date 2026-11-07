// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed durable-origin refusal for router edge and ingress handlers.

pub(crate) const OUTCOME: &str = "rejected_security:delivery_mode_refused";
pub(crate) const REASON: &str = "delivery_mode_refused";

#[derive(Debug)]
pub(crate) struct DeliveryModeRefused {
    pub(crate) target_delivery_id: String,
}

impl DeliveryModeRefused {
    pub(crate) fn from_envelope(envelope: &ramflux_protocol::Envelope) -> Self {
        Self { target_delivery_id: envelope.target_delivery_id.clone() }
    }
}

impl std::fmt::Display for DeliveryModeRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REASON)
    }
}

impl std::error::Error for DeliveryModeRefused {}

pub(crate) fn rejected_security(
    envelope: &ramflux_protocol::Envelope,
) -> ramflux_node_core::EnvelopeSubmitResponse {
    rejected_security_for_target(&envelope.target_delivery_id)
}

pub(crate) fn rejected_security_for_target(
    target_delivery_id: &str,
) -> ramflux_node_core::EnvelopeSubmitResponse {
    ramflux_node_core::EnvelopeSubmitResponse {
        migration_refusal: None,
        outcome: OUTCOME.into(),
        target_delivery_id: target_delivery_id.to_owned(),
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

pub(crate) fn refused_quic(
    envelope: &ramflux_protocol::Envelope,
) -> ramflux_transport::GatewayQuicResponse {
    ramflux_transport::GatewayQuicResponse {
        status: 200,
        body: serde_json::json!({
            "migration_refusal": null,
            "outcome": OUTCOME,
            "target_delivery_id": envelope.target_delivery_id,
            "inbox_seq": null,
            "cursor": null,
            "nack": null,
        }),
    }
}

pub(crate) fn is_mode_refused(error: &anyhow::Error) -> bool {
    error.downcast_ref::<DeliveryModeRefused>().is_some()
        || error.downcast_ref::<ramflux_protocol::ephemeral::EphemeralModeError>().is_some()
        || error.chain().any(|source| source.to_string() == REASON)
}

pub(crate) fn transport_refusal(
    error: &anyhow::Error,
) -> Option<ramflux_node_core::EnvelopeSubmitResponse> {
    if !is_mode_refused(error) {
        return None;
    }
    let target = error
        .downcast_ref::<DeliveryModeRefused>()
        .map_or("", |refused| refused.target_delivery_id.as_str());
    Some(rejected_security_for_target(target))
}
