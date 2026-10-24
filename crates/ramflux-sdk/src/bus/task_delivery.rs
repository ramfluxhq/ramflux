// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary gateway submission and bounded executor-confirmation retries.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub(super) struct Destination {
    pub route: LocalBusFederationRoute,
    pub conversation_id: String,
    pub message_id: String,
    pub device_id: String,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Delivery {
    pub envelope: ramflux_protocol::Envelope,
    pub federation: Option<Destination>,
    pub attempts: u32,
    pub next_at: i64,
}
pub(super) async fn submit_all(
    account: &mut LocalBusAccountState,
    deliveries: Vec<Delivery>,
) -> Result<usize, SdkError> {
    submit_until(account, deliveries, tokio::time::Instant::now() + Duration::from_secs(15)).await
}
pub(super) async fn submit_until(
    account: &mut LocalBusAccountState,
    deliveries: Vec<Delivery>,
    deadline: tokio::time::Instant,
) -> Result<usize, SdkError> {
    let count = deliveries.len();
    for delivery in deliveries {
        submit(account, &delivery, deadline).await?;
    }
    Ok(count)
}
async fn submit(
    account: &mut LocalBusAccountState,
    delivery: &Delivery,
    deadline: tokio::time::Instant,
) -> Result<(), SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result = if let Some(destination) = &delivery.federation {
        let envelope = &delivery.envelope;
        let body = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
            .map_err(|_| SdkError::LocalBus("invalid retained task ciphertext".into()));
        match body {
            Ok(encrypted_body) => account
                .client
                .forward_federated_gateway_message(
                    &engine,
                    &GatewayDirectMessage {
                        conversation_id: destination.conversation_id.clone(),
                        message_id: destination.message_id.clone(),
                        envelope_id: envelope.envelope_id.clone(),
                        source_principal_id: envelope.source_principal_id.clone(),
                        sender_id: envelope.source_device_id.clone(),
                        recipient_device_id: Some(destination.device_id.clone()),
                        target_delivery_id: envelope.target_delivery_id.clone(),
                        encrypted_body,
                        created_at: envelope.created_at,
                        ttl: envelope.ttl,
                    },
                    &destination.route,
                )
                .map(|_| ()),
            Err(error) => Err(error),
        }
    } else {
        match tokio::time::timeout_at(deadline, engine.submit_envelope(delivery.envelope.clone()))
            .await
        {
            Ok(result) => result.map(|_| ()),
            Err(_) => Err(SdkError::InboundPending("task delivery tick budget exhausted".into())),
        }
    };
    account.put_engine(engine);
    result
}
