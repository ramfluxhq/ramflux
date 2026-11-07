// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    EphemeralEnqueueOutcome, GatewayForwardEphemeralRequest, PATH, handle, map_forward,
    reset_wake_count, wake_count,
};
use crate::GatewaySessionHub;
use crate::session_push::tests::support::{ID, sink};
use ramflux_node_core::SessionPushForwardOutcome;
use ramflux_protocol::Envelope;
use std::sync::Arc;

const TARGET: &str = "target-c4";
const OTHER: &str = "target-other";
const SESSION: &str = "session-c4";
const SOURCE: &str = "gateway-a";
const EXPIRES_AT_MS: u64 = 1_760_000_005_000;
const RECIPIENT_UNSUPPORTED: &str = "recipient_unsupported";
const OFFLINE: &str = "offline";

type TestResult = anyhow::Result<()>;
type Fallible<T> = anyhow::Result<T>;

fn envelope(target: &str, envelope_id: &str) -> Envelope {
    Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "test-c4-key".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "test-c4-signature".to_owned(),
        },
        envelope_id: envelope_id.to_owned(),
        source_principal_id: "principal-c4".to_owned(),
        source_device_id: "device-c4".to_owned(),
        target_delivery_id: target.to_owned(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
        priority: ramflux_protocol::Priority::Low,
        ttl: 5,
        created_at: 1_760_000_000,
        encrypted_payload: "encrypted_payload".to_owned(),
        payload_hash: "payload_hash".to_owned(),
    }
}

fn request(
    target: &str,
    envelope_target: &str,
    envelope_id: &str,
) -> GatewayForwardEphemeralRequest {
    GatewayForwardEphemeralRequest {
        source_gateway_id: SOURCE.to_owned(),
        target_delivery_id: target.to_owned(),
        forwarded: true,
        envelope: envelope(envelope_target, envelope_id),
        expires_at_ms: EXPIRES_AT_MS,
    }
}

async fn capable_hub(target: &str) -> Fallible<Arc<GatewaySessionHub>> {
    let hub = Arc::new(GatewaySessionHub::default());
    let (send, _) = sink();
    hub.register_ephemeral(target.to_owned(), SESSION.to_owned(), send, Some(ID.into()), 32)
        .await?;
    anyhow::ensure!(hub.ephemeral_flag(target).await == Some(true));
    Ok(hub)
}

fn assert_no_wake() {
    assert_eq!(wake_count(), 0);
}

fn assert_unsupported(outcome: EphemeralEnqueueOutcome) {
    assert_eq!(outcome, EphemeralEnqueueOutcome::RecipientUnsupported);
    assert_eq!(outcome.to_string(), RECIPIENT_UNSUPPORTED);
    let mapped = map_forward(outcome);
    assert!(!mapped.delivered);
    assert_eq!(mapped.outcome, Some(SessionPushForwardOutcome::Unsupported));
}

fn assert_offline(outcome: EphemeralEnqueueOutcome) {
    assert_eq!(outcome, EphemeralEnqueueOutcome::Offline);
    assert_eq!(outcome.to_string(), OFFLINE);
    let mapped = map_forward(outcome);
    assert!(!mapped.delivered);
    assert_eq!(mapped.outcome, Some(SessionPushForwardOutcome::NoSession));
}

async fn row_capable_open_token_enqueues() -> TestResult {
    reset_wake_count();
    let hub = capable_hub(TARGET).await?;
    let reply = handle(&hub, request(TARGET, TARGET, "env-ok")).await?;
    assert!(reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Queued));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 1);
    assert_no_wake();
    Ok(())
}

async fn row_forward_target_differs_from_hub() -> TestResult {
    reset_wake_count();
    let hub = capable_hub(TARGET).await?;
    let bytes = serde_json::to_vec(&request(OTHER, TARGET, "env-hub-mismatch").envelope)?;
    let outcome = hub.try_enqueue_ephemeral(TARGET, OTHER, TARGET, bytes).await;
    assert_unsupported(outcome);
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    assert_eq!(hub.ephemeral_queued(OTHER).await, 0);
    assert_no_wake();
    Ok(())
}

async fn row_forward_target_differs_from_envelope() -> TestResult {
    reset_wake_count();
    let hub = capable_hub(TARGET).await?;
    let reply = handle(&hub, request(TARGET, OTHER, "env-envelope-mismatch")).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Unsupported));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    assert_eq!(hub.ephemeral_queued(OTHER).await, 0);
    assert_no_wake();
    Ok(())
}

async fn row_capability_absent() -> TestResult {
    reset_wake_count();
    let hub = Arc::new(GatewaySessionHub::default());
    let (send, _) = sink();
    hub.register_session(TARGET.to_owned(), SESSION.to_owned(), send, Some(ID.into())).await?;
    anyhow::ensure!(hub.ephemeral_flag(TARGET).await == Some(false));
    let reply = handle(&hub, request(TARGET, TARGET, "env-legacy")).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Unsupported));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    assert_no_wake();
    Ok(())
}

async fn row_capable_token_replaced_by_legacy() -> TestResult {
    reset_wake_count();
    let hub = capable_hub(TARGET).await?;
    let (legacy, _) = sink();
    hub.register_session(TARGET.to_owned(), SESSION.to_owned(), legacy, Some(ID.into())).await?;
    anyhow::ensure!(hub.ephemeral_flag(TARGET).await == Some(false));
    let reply = handle(&hub, request(TARGET, TARGET, "env-replaced")).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Unsupported));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    assert_no_wake();
    Ok(())
}

async fn row_no_hub_entry_offline() -> TestResult {
    reset_wake_count();
    let hub = Arc::new(GatewaySessionHub::default());
    let bytes = serde_json::to_vec(&request(TARGET, TARGET, "env-missing").envelope)?;
    let outcome = hub.try_enqueue_ephemeral(TARGET, TARGET, TARGET, bytes).await;
    assert_offline(outcome);
    let reply = handle(&hub, request(TARGET, TARGET, "env-missing")).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::NoSession));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    assert_no_wake();
    Ok(())
}

async fn row_held_forward_enqueues_on_a_if_still_open() -> TestResult {
    reset_wake_count();
    let hub_a = capable_hub(TARGET).await?;
    let hub_b = capable_hub(TARGET).await?;
    let reply = handle(&hub_a, request(TARGET, TARGET, "env-held-open")).await?;
    assert!(reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Queued));
    assert_eq!(hub_a.ephemeral_queued(TARGET).await, 1);
    assert_eq!(hub_b.ephemeral_queued(TARGET).await, 0);
    assert_eq!(hub_a.ephemeral_queued(OTHER).await, 0);
    assert_no_wake();
    Ok(())
}

async fn row_held_forward_drops_when_a_closed() -> TestResult {
    reset_wake_count();
    let hub_a = capable_hub(TARGET).await?;
    let hub_b = capable_hub(TARGET).await?;
    let snapshot = hub_a.snapshot().await;
    let token = snapshot.get(TARGET).ok_or_else(|| anyhow::anyhow!("hub a token"))?.token;
    hub_a.unregister(TARGET, token).await;
    let reply = handle(&hub_a, request(TARGET, TARGET, "env-held-closed")).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::NoSession));
    assert_eq!(hub_a.ephemeral_queued(TARGET).await, 0);
    assert_eq!(hub_b.ephemeral_queued(TARGET).await, 0);
    assert_eq!(hub_a.ephemeral_queued(OTHER).await, 0);
    assert_eq!(hub_b.ephemeral_queued(OTHER).await, 0);
    assert_no_wake();
    Ok(())
}

fn row_path_is_same_node_forward() {
    assert_eq!(PATH, "/mvp0/gateway-forward-ephemeral");
}

fn row_map_queue_full() {
    let mapped = map_forward(EphemeralEnqueueOutcome::QueueFull);
    assert!(!mapped.delivered);
    assert_eq!(mapped.outcome, Some(SessionPushForwardOutcome::Full));
    assert_eq!(EphemeralEnqueueOutcome::QueueFull.to_string(), "queue_full");
}

#[tokio::test]
async fn final_registration_capability() -> TestResult {
    row_path_is_same_node_forward();
    row_map_queue_full();
    row_capable_open_token_enqueues().await?;
    row_forward_target_differs_from_hub().await?;
    row_forward_target_differs_from_envelope().await?;
    row_capable_token_replaced_by_legacy().await?;
    row_capability_absent().await?;
    row_no_hub_entry_offline().await?;
    row_held_forward_enqueues_on_a_if_still_open().await?;
    row_held_forward_drops_when_a_closed().await?;
    Ok(())
}
