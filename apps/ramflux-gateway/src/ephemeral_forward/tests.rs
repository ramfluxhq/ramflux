// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    EphemeralEnqueueOutcome, FRAME_BYTE_CAP, GatewayForwardEphemeralRequest, PATH, frame_bytes,
    handle_at, map_forward,
};
use crate::GatewaySessionHub;
use crate::push_queue::{TRANSIENT_BYTE_CAP, TRANSIENT_FRAME_CAP};
use crate::session_push::tests::support::{ID, sink};
use ramflux_node_core::{
    EphemeralRouteGate, RouterCore, SessionDescriptor, SessionLifecycle, SessionPushForwardOutcome,
};
use ramflux_protocol::ephemeral::DELIVERY_MODE_EXTENSION;
use ramflux_protocol::{Envelope, Ext, Priority};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TARGET: &str = "target-c4";
const OTHER: &str = "target-other";
const SESSION: &str = "session-c4";
const SESSION_B: &str = "session-c4-b";
const SOURCE: &str = "gateway-a";
const GATEWAY_A: &str = "ramflux-gateway";
const GATEWAY_B: &str = "ramflux-gateway-b";
const EXPIRES_AT_MS: u64 = 1_760_000_005_000;
const NOW_LIVE_MS: u64 = 1_760_000_004_999;
const NOW_EXPIRED_MS: u64 = 1_760_000_005_000;
const RECIPIENT_UNSUPPORTED: &str = "recipient_unsupported";
const OFFLINE: &str = "offline";
const QUEUE_FULL: &str = "queue_full";
const EXPIRED: &str = "expired";
const INVALID: &str = "invalid";

type TestResult = anyhow::Result<()>;
type Fallible<T> = anyhow::Result<T>;

#[allow(clippy::panic, reason = "test hang guard must fail with the awaited event")]
async fn guard_10s<F: std::future::Future>(event: &str, future: F) -> F::Output {
    match tokio::time::timeout(Duration::from_secs(10), future).await {
        Ok(output) => output,
        Err(elapsed) => panic!("timed out waiting for {event} after 10s: {elapsed}"),
    }
}

fn ephemeral_ext() -> Ext {
    let mut ext = BTreeMap::new();
    ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("ephemeral".to_owned()));
    Ext { ext }
}

fn envelope(target: &str, envelope_id: &str) -> Envelope {
    Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: ephemeral_ext(),
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
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
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

fn pad_request_to(
    mut request: GatewayForwardEphemeralRequest,
    want: usize,
) -> Fallible<GatewayForwardEphemeralRequest> {
    let base = frame_bytes(&request.envelope, request.expires_at_ms)
        .ok_or_else(|| anyhow::anyhow!("encode base"))?;
    anyhow::ensure!(base.len() <= want, "base {} exceeds {want}", base.len());
    request.envelope.encrypted_payload.push_str(&"x".repeat(want - base.len()));
    let got = frame_bytes(&request.envelope, request.expires_at_ms)
        .ok_or_else(|| anyhow::anyhow!("encode padded"))?;
    anyhow::ensure!(got.len() == want, "padded {} want {want}", got.len());
    Ok(request)
}

fn decode_request(
    request: &GatewayForwardEphemeralRequest,
) -> Fallible<GatewayForwardEphemeralRequest> {
    let wire = serde_json::to_vec(request)?;
    let decoded: GatewayForwardEphemeralRequest = serde_json::from_slice(&wire)?;
    let again = serde_json::to_vec(&decoded)?;
    anyhow::ensure!(again == wire, "forward request bytes changed after decode");
    anyhow::ensure!(decoded == *request);
    Ok(decoded)
}

async fn capable_hub_frames(
    target: &str,
) -> Fallible<(Arc<GatewaySessionHub>, Arc<Mutex<Vec<Value>>>)> {
    let hub = Arc::new(GatewaySessionHub::default());
    let (send, frames) = sink();
    hub.register_ephemeral(target.to_owned(), SESSION.to_owned(), send, Some(ID.into()), 32)
        .await?;
    anyhow::ensure!(hub.ephemeral_flag(target).await == Some(true));
    hub.set_queue_clock(target, NOW_LIVE_MS).await;
    Ok((hub, frames))
}

async fn capable_hub(target: &str) -> Fallible<Arc<GatewaySessionHub>> {
    let (hub, _) = capable_hub_frames(target).await?;
    Ok(hub)
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

fn seed_live(router: &RouterCore, target: &str, session_id: &str, gateway_id: &str) -> TestResult {
    router.upsert_session(SessionDescriptor {
        target_delivery_id: target.into(),
        device_id: "device".into(),
        gateway_id: gateway_id.into(),
        session_id: session_id.into(),
        device_epoch: 1,
        session_seq: 1,
        last_cursor: None,
        push_alias_hash: None,
        lifecycle: SessionLifecycle::Live,
    })?;
    router.mark_live(target)?;
    Ok(())
}

async fn park_hub_write(
    hub: &GatewaySessionHub,
    target: &str,
) -> Fallible<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Semaphore>)> {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let queue = hub
        .snapshot()
        .await
        .get(target)
        .ok_or_else(|| anyhow::anyhow!("missing hub {target}"))?
        .queue
        .clone();
    queue.park_next_write(entered.clone(), release.clone());
    Ok((entered, release))
}

async fn row_durable_wake_positive_control(context: &crate::GatewayQuicContext) -> TestResult {
    let before = context.notify.wake_count();
    let mut envelope = envelope(TARGET, "env-wake");
    envelope.created_at = i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(0);
    envelope.ttl = 60;
    crate::session::dispatch_offline_wake(context, "source-c4", 1, 1, TARGET, &envelope).await?;
    assert_eq!(context.notify.wake_count(), before + 1);
    Ok(())
}

async fn row_ephemeral_forward_does_not_wake(context: &crate::GatewayQuicContext) -> TestResult {
    let pair = crate::serve::forward_identity_tests::ephemeral_pair()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let mut caller = context.clone();
    caller.gateway_id = "gw-a".into();
    caller.peers = pair.peers.clone();
    let hub = &pair.hub;
    let forward = request(TARGET, TARGET, "env-nowake");
    let (recipient, received) = sink();
    hub.register_ephemeral(TARGET.into(), SESSION.into(), recipient, Some(ID.into()), 32).await?;
    hub.set_ephemeral_clock_ms(NOW_LIVE_MS);
    hub.set_queue_clock(TARGET, NOW_LIVE_MS).await;
    let wake_before = caller.notify.wake_count();
    let reply = super::originate(&caller, "gw-b", &forward.envelope, forward.expires_at_ms).await;
    assert_eq!(reply, crate::ephemeral::RouteDecision::Forwarded);
    hub.flushed(TARGET).await?;
    assert_eq!(received.lock().map_err(|_| anyhow::anyhow!("recipient frames"))?.len(), 1);
    assert_eq!(caller.notify.wake_count(), wake_before, "actual forwarding caller must not wake");
    Ok(())
}

async fn row_writer_emits_transient() -> TestResult {
    let (hub, frames) = capable_hub_frames(TARGET).await?;
    let reply =
        handle_at(&hub, decode_request(&request(TARGET, TARGET, "env-ok"))?, NOW_LIVE_MS).await?;
    assert!(reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Queued));
    hub.flushed(TARGET).await?;
    let recorded = frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.clone();
    let expected = serde_json::from_slice::<Value>(
        &frame_bytes(&request(TARGET, TARGET, "env-ok").envelope, EXPIRES_AT_MS)
            .ok_or_else(|| anyhow::anyhow!("encode expected"))?,
    )?;
    assert_eq!(recorded, vec![expected]);
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_sixty_fifth_frame_queue_full() -> TestResult {
    let hub = capable_hub(TARGET).await?;
    let (entered, release) = park_hub_write(&hub, TARGET).await?;
    let first = handle_at(&hub, request(TARGET, TARGET, "env-f0"), NOW_LIVE_MS).await?;
    assert!(first.delivered);
    guard_10s("writer entering the sink for the frame-cap row", entered.notified()).await;
    for n in 1..TRANSIENT_FRAME_CAP {
        let reply =
            handle_at(&hub, request(TARGET, TARGET, &format!("env-f{n}")), NOW_LIVE_MS).await?;
        assert!(reply.delivered, "frame {n}");
    }
    assert_eq!(hub.ephemeral_queued(TARGET).await, TRANSIENT_FRAME_CAP);
    let overflow = handle_at(&hub, request(TARGET, TARGET, "env-f64"), NOW_LIVE_MS).await?;
    assert!(!overflow.delivered);
    assert_eq!(overflow.outcome, Some(SessionPushForwardOutcome::Full));
    assert_eq!(EphemeralEnqueueOutcome::QueueFull.to_string(), QUEUE_FULL);
    assert_eq!(hub.ephemeral_queued(TARGET).await, TRANSIENT_FRAME_CAP);
    release.add_permits(1);
    Ok(())
}

async fn row_byte_cap_ninth_max_frame_queue_full() -> TestResult {
    let hub = capable_hub(TARGET).await?;
    let (entered, release) = park_hub_write(&hub, TARGET).await?;
    let first = handle_at(
        &hub,
        pad_request_to(request(TARGET, TARGET, "env-b0"), FRAME_BYTE_CAP)?,
        NOW_LIVE_MS,
    )
    .await?;
    assert!(first.delivered);
    guard_10s("writer entering the sink for the byte-cap row", entered.notified()).await;
    for n in 1..8 {
        let reply = handle_at(
            &hub,
            pad_request_to(request(TARGET, TARGET, &format!("env-b{n}")), FRAME_BYTE_CAP)?,
            NOW_LIVE_MS,
        )
        .await?;
        assert!(reply.delivered, "max frame {n}");
    }
    assert_eq!(hub.ephemeral_queued(TARGET).await, 8);
    let overflow = handle_at(
        &hub,
        pad_request_to(request(TARGET, TARGET, "env-b8"), FRAME_BYTE_CAP)?,
        NOW_LIVE_MS,
    )
    .await?;
    assert!(!overflow.delivered);
    assert_eq!(overflow.outcome, Some(SessionPushForwardOutcome::Full));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 8);
    assert_eq!(8 * FRAME_BYTE_CAP, TRANSIENT_BYTE_CAP);
    release.add_permits(1);
    Ok(())
}

async fn row_forward_target_differs_from_hub() -> TestResult {
    let hub = capable_hub(TARGET).await?;
    let bytes = frame_bytes(&request(OTHER, TARGET, "env-hub-mismatch").envelope, EXPIRES_AT_MS)
        .ok_or_else(|| anyhow::anyhow!("encode"))?;
    let outcome = hub.try_enqueue_ephemeral(TARGET, OTHER, TARGET, bytes, EXPIRES_AT_MS).await;
    assert_unsupported(outcome);
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    assert_eq!(hub.ephemeral_queued(OTHER).await, 0);
    Ok(())
}

async fn row_forward_target_differs_from_envelope() -> TestResult {
    let hub = capable_hub(TARGET).await?;
    let reply =
        handle_at(&hub, request(TARGET, OTHER, "env-envelope-mismatch"), NOW_LIVE_MS).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Unsupported));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    assert_eq!(hub.ephemeral_queued(OTHER).await, 0);
    Ok(())
}

async fn row_capability_absent() -> TestResult {
    let hub = Arc::new(GatewaySessionHub::default());
    let (send, _) = sink();
    hub.register_session(TARGET.to_owned(), SESSION.to_owned(), send, Some(ID.into())).await?;
    anyhow::ensure!(hub.ephemeral_flag(TARGET).await == Some(false));
    let reply = handle_at(&hub, request(TARGET, TARGET, "env-legacy"), NOW_LIVE_MS).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Unsupported));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_capable_token_replaced_after_c1() -> TestResult {
    let router = RouterCore::new();
    seed_live(&router, TARGET, SESSION, GATEWAY_A)?;
    router.bind_ephemeral_capability(TARGET, GATEWAY_A, SESSION);
    assert_eq!(
        router.route_gate(TARGET),
        EphemeralRouteGate::Online { gateway_id: GATEWAY_A.into(), session_id: SESSION.into() }
    );
    let hub = capable_hub(TARGET).await?;
    let (legacy, _) = sink();
    hub.register_session(TARGET.to_owned(), SESSION.to_owned(), legacy, Some(ID.into())).await?;
    anyhow::ensure!(hub.ephemeral_flag(TARGET).await == Some(false));
    assert_eq!(
        router.route_gate(TARGET),
        EphemeralRouteGate::Online { gateway_id: GATEWAY_A.into(), session_id: SESSION.into() }
    );
    let reply = handle_at(&hub, request(TARGET, TARGET, "env-replaced"), NOW_LIVE_MS).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Unsupported));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_no_hub_entry_offline() -> TestResult {
    let hub = Arc::new(GatewaySessionHub::default());
    let bytes = frame_bytes(&request(TARGET, TARGET, "env-missing").envelope, EXPIRES_AT_MS)
        .ok_or_else(|| anyhow::anyhow!("encode"))?;
    let outcome = hub.try_enqueue_ephemeral(TARGET, TARGET, TARGET, bytes, EXPIRES_AT_MS).await;
    assert_offline(outcome);
    let reply = handle_at(&hub, request(TARGET, TARGET, "env-missing"), NOW_LIVE_MS).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::NoSession));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_held_forward_enqueues_on_a_after_router_move() -> TestResult {
    let router = RouterCore::new();
    seed_live(&router, TARGET, SESSION, GATEWAY_A)?;
    router.bind_ephemeral_capability(TARGET, GATEWAY_A, SESSION);
    assert_eq!(
        router.route_gate(TARGET),
        EphemeralRouteGate::Online { gateway_id: GATEWAY_A.into(), session_id: SESSION.into() }
    );
    let (hub_a, frames_a) = capable_hub_frames(TARGET).await?;
    let (hub_b, frames_b) = capable_hub_frames(TARGET).await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    hub_a.park_next_enqueue(entered.clone(), release.clone());
    let held = hub_a.clone();
    let task = tokio::spawn(async move {
        handle_at(&held, request(TARGET, TARGET, "env-held-open"), NOW_LIVE_MS).await
    });
    guard_10s("hub enqueue hold for the router-move row", entered.notified()).await;
    seed_live(&router, TARGET, SESSION_B, GATEWAY_B)?;
    router.bind_ephemeral_capability(TARGET, GATEWAY_B, SESSION_B);
    assert_eq!(
        router.route_gate(TARGET),
        EphemeralRouteGate::Online { gateway_id: GATEWAY_B.into(), session_id: SESSION_B.into() }
    );
    release.add_permits(1);
    let reply = guard_10s("router-move ephemeral forward task", task).await??;
    assert!(reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Queued));
    hub_a.flushed(TARGET).await?;
    hub_b.flushed(TARGET).await?;
    let recorded_a = frames_a.lock().map_err(|_| anyhow::anyhow!("frames a"))?.clone();
    let recorded_b = frames_b.lock().map_err(|_| anyhow::anyhow!("frames b"))?.clone();
    let expected = serde_json::from_slice::<Value>(
        &frame_bytes(&request(TARGET, TARGET, "env-held-open").envelope, EXPIRES_AT_MS)
            .ok_or_else(|| anyhow::anyhow!("encode expected"))?,
    )?;
    assert_eq!(recorded_a, vec![expected]);
    assert_eq!(recorded_b, Vec::<Value>::new());
    assert_eq!(hub_a.ephemeral_queued(TARGET).await, 0);
    assert_eq!(hub_b.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_held_forward_drops_when_a_closed() -> TestResult {
    let router = RouterCore::new();
    seed_live(&router, TARGET, SESSION, GATEWAY_A)?;
    router.bind_ephemeral_capability(TARGET, GATEWAY_A, SESSION);
    let (hub_a, frames_a) = capable_hub_frames(TARGET).await?;
    let (hub_b, frames_b) = capable_hub_frames(TARGET).await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    hub_a.park_next_enqueue(entered.clone(), release.clone());
    let held = hub_a.clone();
    let task = tokio::spawn(async move {
        handle_at(&held, request(TARGET, TARGET, "env-held-closed"), NOW_LIVE_MS).await
    });
    guard_10s("hub enqueue hold for the closed-registration row", entered.notified()).await;
    seed_live(&router, TARGET, SESSION_B, GATEWAY_B)?;
    router.bind_ephemeral_capability(TARGET, GATEWAY_B, SESSION_B);
    assert_eq!(
        router.route_gate(TARGET),
        EphemeralRouteGate::Online { gateway_id: GATEWAY_B.into(), session_id: SESSION_B.into() }
    );
    let snapshot = hub_a.snapshot().await;
    let token = snapshot.get(TARGET).ok_or_else(|| anyhow::anyhow!("hub a token"))?.token;
    hub_a.unregister(TARGET, token).await;
    release.add_permits(1);
    let reply = guard_10s("closed-registration ephemeral forward task", task).await??;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::NoSession));
    hub_a.flushed(TARGET).await?;
    hub_b.flushed(TARGET).await?;
    let recorded_a = frames_a.lock().map_err(|_| anyhow::anyhow!("frames a"))?.clone();
    let recorded_b = frames_b.lock().map_err(|_| anyhow::anyhow!("frames b"))?.clone();
    assert_eq!(recorded_a, Vec::<Value>::new());
    assert_eq!(recorded_b, Vec::<Value>::new());
    assert_eq!(hub_a.ephemeral_queued(TARGET).await, 0);
    assert_eq!(hub_b.ephemeral_queued(TARGET).await, 0);
    assert_eq!(hub_a.ephemeral_queued(OTHER).await, 0);
    assert_eq!(hub_b.ephemeral_queued(OTHER).await, 0);
    Ok(())
}

async fn row_expired_at_d() -> TestResult {
    let hub = capable_hub(TARGET).await?;
    let reply = handle_at(&hub, request(TARGET, TARGET, "env-expired"), NOW_EXPIRED_MS).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Expired));
    assert_eq!(EphemeralEnqueueOutcome::Expired.to_string(), EXPIRED);
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_held_forward_refused_when_clock_reaches_d() -> TestResult {
    let hub = capable_hub(TARGET).await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    hub.park_next_enqueue(entered.clone(), release.clone());
    let held = hub.clone();
    let task = tokio::spawn(async move {
        handle_at(&held, request(TARGET, TARGET, "env-held-at-d"), NOW_LIVE_MS).await
    });
    guard_10s("hub enqueue hold for the deadline row", entered.notified()).await;
    hub.set_queue_clock(TARGET, EXPIRES_AT_MS).await;
    release.add_permits(1);
    let reply = guard_10s("deadline ephemeral forward task", task).await??;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Expired));
    assert_eq!(EphemeralEnqueueOutcome::Expired.to_string(), EXPIRED);
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_held_forward_queued_before_d() -> TestResult {
    let (hub, frames) = capable_hub_frames(TARGET).await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    hub.park_next_enqueue(entered.clone(), release.clone());
    let held = hub.clone();
    let task = tokio::spawn(async move {
        handle_at(&held, request(TARGET, TARGET, "env-held-before-d"), NOW_LIVE_MS).await
    });
    guard_10s("hub enqueue hold for the pre-deadline row", entered.notified()).await;
    release.add_permits(1);
    let reply = guard_10s("pre-deadline ephemeral forward task", task).await??;
    assert!(reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Queued));
    hub.flushed(TARGET).await?;
    let recorded = frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.clone();
    assert_eq!(recorded.len(), 1);
    Ok(())
}

async fn row_deadline_mismatch_invalid() -> TestResult {
    let hub = capable_hub(TARGET).await?;
    let mut req = request(TARGET, TARGET, "env-mismatch");
    req.expires_at_ms = 1_760_000_004_000;
    let reply = handle_at(&hub, req, NOW_LIVE_MS).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Invalid));
    assert_eq!(EphemeralEnqueueOutcome::Invalid.to_string(), INVALID);
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_durable_mode_invalid() -> TestResult {
    let hub = capable_hub(TARGET).await?;
    let mut req = request(TARGET, TARGET, "env-durable");
    req.envelope.ext = Ext::default();
    let reply = handle_at(&hub, req, NOW_LIVE_MS).await?;
    assert!(!reply.delivered);
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Invalid));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_frame_32768_accepted_32769_invalid() -> TestResult {
    let hub = capable_hub(TARGET).await?;
    let (entered, release) = park_hub_write(&hub, TARGET).await?;
    let accepted = handle_at(
        &hub,
        decode_request(&pad_request_to(request(TARGET, TARGET, "env-max"), FRAME_BYTE_CAP)?)?,
        NOW_LIVE_MS,
    )
    .await?;
    assert!(accepted.delivered);
    assert_eq!(accepted.outcome, Some(SessionPushForwardOutcome::Queued));
    guard_10s("writer entering the sink for the maximum-frame row", entered.notified()).await;
    release.add_permits(1);
    hub.flushed(TARGET).await?;
    let over = handle_at(
        &hub,
        decode_request(&pad_request_to(
            request(TARGET, TARGET, "env-over"),
            FRAME_BYTE_CAP.saturating_add(1),
        )?)?,
        NOW_LIVE_MS,
    )
    .await?;
    assert!(!over.delivered);
    assert_eq!(over.outcome, Some(SessionPushForwardOutcome::Invalid));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_marker_required_exact_error() -> TestResult {
    let hub = capable_hub(TARGET).await?;
    let mut req = request(TARGET, TARGET, "env-marker");
    req.forwarded = false;
    let decoded = decode_request(&req)?;
    let error = handle_at(&hub, decoded, NOW_LIVE_MS).await.err().map(|e| e.to_string());
    assert_eq!(error.as_deref(), Some("forward marker required"));
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0);
    Ok(())
}

async fn row_id_bounds_exact_errors_and_inclusive_positives() -> TestResult {
    let empty = request(TARGET, TARGET, "env-id-empty");
    let mut empty = empty;
    empty.source_gateway_id.clear();
    let hub_empty = capable_hub(TARGET).await?;
    let error = handle_at(&hub_empty, decode_request(&empty)?, NOW_LIVE_MS)
        .await
        .err()
        .map(|e| e.to_string());
    assert_eq!(error.as_deref(), Some("invalid forwarding identity"));

    let mut over = request(TARGET, TARGET, "env-id-257");
    over.source_gateway_id = "x".repeat(257);
    let hub_over = capable_hub(TARGET).await?;
    let error = handle_at(&hub_over, decode_request(&over)?, NOW_LIVE_MS)
        .await
        .err()
        .map(|e| e.to_string());
    assert_eq!(error.as_deref(), Some("invalid forwarding identity"));

    let mut target_empty = request(TARGET, TARGET, "env-target-empty");
    target_empty.target_delivery_id.clear();
    let hub_target_empty = capable_hub(TARGET).await?;
    let error = handle_at(&hub_target_empty, decode_request(&target_empty)?, NOW_LIVE_MS)
        .await
        .err()
        .map(|e| e.to_string());
    assert_eq!(error.as_deref(), Some("invalid forwarding identity"));
    assert_eq!(hub_target_empty.ephemeral_queued(TARGET).await, 0);

    let mut target_over = request(TARGET, TARGET, "env-target-257");
    target_over.target_delivery_id = "y".repeat(257);
    let hub_target_over = capable_hub(TARGET).await?;
    let error = handle_at(&hub_target_over, decode_request(&target_over)?, NOW_LIVE_MS)
        .await
        .err()
        .map(|e| e.to_string());
    assert_eq!(error.as_deref(), Some("invalid forwarding identity"));
    assert_eq!(hub_target_over.ephemeral_queued(TARGET).await, 0);

    let one = "a";
    let (hub_one, frames_one) = capable_hub_frames(one).await?;
    let mut req_one = request(one, one, "env-id-1");
    req_one.source_gateway_id = "b".to_owned();
    let reply = handle_at(&hub_one, decode_request(&req_one)?, NOW_LIVE_MS).await?;
    assert!(reply.delivered);
    hub_one.flushed(one).await?;
    assert_eq!(frames_one.lock().map_err(|_| anyhow::anyhow!("frames"))?.len(), 1);

    let max = "c".repeat(256);
    let (hub_max, frames_max) = capable_hub_frames(&max).await?;
    let mut req_max = request(&max, &max, "env-id-256");
    req_max.source_gateway_id = "d".repeat(256);
    let reply = handle_at(&hub_max, decode_request(&req_max)?, NOW_LIVE_MS).await?;
    assert!(reply.delivered);
    hub_max.flushed(&max).await?;
    assert_eq!(frames_max.lock().map_err(|_| anyhow::anyhow!("frames"))?.len(), 1);
    Ok(())
}

async fn assert_forward_invalid(
    change: impl FnOnce(&mut GatewayForwardEphemeralRequest),
    envelope_id: &str,
) -> TestResult {
    let hub = capable_hub(TARGET).await?;
    hub.refuse_ephemeral_enqueue();
    let mut req = request(TARGET, TARGET, envelope_id);
    change(&mut req);
    let reply = handle_at(&hub, decode_request(&req)?, NOW_LIVE_MS).await?;
    assert!(!reply.delivered, "{envelope_id}");
    assert_eq!(reply.outcome, Some(SessionPushForwardOutcome::Invalid), "{envelope_id}");
    assert_eq!(hub.ephemeral_queued(TARGET).await, 0, "{envelope_id}");
    Ok(())
}

async fn row_isolated_p01_predicates() -> TestResult {
    assert_forward_invalid(
        |req| {
            req.envelope
                .ext
                .ext
                .insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("Ephemeral".to_owned()));
        },
        "p01-mode-Ephemeral",
    )
    .await?;
    assert_forward_invalid(
        |req| {
            req.envelope
                .ext
                .ext
                .insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String(String::new()));
        },
        "p01-mode-empty",
    )
    .await?;
    assert_forward_invalid(
        |req| {
            req.envelope
                .ext
                .ext
                .insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::Number(1.into()));
        },
        "p01-mode-1",
    )
    .await?;
    assert_forward_invalid(
        |req| {
            req.envelope.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::Null);
        },
        "p01-mode-null",
    )
    .await?;
    assert_forward_invalid(
        |req| {
            req.envelope.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), serde_json::json!({}));
        },
        "p01-mode-object",
    )
    .await?;
    assert_forward_invalid(|req| req.envelope.priority = Priority::Normal, "p01-priority-normal")
        .await?;
    assert_forward_invalid(|req| req.envelope.priority = Priority::High, "p01-priority-high")
        .await?;
    assert_forward_invalid(|req| req.envelope.priority = Priority::Urgent, "p01-priority-urgent")
        .await?;
    assert_forward_invalid(|req| req.envelope.ttl = 0, "p01-ttl-0").await?;
    assert_forward_invalid(|req| req.envelope.ttl = 6, "p01-ttl-6").await?;
    assert_forward_invalid(|req| req.envelope.ttl = u32::MAX, "p01-ttl-max").await?;
    assert_forward_invalid(
        |req| {
            req.envelope.created_at = i64::MAX;
            req.envelope.ttl = 5;
        },
        "p01-created-overflow",
    )
    .await?;
    assert_forward_invalid(
        |req| {
            req.envelope.created_at = -2;
            req.envelope.ttl = 1;
        },
        "p01-negative-deadline",
    )
    .await?;
    Ok(())
}

fn row_path_is_same_node_forward() {
    assert_eq!(PATH, "/mvp0/gateway-forward-ephemeral");
}

fn row_map_queue_full() {
    let mapped = map_forward(EphemeralEnqueueOutcome::QueueFull);
    assert!(!mapped.delivered);
    assert_eq!(mapped.outcome, Some(SessionPushForwardOutcome::Full));
    assert_eq!(EphemeralEnqueueOutcome::QueueFull.to_string(), QUEUE_FULL);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn final_registration_capability() -> TestResult {
    let (_fixture_directory_0, wake_context) = crate::session::tests::test_gateway_context()?;
    row_path_is_same_node_forward();
    row_map_queue_full();
    row_durable_wake_positive_control(&wake_context).await?;
    row_ephemeral_forward_does_not_wake(&wake_context).await?;
    row_writer_emits_transient().await?;
    row_sixty_fifth_frame_queue_full().await?;
    row_byte_cap_ninth_max_frame_queue_full().await?;
    row_forward_target_differs_from_hub().await?;
    row_forward_target_differs_from_envelope().await?;
    row_capable_token_replaced_after_c1().await?;
    row_capability_absent().await?;
    row_no_hub_entry_offline().await?;
    row_held_forward_enqueues_on_a_after_router_move().await?;
    row_held_forward_drops_when_a_closed().await?;
    row_expired_at_d().await?;
    row_held_forward_refused_when_clock_reaches_d().await?;
    row_held_forward_queued_before_d().await?;
    row_deadline_mismatch_invalid().await?;
    row_durable_mode_invalid().await?;
    row_frame_32768_accepted_32769_invalid().await?;
    row_marker_required_exact_error().await?;
    row_id_bounds_exact_errors_and_inclusive_positives().await?;
    row_isolated_p01_predicates().await?;
    Ok(())
}

#[tokio::test]
async fn ephemeral_enqueue_trap_calibrates_actual_boundary() -> TestResult {
    let hub = GatewaySessionHub::default();
    hub.refuse_ephemeral_enqueue();
    let result = tokio::spawn(async move {
        hub.try_enqueue_ephemeral(TARGET, TARGET, TARGET, Vec::new(), EXPIRES_AT_MS).await
    })
    .await;
    assert!(result.is_err_and(|error| error.is_panic()), "actual enqueue must trigger the trap");
    Ok(())
}
