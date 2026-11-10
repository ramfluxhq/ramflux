// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named S6c P09 admission rows: validate-before-route, rate, one result.

use super::{
    Admission, EPHEMERAL_FRAME_CAP, EPHEMERAL_RATE_BURST, EphemeralEnqueue, EphemeralRate,
    EphemeralRoute, RouteDecision, SourceCheck, admit, frame_bytes,
};
use crate::push_queue::{TRANSIENT_BYTE_CAP, TransientAdmission};
use ramflux_protocol::ephemeral::{
    DELIVERY_MODE_EXTENSION, EphemeralDropReason, EphemeralSubmitOutcome, EphemeralSubmitResult,
    MAX_EPHEMERAL_TTL_SECONDS, MIN_EPHEMERAL_TTL_SECONDS,
};
use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

pub(super) const NOW_MS: u64 = 1_000_000;
pub(super) const DEADLINE_MS: u64 = 1_005_000;

pub(super) type TestResult<T = ()> = anyhow::Result<T>;

pub(super) struct RouteRecorder {
    pub(super) calls: Vec<(String, u64)>,
    pub(super) decision: RouteDecision,
}

impl Default for RouteRecorder {
    fn default() -> Self {
        Self { calls: Vec::new(), decision: RouteDecision::Local }
    }
}

impl EphemeralRoute for RouteRecorder {
    fn route(
        &mut self,
        envelope: &Envelope,
        expires_at_ms: u64,
    ) -> impl std::future::Future<Output = RouteDecision> + Send {
        self.calls.push((envelope.envelope_id.clone(), expires_at_ms));
        std::future::ready(self.decision)
    }
}

pub(super) struct EnqueueRecorder {
    pub(super) calls: usize,
    pub(super) admission: TransientAdmission,
    pub(super) last_bytes: Option<Vec<u8>>,
}

impl Default for EnqueueRecorder {
    fn default() -> Self {
        Self { calls: 0, admission: TransientAdmission::Queued, last_bytes: None }
    }
}

impl EphemeralEnqueue for EnqueueRecorder {
    fn enqueue(
        &mut self,
        _target: &str,
        bytes: Vec<u8>,
        _expires_at_ms: u64,
    ) -> impl std::future::Future<Output = TransientAdmission> + Send {
        self.calls = self.calls.saturating_add(1);
        self.last_bytes = Some(bytes);
        std::future::ready(self.admission)
    }
}

pub(super) fn valid_envelope() -> Envelope {
    let mut extensions = BTreeMap::new();
    extensions.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("ephemeral".to_owned()));
    Envelope {
        schema: "ramflux.envelope.v1".to_owned(),
        version: 1,
        domain: "ramflux.message".to_owned(),
        ext: Ext { ext: extensions },
        signed: SignedFields {
            signing_key_id: "key".to_owned(),
            signature_alg: SignatureAlg::Ed25519,
            signature: "signature".to_owned(),
        },
        envelope_id: "envelope".to_owned(),
        source_principal_id: "principal".to_owned(),
        source_device_id: "device".to_owned(),
        target_delivery_id: "target".to_owned(),
        routing_set_id: None,
        delivery_class: DeliveryClass::OpaqueEvent,
        priority: Priority::Low,
        ttl: MAX_EPHEMERAL_TTL_SECONDS,
        created_at: 1_000,
        encrypted_payload: "payload".to_owned(),
        payload_hash: "hash".to_owned(),
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
    }
}

pub(super) fn mutated(change: impl FnOnce(&mut Envelope)) -> Envelope {
    let mut envelope = valid_envelope();
    change(&mut envelope);
    envelope
}

pub(super) fn dropped_frame(
    frame: &ramflux_node_core::GatewayServerFrame,
    envelope_id: &str,
    reason: EphemeralDropReason,
) -> bool {
    matches!(
        frame,
        ramflux_node_core::GatewayServerFrame::EphemeralResult { envelope_id: id, result }
            if id == envelope_id
                && result.outcome() == EphemeralSubmitOutcome::Dropped
                && result.reason() == Some(reason)
    )
}

pub(super) fn accepted_frame(
    frame: &ramflux_node_core::GatewayServerFrame,
    envelope_id: &str,
) -> bool {
    matches!(
        frame,
        ramflux_node_core::GatewayServerFrame::EphemeralResult { envelope_id: id, result }
            if id == envelope_id
                && result.outcome() == EphemeralSubmitOutcome::Accepted
                && result.reason().is_none()
    )
}

async fn refuse_before_route(
    envelope: &Envelope,
    now_ms: u64,
    source: SourceCheck,
    negotiated: bool,
    reason: EphemeralDropReason,
) -> TestResult {
    let rate = EphemeralRate::default();
    let mut route = RouteRecorder::default();
    let mut enqueue = EnqueueRecorder::default();
    let frame = admit(Admission {
        negotiated,
        now_ms,
        envelope,
        source,
        rate: &rate,
        route: &mut route,
        enqueue: &mut enqueue,
    })
    .await;
    anyhow::ensure!(dropped_frame(&frame, &envelope.envelope_id, reason), "unexpected {frame:?}");
    anyhow::ensure!(route.calls.is_empty(), "router recorder saw {:?}", route.calls);
    anyhow::ensure!(enqueue.calls == 0, "enqueue called");
    Ok(())
}

fn pad_to_frame_size(target: usize) -> TestResult<Envelope> {
    let mut envelope = valid_envelope();
    envelope.encrypted_payload.clear();
    let empty = frame_bytes(&envelope, DEADLINE_MS).ok_or_else(|| anyhow::anyhow!("serialize"))?;
    anyhow::ensure!(empty.len() < target, "empty frame {} >= {target}", empty.len());
    envelope.encrypted_payload = "x".repeat(target - empty.len());
    let mut bytes =
        frame_bytes(&envelope, DEADLINE_MS).ok_or_else(|| anyhow::anyhow!("serialize"))?;
    while bytes.len() < target {
        envelope.encrypted_payload.push('x');
        bytes = frame_bytes(&envelope, DEADLINE_MS).ok_or_else(|| anyhow::anyhow!("serialize"))?;
    }
    while bytes.len() > target && !envelope.encrypted_payload.is_empty() {
        envelope.encrypted_payload.pop();
        bytes = frame_bytes(&envelope, DEADLINE_MS).ok_or_else(|| anyhow::anyhow!("serialize"))?;
    }
    anyhow::ensure!(bytes.len() == target, "sized frame is {} want {target}", bytes.len());
    Ok(envelope)
}

pub(super) async fn guard_10s<F: std::future::Future>(what: &str, future: F) -> F::Output {
    let finished = tokio::time::timeout(Duration::from_secs(10), future).await;
    assert!(finished.is_ok(), "{what} did not finish within 10s");
    match finished {
        Ok(output) => output,
        Err(_) => unreachable!("guarded by the assert above"),
    }
}

/// §9.2: burst 40, 41st rate-limited, 50 ms refill 1; ttl 0/6 before route; no second reply.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_admission_result() -> TestResult {
    wire_result_bytes()?;
    row_invalid_ttl_refuses_before_route().await?;
    row_burst_then_refill().await?;
    row_accepted_then_expired_no_second_reply().await?;
    row_source_and_mode_negatives().await?;
    row_priority_ttl_clock_negatives().await?;
    row_size_and_session_negatives().await?;
    row_positive_ttl_and_future_boundaries().await?;
    Ok(())
}

/// §9.2: stale signed input refused before router I/O; D exact; now==D expires.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_deadline() -> TestResult {
    row_stale_refused_before_route().await?;
    row_deadline_exact_on_route().await?;
    row_now_equals_deadline_expires().await?;
    Ok(())
}

fn wire_result_bytes() -> TestResult {
    let dropped = ramflux_node_core::GatewayServerFrame::EphemeralResult {
        envelope_id: "e1".to_owned(),
        result: EphemeralSubmitResult::dropped(EphemeralDropReason::RateLimited),
    };
    assert_eq!(
        serde_json::to_vec(&dropped)?,
        br#"{"frame_type":"ephemeral_result","envelope_id":"e1","outcome":"dropped","reason":"rate_limited"}"#
    );
    let accepted = ramflux_node_core::GatewayServerFrame::EphemeralResult {
        envelope_id: "e1".to_owned(),
        result: EphemeralSubmitResult::accepted(),
    };
    assert_eq!(
        serde_json::to_vec(&accepted)?,
        br#"{"frame_type":"ephemeral_result","envelope_id":"e1","outcome":"accepted"}"#
    );
    Ok(())
}

pub(super) async fn admit_ok(
    envelope: &Envelope,
    now_ms: u64,
    rate: &EphemeralRate,
    route: &mut RouteRecorder,
    enqueue: &mut EnqueueRecorder,
) -> ramflux_node_core::GatewayServerFrame {
    admit(Admission {
        negotiated: true,
        now_ms,
        envelope,
        source: SourceCheck::Ok,
        rate,
        route,
        enqueue,
    })
    .await
}

async fn row_burst_then_refill() -> TestResult {
    let rate = EphemeralRate::default();
    let mut route = RouteRecorder::default();
    let mut enqueue = EnqueueRecorder::default();
    for n in 0..EPHEMERAL_RATE_BURST {
        let envelope = mutated(|e| e.envelope_id = format!("burst-{n}"));
        let frame = admit_ok(&envelope, NOW_MS, &rate, &mut route, &mut enqueue).await;
        anyhow::ensure!(accepted_frame(&frame, &envelope.envelope_id), "burst {n}: {frame:?}");
    }
    anyhow::ensure!(route.calls.len() == EPHEMERAL_RATE_BURST as usize);
    let limited = mutated(|e| e.envelope_id = "burst-41".to_owned());
    let frame = admit_ok(&limited, NOW_MS, &rate, &mut route, &mut enqueue).await;
    anyhow::ensure!(dropped_frame(&frame, "burst-41", EphemeralDropReason::RateLimited));
    anyhow::ensure!(
        route.calls.len() == EPHEMERAL_RATE_BURST as usize,
        "41st submit must not call the router"
    );
    let refill = mutated(|e| e.envelope_id = "burst-refill".to_owned());
    let frame = admit_ok(&refill, NOW_MS + 50, &rate, &mut route, &mut enqueue).await;
    anyhow::ensure!(accepted_frame(&frame, "burst-refill"), "{frame:?}");
    anyhow::ensure!(route.calls.len() == EPHEMERAL_RATE_BURST as usize + 1);
    Ok(())
}

async fn row_invalid_ttl_refuses_before_route() -> TestResult {
    refuse_before_route(
        &mutated(|e| e.ttl = 0),
        NOW_MS,
        SourceCheck::Ok,
        true,
        EphemeralDropReason::Invalid,
    )
    .await?;
    refuse_before_route(
        &mutated(|e| e.ttl = 6),
        NOW_MS,
        SourceCheck::Ok,
        true,
        EphemeralDropReason::Invalid,
    )
    .await
}

async fn row_accepted_then_expired_no_second_reply() -> TestResult {
    use crate::session_push::tests::support::{ID, sink};
    let (closed, _) = tokio::sync::watch::channel(false);
    let queue = crate::push_queue::PushQueue::new(16, closed);
    queue.set_clock_ms(NOW_MS);
    let (send, frames) = sink();
    queue.install(&send, Some(ID.into())).await?;
    let envelope = valid_envelope();
    let rate = EphemeralRate::default();
    let mut route = RouteRecorder::default();
    let mut enqueue = QueueEnqueue { queue: queue.clone() };
    let frame = admit(Admission {
        negotiated: true,
        now_ms: NOW_MS,
        envelope: &envelope,
        source: SourceCheck::Ok,
        rate: &rate,
        route: &mut route,
        enqueue: &mut enqueue,
    })
    .await;
    anyhow::ensure!(accepted_frame(&frame, "envelope"));
    anyhow::ensure!(route.calls.len() == 1);
    queue.set_clock_ms(DEADLINE_MS);
    let worker = queue.clone();
    let handle = send.clone();
    tokio::spawn(async move {
        worker.run(handle, "target".into(), Some(ID.into())).await;
    });
    guard_10s("expiry flush", queue.flushed()).await?;
    anyhow::ensure!(
        frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.is_empty(),
        "expiry must not write the ephemeral frame"
    );
    anyhow::ensure!(accepted_frame(&frame, "envelope"), "no second ephemeral_result");
    Ok(())
}

struct QueueEnqueue {
    queue: crate::push_queue::PushQueue,
}

impl EphemeralEnqueue for QueueEnqueue {
    fn enqueue(
        &mut self,
        _target: &str,
        bytes: Vec<u8>,
        expires_at_ms: u64,
    ) -> impl std::future::Future<Output = TransientAdmission> + Send {
        std::future::ready(self.queue.try_push_transient(bytes, expires_at_ms))
    }
}

async fn invalid_before_route(change: impl FnOnce(&mut Envelope)) -> TestResult {
    refuse_before_route(
        &mutated(change),
        NOW_MS,
        SourceCheck::Ok,
        true,
        EphemeralDropReason::Invalid,
    )
    .await
}

async fn row_source_and_mode_negatives() -> TestResult {
    refuse_before_route(
        &valid_envelope(),
        NOW_MS,
        SourceCheck::Rejected,
        true,
        EphemeralDropReason::Invalid,
    )
    .await?;
    bind_source_mismatch_and_bad_signature()?;
    invalid_before_route(|e| {
        e.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("Ephemeral".to_owned()));
    })
    .await?;
    invalid_before_route(|e| {
        e.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String(String::new()));
    })
    .await?;
    invalid_before_route(|e| {
        e.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::Number(1.into()));
    })
    .await?;
    invalid_before_route(|e| {
        e.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::Null);
    })
    .await?;
    invalid_before_route(|e| {
        e.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), serde_json::json!({}));
    })
    .await
}

async fn row_priority_ttl_clock_negatives() -> TestResult {
    invalid_before_route(|e| e.priority = Priority::Normal).await?;
    invalid_before_route(|e| e.priority = Priority::High).await?;
    invalid_before_route(|e| e.priority = Priority::Urgent).await?;
    invalid_before_route(|e| e.ttl = u32::MAX).await?;
    refuse_before_route(
        &mutated(|e| {
            e.created_at = 1_002;
            e.ttl = 1;
        }),
        999_999,
        SourceCheck::Ok,
        true,
        EphemeralDropReason::Invalid,
    )
    .await?;
    invalid_before_route(|e| {
        e.created_at = i64::MAX;
        e.ttl = 5;
    })
    .await?;
    invalid_before_route(|e| {
        e.created_at = -2;
        e.ttl = 1;
    })
    .await
}

async fn row_size_and_session_negatives() -> TestResult {
    let oversized = pad_to_frame_size(EPHEMERAL_FRAME_CAP.saturating_add(1))?;
    refuse_before_route(&oversized, NOW_MS, SourceCheck::Ok, true, EphemeralDropReason::Invalid)
        .await?;
    let at_cap = pad_to_frame_size(EPHEMERAL_FRAME_CAP)?;
    let rate = EphemeralRate::default();
    let mut route = RouteRecorder::default();
    let mut enqueue = EnqueueRecorder::default();
    let frame = admit_ok(&at_cap, NOW_MS, &rate, &mut route, &mut enqueue).await;
    anyhow::ensure!(accepted_frame(&frame, &at_cap.envelope_id));
    anyhow::ensure!(route.calls.len() == 1);
    anyhow::ensure!(enqueue.last_bytes.as_ref().is_some_and(|b| b.len() == EPHEMERAL_FRAME_CAP));
    refuse_before_route(
        &valid_envelope(),
        NOW_MS,
        SourceCheck::Ok,
        false,
        EphemeralDropReason::Unsupported,
    )
    .await?;
    let _ = TRANSIENT_BYTE_CAP;
    let _ = MIN_EPHEMERAL_TTL_SECONDS;
    Ok(())
}

fn bind_source_mismatch_and_bad_signature() -> TestResult {
    let branch = ramflux_crypto::create_device_branch("alice", "shared", 1, [2; 32]);
    let authority = crate::submit_source::tests::authority(
        "alice",
        "shared",
        1,
        ramflux_crypto::public_key_base64url_from_seed([2; 32]),
        1,
    )?;
    let runtime = crate::GatewaySessionRuntime {
        session_push: None,
        ephemeral: false,
        push_limit: 256,
        source_identity: authority.authenticated_device_identity()?,
        session_id: "session".into(),
        resume_token: "resume".into(),
        principal_id: "alice".into(),
        device_id: "shared".into(),
        target_delivery_id: "source-delivery".into(),
        branch_public_key: authority.branch_public_key.clone(),
        device_epoch: 1,
        supports_forward_ack: false,
        ephemeral_rate: std::sync::Arc::default(),
    };
    let mut envelope = valid_envelope();
    envelope.source_principal_id = "alice".into();
    envelope.source_device_id = "shared".into();
    envelope.ext.ext.insert(
        "source_root_commitment".into(),
        serde_json::json!(runtime.source_identity.root_commitment()),
    );
    envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
        &branch,
    );
    anyhow::ensure!(crate::submit_source::bind_source(&runtime, &envelope).is_ok());
    let mut mismatch = envelope.clone();
    mismatch.source_principal_id = "mallory".into();
    anyhow::ensure!(
        crate::submit_source::bind_source(&runtime, &mismatch)
            .err()
            .map(|e| e.to_string())
            .as_deref()
            == Some("submit source differs from authenticated session")
    );
    let mut bad_sig = envelope;
    bad_sig.signed.signature = "invalid".into();
    anyhow::ensure!(
        crate::submit_source::bind_source(&runtime, &bad_sig)
            .err()
            .map(|e| e.to_string())
            .as_deref()
            == Some("base64url decode failed: Invalid last symbol 100, offset 6.")
    );
    Ok(())
}

async fn row_stale_refused_before_route() -> TestResult {
    refuse_before_route(
        &mutated(|e| {
            e.created_at = 1;
            e.ttl = 1;
        }),
        NOW_MS,
        SourceCheck::Ok,
        true,
        EphemeralDropReason::Expired,
    )
    .await
}

async fn row_deadline_exact_on_route() -> TestResult {
    let envelope = valid_envelope();
    let rate = EphemeralRate::default();
    let mut route = RouteRecorder::default();
    let mut enqueue = EnqueueRecorder::default();
    let frame = admit_ok(&envelope, NOW_MS, &rate, &mut route, &mut enqueue).await;
    anyhow::ensure!(accepted_frame(&frame, "envelope"));
    anyhow::ensure!(route.calls == vec![("envelope".to_owned(), DEADLINE_MS)]);
    Ok(())
}

async fn row_now_equals_deadline_expires() -> TestResult {
    refuse_before_route(
        &mutated(|e| {
            e.created_at = 1_000;
            e.ttl = 1;
        }),
        1_001_000,
        SourceCheck::Ok,
        true,
        EphemeralDropReason::Expired,
    )
    .await
}

/// ttl 1 is the smallest accepted lifetime and `created_at` may lead the clock by exactly 2000 ms.
async fn row_positive_ttl_and_future_boundaries() -> TestResult {
    let one_second = mutated(|e| {
        e.created_at = 1_000;
        e.ttl = 1;
    });
    let (mut route, mut enqueue) = (RouteRecorder::default(), EnqueueRecorder::default());
    let rate = EphemeralRate::default();
    let frame = admit_ok(&one_second, NOW_MS, &rate, &mut route, &mut enqueue).await;
    anyhow::ensure!(accepted_frame(&frame, "envelope"), "{frame:?}");
    anyhow::ensure!(route.calls == vec![("envelope".to_owned(), 1_001_000)], "{:?}", route.calls);

    // created_at 1,000 s is 1,000,000 ms: exactly now + 2000 ms is accepted, +2001 is refused.
    let (mut route, mut enqueue) = (RouteRecorder::default(), EnqueueRecorder::default());
    let rate = EphemeralRate::default();
    let at_tolerance = valid_envelope();
    let frame = admit_ok(&at_tolerance, 998_000, &rate, &mut route, &mut enqueue).await;
    anyhow::ensure!(accepted_frame(&frame, "envelope"), "{frame:?}");
    anyhow::ensure!(route.calls.len() == 1);
    refuse_before_route(&at_tolerance, 997_999, SourceCheck::Ok, true, EphemeralDropReason::Invalid)
        .await
}
