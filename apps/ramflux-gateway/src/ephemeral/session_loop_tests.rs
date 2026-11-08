// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! S6c P09 r3: the REAL session loop never changes checkpointed gateway state for a non-durable
//! submit (I-NP), and a same-session resume keeps the session's volatile ephemeral rate bucket.

use super::handler_tests::{accepted, dropped, now_ms, submit};
use super::tests::{EnqueueRecorder, RouteRecorder, TestResult, admit_ok, guard_10s, mutated};
use super::{
    EPHEMERAL_RATE_BURST, EPHEMERAL_RATE_FULL_REFILL_MS, EphemeralRate, EphemeralRateRegistry,
};
use crate::session::submit_fixtures::test_runtime;
use crate::session_push::tests::support::{Fixture, ID, Sink, Source, sink};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// Serialized persisted (reloaded from the store) and in-memory gateway state after an
/// ordinary durable save, which is what any later durable request does.
/// Independent literal of P03's live refusal frame (not derived from `durable_mode`).
fn p03_nack() -> serde_json::Value {
    json!({"frame_type":"nack","reason":"delivery_mode_refused"})
}

fn persisted(context: &crate::GatewayQuicContext) -> TestResult<Vec<u8>> {
    {
        let state = crate::gateway_state(&context.state)?;
        context.store.save_state(&state)?;
    }
    let reloaded = context.store.load_state()?;
    let memory = crate::gateway_state(&context.state)?.clone();
    Ok(serde_json::to_vec(&(reloaded, memory))?)
}

fn frame_bytes(frame: &ramflux_node_core::GatewayClientFrame) -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(frame)?)
}

/// Run the real session loop over `frames`; answer a router call if `route_reply` is given.
async fn run_loop(
    fixture: &mut Fixture,
    runtime: &crate::GatewaySessionRuntime,
    frames: Vec<Vec<u8>>,
    route_reply: Option<Value>,
) -> TestResult<Vec<Value>> {
    let (send, written) = sink();
    let recv = Box::new(Source(frames.into()));
    let task = tokio::spawn(crate::session::run_gateway_session_loop_until_closed(
        send,
        recv,
        fixture.context.clone(),
        runtime.clone(),
        None,
        None,
    ));
    if let Some(reply) = route_reply {
        let request = fixture.next().await?;
        anyhow::ensure!(request.path == "/mvp0/envelope-ephemeral", "{}", request.path);
        request.respond.send((200, reply)).map_err(|_| anyhow::anyhow!("router gone"))?;
    }
    guard_10s("session loop", task).await??;
    let frames = written.lock().map_err(|_| anyhow::anyhow!("frames"))?.clone();
    Ok(frames)
}

fn submit_frame(
    submit: ramflux_node_core::GatewaySubmitFrame,
) -> ramflux_node_core::GatewayClientFrame {
    ramflux_node_core::GatewayClientFrame::Submit { submit }
}

/// I-NP at the session boundary: accepted, admission-refused (ttl=0), invalid-mode and
/// not-negotiated non-durable submits leave persisted state byte-identical; a durable
/// request through the same loop does change it.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_session_loop_persists_nothing() -> TestResult {
    let mut fixture = Fixture::new("p09-session-loop")?;
    let mut runtime = test_runtime()?;
    runtime.ephemeral = true;
    let context = fixture.context.clone();
    // The addressee is live on this gateway, so an accepted ephemeral really enqueues.
    let (target_send, _target_frames) = sink();
    let _registration =
        context.hub.register("alice-target".into(), "peer-session".into(), target_send).await?;
    let baseline = persisted(&context)?;
    let online = json!({"outcome":"online","gateway_id":"ramflux-gateway"});

    let ok = submit(&runtime, "loop-accepted", 5, |_| {})?;
    let written =
        run_loop(&mut fixture, &runtime, vec![frame_bytes(&submit_frame(ok))?], Some(online))
            .await?;
    anyhow::ensure!(written == vec![accepted("loop-accepted")], "{written:?}");
    anyhow::ensure!(persisted(&context)? == baseline, "accepted ephemeral changed state");

    let zero = submit(&runtime, "loop-ttl0", 0, |_| {})?;
    let written =
        run_loop(&mut fixture, &runtime, vec![frame_bytes(&submit_frame(zero))?], None).await?;
    anyhow::ensure!(written == vec![dropped("loop-ttl0", "invalid")], "{written:?}");
    anyhow::ensure!(persisted(&context)? == baseline, "ttl=0 ephemeral changed state");

    let bad_mode = submit(&runtime, "loop-mode", 5, |e| {
        e.ext.ext.insert(
            ramflux_protocol::ephemeral::DELIVERY_MODE_EXTENSION.to_owned(),
            json!("Ephemeral"),
        );
    })?;
    let written =
        run_loop(&mut fixture, &runtime, vec![frame_bytes(&submit_frame(bad_mode))?], None).await?;
    // Controller ruling: an unknown mode string is P03's live refusal even when negotiated.
    anyhow::ensure!(written == vec![p03_nack()], "{written:?}");
    anyhow::ensure!(persisted(&context)? == baseline, "invalid-mode submit changed state");

    runtime.ephemeral = false;
    let off = submit(&runtime, "loop-unsupported", 5, |_| {})?;
    let written =
        run_loop(&mut fixture, &runtime, vec![frame_bytes(&submit_frame(off))?], None).await?;
    anyhow::ensure!(written == vec![p03_nack()], "{written:?}");
    anyhow::ensure!(persisted(&context)? == baseline, "not-negotiated ephemeral changed state");

    // Control: an ordinary durable-class request through the same loop does change it.
    let heartbeat = ramflux_node_core::GatewayClientFrame::Heartbeat { now: 1 };
    let written = run_loop(&mut fixture, &runtime, vec![frame_bytes(&heartbeat)?], None).await?;
    anyhow::ensure!(written.len() == 1, "{written:?}");
    anyhow::ensure!(persisted(&context)? != baseline, "control: durable request left no mark");
    Ok(())
}

fn open_frame(previous: Option<(&str, &str)>) -> TestResult<ramflux_node_core::GatewayOpenFrame> {
    let (session, hash) =
        previous.map_or((Value::Null, Value::Null), |(s, h)| (json!(s), json!(h)));
    Ok(serde_json::from_value(json!({
        "protocol_version":ramflux_node_core::GATEWAY_SESSION_PROTOCOL_VERSION,
        "transport_kind":"quic_quinn","client_instance_id":"client","device_id":"device",
        "target_delivery_id":"target","stream_nonce":"nonce","previous_session_id":session,
        "resume_token_hash":hash,"last_seen_inbox_seq":null,"max_inflight_downstream":64,
        "max_inflight_upstream":4,"pre_auth_cookie":null,"pre_auth_now":null,"source_ip_hash":null
    }))?)
}

fn auth_frame() -> TestResult<ramflux_node_core::GatewayAuthFrame> {
    Ok(serde_json::from_value(json!({
        "signed_request":{"schema":"ramflux.signed_request.v1","version":1,"domain":"ramflux.signed_request.v1","signing_key_id":"device","signature_alg":"ed25519","signature":"fixture","source_device_id":"device","request_id":"open","method":"POST","path":"/gateway/open","device_proof_hash":"hash","body_hash":"hash","nonce":"nonce","created_at":1,"expires_at":2},
        "device_proof":{"schema":"ramflux.device_proof.v1","version":1,"domain":"ramflux.device_proof.v1","signing_key_id":"device","signature_alg":"ed25519","signature":"fixture","principal_id":"principal","device_id":"device","device_epoch":1,"branch_proof_hash":"hash","capability_scope":[],"nonce":"nonce","expires_at":2}
    }))?)
}

/// Establish (or resume) through the real `establish_gateway_session`, answering its router calls.
async fn establish(
    fixture: &mut Fixture,
    open: ramflux_node_core::GatewayOpenFrame,
) -> TestResult<crate::GatewaySessionRuntime> {
    fixture.context.hub.readiness.suppress_discovery_for_test();
    let context = fixture.context.clone();
    let source = crate::session_push::tests::support::runtime()?.source_identity;
    let key = ramflux_node_core::DeviceAuthKeyResponse {
        custody_authority: None,
        root_public_key: None,
        signed_device_set: None,
        principal_id: "principal".into(),
        device_id: "device".into(),
        device_epoch: 1,
        branch_public_key: "branch".into(),
        target_delivery_id: "target".into(),
        revoked: false,
    };
    let auth = auth_frame()?;
    let task = tokio::spawn(async move {
        let mut send = Sink(Arc::new(Mutex::new(Vec::new())));
        crate::session::establish_gateway_session(&mut send, &context, &open, &auth, key, source)
            .await
    });
    let upsert = fixture.next().await?;
    anyhow::ensure!(upsert.path == "/s1/session/upsert", "{}", upsert.path);
    let echo = upsert.body.clone();
    upsert.respond.send((200, echo)).map_err(|_| anyhow::anyhow!("router gone"))?;
    let cursor = fixture.next().await?;
    anyhow::ensure!(cursor.path == "/mvp0/cursor/target", "{}", cursor.path);
    cursor.respond.send((200, Value::Null)).map_err(|_| anyhow::anyhow!("router gone"))?;
    guard_10s("establish", task).await?
}

/// Real establishment: `runtime.ephemeral` is the router's capability echo, not a test latch.
async fn establish_echoed(
    fixture: &mut Fixture,
    session_push: bool,
    ephemeral: bool,
) -> TestResult<crate::GatewaySessionRuntime> {
    establish_echoed_auth(
        fixture,
        session_push,
        ephemeral,
        crate::session_push::tests::negotiation::auth(session_push)?,
    )
    .await
}

async fn establish_echoed_auth(
    fixture: &mut Fixture,
    session_push: bool,
    ephemeral: bool,
    auth: ramflux_node_core::GatewayAuthFrame,
) -> TestResult<crate::GatewaySessionRuntime> {
    fixture.context.hub.readiness.seed_echo_for_test(session_push, ephemeral);
    let context = fixture.context.clone();
    let source = crate::session_push::tests::support::runtime()?.source_identity;
    let key = ramflux_node_core::DeviceAuthKeyResponse {
        custody_authority: None,
        root_public_key: None,
        signed_device_set: None,
        principal_id: "principal".into(),
        device_id: "device".into(),
        device_epoch: 1,
        branch_public_key: "branch".into(),
        target_delivery_id: "target".into(),
        revoked: false,
    };
    let open = open_frame(None)?;
    let task = tokio::spawn(async move {
        let mut send = Sink(Arc::new(Mutex::new(Vec::new())));
        crate::session::establish_gateway_session(&mut send, &context, &open, &auth, key, source)
            .await
    });
    let req = fixture.next().await?;
    let reply = if req.path == "/s1/session" {
        let mut reply = req.body.clone();
        reply["incarnation_id"] = json!(ID);
        reply
    } else {
        req.body.clone()
    };
    req.respond.send((200, reply)).map_err(|_| anyhow::anyhow!("router gone"))?;
    let cursor = fixture.next().await?;
    anyhow::ensure!(cursor.path == "/mvp0/cursor/target", "{}", cursor.path);
    cursor.respond.send((200, Value::Null)).map_err(|_| anyhow::anyhow!("router gone"))?;
    guard_10s("establish echoed", task).await?
}

/// Router does not advertise `gateway.ephemeral.v1` → P03 nack; advertised → ephemeral path.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_submit_follows_router_advertisement() -> TestResult {
    let mut no_ad = Fixture::new("pre16-no-advertise")?;
    let runtime = establish_echoed(&mut no_ad, true, false).await?;
    anyhow::ensure!(!runtime.ephemeral);
    anyhow::ensure!(!crate::ephemeral::negotiated(&runtime));
    let off = submit(&runtime, "no-advertise", 5, |_| {})?;
    let written =
        run_loop(&mut no_ad, &runtime, vec![frame_bytes(&submit_frame(off))?], None).await?;
    anyhow::ensure!(written == vec![p03_nack()], "{written:?}");

    let mut advertised = Fixture::new("pre16-advertise")?;
    let runtime = establish_echoed(&mut advertised, true, true).await?;
    anyhow::ensure!(runtime.ephemeral);
    anyhow::ensure!(crate::ephemeral::negotiated(&runtime));
    let ok = submit(&runtime, "did-advertise", 5, |_| {})?;
    // Establishment fixture identities differ from the P09 submit helper, so admission
    // refuses as invalid; the frame is still the ephemeral result, never P03's nack.
    let written =
        run_loop(&mut advertised, &runtime, vec![frame_bytes(&submit_frame(ok))?], None).await?;
    anyhow::ensure!(written == vec![dropped("did-advertise", "invalid")], "{written:?}");
    Ok(())
}

/// Client `capability_scope` claiming `gateway.ephemeral.v1` cannot flip the flag when the
/// router does not advertise it. Submit is P03's exact nack; persisted state is unchanged.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_client_claim_without_router_advertise_is_p03() -> TestResult {
    let mut fixture = Fixture::new("pre16-forged-cap")?;
    let auth = crate::session_push::tests::negotiation::auth_claiming_ephemeral(true)?;
    anyhow::ensure!(
        auth.device_proof
            .capability_scope
            .iter()
            .any(|c| c == ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY)
    );
    let runtime = establish_echoed_auth(&mut fixture, true, false, auth).await?;
    anyhow::ensure!(!runtime.ephemeral);
    anyhow::ensure!(!crate::ephemeral::negotiated(&runtime));
    let baseline = persisted(&fixture.context)?;
    let off = submit(&runtime, "forged-cap", 5, |_| {})?;
    let written =
        run_loop(&mut fixture, &runtime, vec![frame_bytes(&submit_frame(off))?], None).await?;
    anyhow::ensure!(written == vec![p03_nack()], "{written:?}");
    anyhow::ensure!(persisted(&fixture.context)? == baseline, "forged claim changed state");
    Ok(())
}

async fn admit_n(
    runtime: &crate::GatewaySessionRuntime,
    count: u32,
    at_ms: u64,
    route: &mut RouteRecorder,
    first_id: u32,
) -> TestResult<Vec<ramflux_node_core::GatewayServerFrame>> {
    let mut enqueue = EnqueueRecorder::default();
    let mut frames = Vec::new();
    for n in 0..count {
        let envelope = mutated(|e| {
            e.envelope_id = format!("resume-{}", first_id + n);
            // Created at the controlled instant so admission sees a live five-second lifetime.
            e.created_at = i64::try_from(at_ms / 1_000).unwrap_or(i64::MAX);
        });
        frames.push(admit_ok(&envelope, at_ms, &runtime.ephemeral_rate, route, &mut enqueue).await);
    }
    Ok(frames)
}

/// M1: exhaust the bucket, really resume the same session ID, and the burst is still spent;
/// normal refill still works.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_rate_survives_same_session_resume() -> TestResult {
    let mut fixture = Fixture::new("p09-resume")?;
    let first = establish(&mut fixture, open_frame(None)?).await?;
    // Future-based instants keep the volatile bucket live whatever the wall clock does.
    let at = now_ms() + 3_600_000;
    let mut route = RouteRecorder::default();
    let burst = admit_n(&first, EPHEMERAL_RATE_BURST, at, &mut route, 0).await?;
    anyhow::ensure!(burst.iter().all(|f| matches!(f,
        ramflux_node_core::GatewayServerFrame::EphemeralResult { result, .. }
            if result.outcome() == ramflux_protocol::ephemeral::EphemeralSubmitOutcome::Accepted)));
    anyhow::ensure!(route.calls.len() == EPHEMERAL_RATE_BURST as usize);

    let hash = ramflux_node_core::gateway_resume_token_hash(&first.resume_token);
    let resumed =
        establish(&mut fixture, open_frame(Some((first.session_id.as_str(), hash.as_str())))?)
            .await?;
    anyhow::ensure!(resumed.session_id == first.session_id, "not a same-session resume");

    let limited = admit_n(&resumed, 1, at, &mut route, 100).await?;
    anyhow::ensure!(
        super::tests::dropped_frame(
            &limited[0],
            "resume-100",
            ramflux_protocol::ephemeral::EphemeralDropReason::RateLimited
        ),
        "{limited:?}"
    );
    anyhow::ensure!(route.calls.len() == EPHEMERAL_RATE_BURST as usize, "resume re-armed burst");
    let refilled = admit_n(&resumed, 1, at + 50, &mut route, 200).await?;
    anyhow::ensure!(super::tests::accepted_frame(&refilled[0], "resume-200"), "{refilled:?}");

    // A different session ID gets its own full bucket.
    anyhow::ensure!(Arc::ptr_eq(&first.ephemeral_rate, &resumed.ephemeral_rate));
    let other = establish(&mut fixture, open_frame(None)?).await?;
    anyhow::ensure!(other.session_id != first.session_id);
    anyhow::ensure!(!Arc::ptr_eq(&other.ephemeral_rate, &first.ephemeral_rate));
    Ok(())
}

/// r4 row 1, the reviewer's interleaving: A, then B (which used to evict A's never-used entry),
/// A spends its burst, a real resume of A still finds it spent.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_rate_survives_other_establishment() -> TestResult {
    let mut fixture = Fixture::new("p09-interleave")?;
    let a = establish(&mut fixture, open_frame(None)?).await?;
    let b = establish(&mut fixture, open_frame(None)?).await?;
    anyhow::ensure!(a.session_id != b.session_id);
    anyhow::ensure!(fixture.context.hub.ephemeral_rates.len() == 2);
    let at = now_ms() + 3_600_000;
    let mut route = RouteRecorder::default();
    admit_n(&a, EPHEMERAL_RATE_BURST, at, &mut route, 0).await?;
    let hash = ramflux_node_core::gateway_resume_token_hash(&a.resume_token);
    let resumed =
        establish(&mut fixture, open_frame(Some((a.session_id.as_str(), hash.as_str())))?).await?;
    anyhow::ensure!(resumed.session_id == a.session_id);
    anyhow::ensure!(Arc::ptr_eq(&a.ephemeral_rate, &resumed.ephemeral_rate), "A's entry was lost");
    let limited = admit_n(&resumed, 1, at, &mut route, 100).await?;
    anyhow::ensure!(
        super::tests::dropped_frame(
            &limited[0],
            "resume-100",
            ramflux_protocol::ephemeral::EphemeralDropReason::RateLimited
        ),
        "{limited:?}"
    );
    anyhow::ensure!(route.calls.len() == EPHEMERAL_RATE_BURST as usize);
    drop(b);
    Ok(())
}

async fn exhaust(bucket: &EphemeralRate, at_ms: u64) -> TestResult {
    for _ in 0..EPHEMERAL_RATE_BURST {
        anyhow::ensure!(bucket.lock().await.try_acquire(at_ms));
    }
    anyhow::ensure!(!bucket.lock().await.try_acquire(at_ms));
    Ok(())
}

async fn admitted(bucket: &EphemeralRate, at_ms: u64) -> u32 {
    let mut count = 0;
    while bucket.lock().await.try_acquire(at_ms) {
        count += 1;
    }
    count
}

/// r4 row 2: an owned entry is never evicted, however idle; time alone decides what it admits.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_rate_owned_entry_is_never_evicted() -> TestResult {
    let registry = EphemeralRateRegistry::default();
    let base = 10_000_u64;
    let owned = registry.bucket("session", base);
    exhaust(&owned, base).await?;
    // Not yet refilled (500 ms = 10 tokens): kept, and exactly the refilled tokens are admitted.
    anyhow::ensure!(Arc::ptr_eq(&registry.bucket("session", base + 500), &owned));
    anyhow::ensure!(admitted(&owned, base + 500).await == 10);
    // Idle far past the refill bound while owned: still the same entry, exactly 40 admitted.
    let idle = base + 500 + 5 * EPHEMERAL_RATE_FULL_REFILL_MS;
    anyhow::ensure!(Arc::ptr_eq(&registry.bucket("session", idle), &owned));
    registry.sweep(idle);
    anyhow::ensure!(registry.len() == 1);
    anyhow::ensure!(admitted(&owned, idle).await == EPHEMERAL_RATE_BURST);
    Ok(())
}

/// r4 rows 3 and 4: an orphan is removed only once refilled.
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_rate_orphan_removed_only_when_refilled() -> TestResult {
    let registry = EphemeralRateRegistry::default();
    let base = 10_000_u64;
    let spent = registry.bucket("spent", base);
    exhaust(&spent, base).await?;
    drop(spent);
    let never_used = registry.bucket("never-used", base);
    drop(never_used);
    anyhow::ensure!(registry.len() == 2);
    // Row 4: the spent orphan is kept until it would be full; the never-used one is already full.
    registry.sweep(base + EPHEMERAL_RATE_FULL_REFILL_MS - 1);
    anyhow::ensure!(registry.len() == 1, "kept {}", registry.len());
    // Row 3: refilled and orphaned, so it is removed and the size drops.
    registry.sweep(base + EPHEMERAL_RATE_FULL_REFILL_MS);
    anyhow::ensure!(registry.len() == 0);
    // A lookup afterwards creates a fresh, full bucket.
    let fresh = registry.bucket("spent", base + EPHEMERAL_RATE_FULL_REFILL_MS);
    anyhow::ensure!(
        admitted(&fresh, base + EPHEMERAL_RATE_FULL_REFILL_MS).await == EPHEMERAL_RATE_BURST
    );
    Ok(())
}
