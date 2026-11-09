// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway ephemeral echo, resume rewrite of C1, and boot-change re-assertion.
use super::*;
use ramflux_node_core::{
    EphemeralRegistrationItem, EphemeralRouteGate, RouterCore, SessionDescriptor,
    SessionPushSessionRequest, gateway_resume_token_hash,
};
use ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY;
use std::sync::Arc;
use support::{Fixture, ID, runtime, sink};

const TARGET: &str = "target";
const GATEWAY: &str = "ramflux-gateway";
const SESSION_PUSH: &str = ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY;

type TestResult = anyhow::Result<()>;

#[allow(clippy::panic, reason = "test hang guard must fail with the awaited event")]
async fn guard_10s<F: std::future::Future>(event: &str, future: F) -> F::Output {
    match tokio::time::timeout(std::time::Duration::from_secs(10), future).await {
        Ok(output) => output,
        Err(elapsed) => panic!("timed out waiting for {event} after 10s: {elapsed}"),
    }
}

fn session_push_auth() -> anyhow::Result<ramflux_node_core::GatewayAuthFrame> {
    super::negotiation::auth(true)
}

fn device_key() -> ramflux_node_core::DeviceAuthKeyResponse {
    ramflux_node_core::DeviceAuthKeyResponse {
        custody_authority: None,
        root_public_key: None,
        signed_device_set: None,
        principal_id: "principal".into(),
        device_id: "device".into(),
        device_epoch: 1,
        branch_public_key: "branch".into(),
        target_delivery_id: TARGET.into(),
        revoked: false,
    }
}

fn open_frame(
    previous_session_id: Option<&str>,
    resume_token_hash: Option<&str>,
) -> anyhow::Result<ramflux_node_core::GatewayOpenFrame> {
    Ok(serde_json::from_value(json!({
        "protocol_version": ramflux_node_core::GATEWAY_SESSION_PROTOCOL_VERSION,
        "transport_kind": "quic_quinn",
        "client_instance_id": "client",
        "device_id": "device",
        "target_delivery_id": TARGET,
        "stream_nonce": "nonce",
        "previous_session_id": previous_session_id,
        "resume_token_hash": resume_token_hash,
        "last_seen_inbox_seq": null,
        "max_inflight_downstream": 32,
        "max_inflight_upstream": 4,
        "pre_auth_cookie": null,
        "pre_auth_now": null,
        "source_ip_hash": null
    }))?)
}

fn apply_router(router: &RouterCore, path: &str, body: &Value) -> TestResult {
    if path == "/s1/session" {
        let request: SessionPushSessionRequest = serde_json::from_value(body.clone())?;
        router.clear_ephemeral_capability(&request.session.target_delivery_id);
        router.upsert_session(request.session.clone())?;
        router.mark_live(&request.session.target_delivery_id)?;
        if request.ephemeral {
            router.bind_ephemeral_capability(
                &request.session.target_delivery_id,
                &request.session.gateway_id,
                &request.session.session_id,
            );
        }
    } else if path == "/s1/session/upsert" {
        let descriptor: SessionDescriptor = serde_json::from_value(body.clone())?;
        router.clear_ephemeral_capability(&descriptor.target_delivery_id);
        router.upsert_session(descriptor.clone())?;
        router.mark_live(&descriptor.target_delivery_id)?;
    } else {
        anyhow::bail!("unexpected establishment path {path}");
    }
    Ok(())
}

fn capable_reply(body: &Value) -> Value {
    let mut reply = body.clone();
    reply["incarnation_id"] = json!(ID);
    reply
}

fn seed_echo(fixture: &Fixture, session_push: bool, ephemeral: bool) {
    fixture.context.hub.readiness.seed_echo_for_test(session_push, ephemeral);
}

async fn establish(
    fixture: &mut Fixture,
    router: &RouterCore,
    previous_session_id: Option<&str>,
    resume_token_hash: Option<&str>,
) -> anyhow::Result<(crate::GatewaySessionRuntime, Vec<Value>, String)> {
    let context = fixture.context.clone();
    let auth = session_push_auth()?;
    let source = runtime()?.source_identity;
    let open = open_frame(previous_session_id, resume_token_hash)?;
    let key = device_key();
    let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = frames.clone();
    let task = tokio::spawn(async move {
        let mut send = support::Sink(captured);
        crate::session::establish_gateway_session(&mut send, &context, &open, &auth, key, source)
            .await
    });
    let req = fixture.next().await?;
    let path = req.path.clone();
    apply_router(router, &path, &req.body)?;
    let reply = if path == "/s1/session" { capable_reply(&req.body) } else { req.body.clone() };
    req.respond.send((200, reply)).map_err(|_| Retired)?;
    let cursor = fixture.next().await?;
    anyhow::ensure!(cursor.path == format!("/mvp0/cursor/{TARGET}"), "{}", cursor.path);
    cursor.respond.send((200, Value::Null)).map_err(|_| Retired)?;
    let runtime = guard_10s("ephemeral session establishment task", task).await??;
    let rows = frames.lock().map_err(|_| Retired)?.clone();
    Ok((runtime, rows, path))
}

fn assert_online(router: &RouterCore, session_id: &str) {
    assert_eq!(
        router.route_gate(TARGET),
        EphemeralRouteGate::Online { gateway_id: GATEWAY.into(), session_id: session_id.into() }
    );
}

fn assert_unsupported(router: &RouterCore) {
    assert_eq!(router.route_gate(TARGET), EphemeralRouteGate::RecipientUnsupported);
}

fn capabilities_of(frame: &Value) -> Option<&Value> {
    frame.get("session").and_then(|session| session.get("capabilities"))
}

fn established_frame() -> ramflux_node_core::GatewaySessionEstablishedFrame {
    ramflux_node_core::GatewaySessionEstablishedFrame {
        session_id: "session".into(),
        gateway_id: GATEWAY.into(),
        accepted_cursor: None,
        resume_token: "resume".into(),
        resume_window_seconds: 300,
    }
}

async fn negotiate_on(
    fixture: &mut Fixture,
    ephemeral: bool,
) -> anyhow::Result<(NegotiatedBinding, String, Value)> {
    let context = fixture.context.clone();
    let auth = session_push_auth()?;
    let descriptor = super::negotiation::descriptor();
    let task = tokio::spawn(async move { negotiate(&context, &auth, &descriptor).await });
    let req = fixture.next().await?;
    let path = req.path.clone();
    let body = req.body.clone();
    let reply = if path == "/s1/session" {
        assert_eq!(body["session_push"], true);
        assert_eq!(body["ephemeral"], ephemeral);
        capable_reply(&body)
    } else {
        body.clone()
    };
    req.respond.send((200, reply)).map_err(|_| Retired)?;
    let binding = guard_10s("ephemeral negotiation task", task).await??;
    Ok((binding, path, body))
}

async fn echo_caps(id: Option<&str>, ephemeral: bool) -> anyhow::Result<Value> {
    let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    established(&mut support::Sink(frames.clone()), established_frame(), id, ephemeral).await?;
    Ok(frames.lock().map_err(|_| Retired)?[0].clone())
}

async fn row_both_echoed() -> TestResult {
    let mut fixture = Fixture::new("p10-negotiation")?;
    seed_echo(&fixture, true, true);
    let (binding, path, _) = negotiate_on(&mut fixture, true).await?;
    assert_eq!(path, "/s1/session");
    assert_eq!(binding.incarnation_id.as_deref(), Some(ID));
    assert!(binding.ephemeral);
    let (send, _) = sink();
    fixture
        .context
        .hub
        .register_ephemeral(
            TARGET.into(),
            "session".into(),
            send,
            binding.incarnation_id.clone(),
            32,
        )
        .await?;
    assert_eq!(fixture.context.hub.ephemeral_flag(TARGET).await, Some(true));
    let echoed = echo_caps(binding.incarnation_id.as_deref(), binding.ephemeral).await?;
    assert_eq!(
        capabilities_of(&echoed),
        Some(&json!([SESSION_PUSH, GATEWAY_EPHEMERAL_CAPABILITY]))
    );
    Ok(())
}

async fn row_session_push_only() -> TestResult {
    let mut fixture = Fixture::new("p10-negotiation-session-push-only")?;
    seed_echo(&fixture, true, false);
    let (binding, path, _) = negotiate_on(&mut fixture, false).await?;
    assert_eq!(path, "/s1/session");
    assert!(!binding.ephemeral);
    let echoed = echo_caps(binding.incarnation_id.as_deref(), binding.ephemeral).await?;
    assert_eq!(capabilities_of(&echoed), Some(&json!([SESSION_PUSH])));
    Ok(())
}

async fn row_ephemeral_without_session_push() -> TestResult {
    let mut fixture = Fixture::new("p10-negotiation-ephemeral-without-session-push")?;
    fixture.context.hub.readiness.start_with_hub(
        &fixture.context.router,
        &fixture.context.hub,
        &fixture.context.gateway_id,
    );
    let discovery = fixture.next().await?;
    assert_eq!(discovery.path, "/mvp1/session-push-capabilities");
    discovery
        .respond
        .send((200, json!({"capabilities":[GATEWAY_EPHEMERAL_CAPABILITY],"router_boot_id":"boot"})))
        .map_err(|_| Retired)?;
    tokio::task::yield_now().await;
    assert!(!fixture.context.hub.readiness.supports());
    assert!(!fixture.context.hub.readiness.supports_ephemeral());
    let (binding, path, _) = negotiate_on(&mut fixture, false).await?;
    assert_eq!(path, "/s1/session/upsert");
    assert_eq!(binding.incarnation_id, None);
    assert!(!binding.ephemeral);
    let legacy = echo_caps(binding.incarnation_id.as_deref(), true).await?;
    assert!(capabilities_of(&legacy).is_none());
    Ok(())
}

fn row_recognizer() -> TestResult {
    for frame in [
        json!({"frame_type":"fetch_entry","incarnation_id":ID,"inbox_seq":1}),
        json!({"frame_type":"ack_batch","incarnation_id":ID,"inbox_seqs":[1]}),
        json!({"frame_type":"resume","incarnation_id":ID,"resume":{}}),
        json!({"frame_type":"ack","incarnation_id":ID}),
        json!({"frame_type":"nack","incarnation_id":ID}),
    ] {
        let bytes = serde_json::to_vec(&frame)?;
        assert!(!recognizes(&bytes, false), "{}", frame["frame_type"]);
        assert!(recognizes(&bytes, true), "{}", frame["frame_type"]);
    }
    Ok(())
}

#[tokio::test]
async fn ephemeral_capability_negotiation() -> TestResult {
    row_both_echoed().await?;
    row_session_push_only().await?;
    row_ephemeral_without_session_push().await?;
    row_recognizer()?;
    Ok(())
}

async fn row_resume_withdraws_capability() -> TestResult {
    let mut fixture = Fixture::new("p10-resume-withdraw")?;
    seed_echo(&fixture, true, true);
    let router = RouterCore::new();
    let (first, _, path) = establish(&mut fixture, &router, None, None).await?;
    assert_eq!(path, "/s1/session");
    assert!(first.ephemeral);
    assert_online(&router, &first.session_id);
    seed_echo(&fixture, true, false);
    let hash = gateway_resume_token_hash(&first.resume_token);
    let (resumed, frames, path) =
        establish(&mut fixture, &router, Some(&first.session_id), Some(&hash)).await?;
    assert_eq!(path, "/s1/session");
    assert!(!resumed.ephemeral);
    assert_eq!(resumed.session_id, first.session_id);
    assert_unsupported(&router);
    assert_eq!(capabilities_of(&frames[0]), Some(&json!([SESSION_PUSH])));
    assert!(fixture.requests.try_recv().is_err(), "zero forwards after withdrawn capability");
    Ok(())
}

async fn establish_legacy(
    fixture: &mut Fixture,
    router: &RouterCore,
) -> anyhow::Result<crate::GatewaySessionRuntime> {
    let context = fixture.context.clone();
    let auth = super::negotiation::auth(false)?;
    let source = runtime()?.source_identity;
    let open = open_frame(None, None)?;
    let key = device_key();
    let task = tokio::spawn(async move {
        let mut send = support::Sink(Arc::new(std::sync::Mutex::new(Vec::new())));
        crate::session::establish_gateway_session(&mut send, &context, &open, &auth, key, source)
            .await
    });
    let req = fixture.next().await?;
    assert_eq!(req.path, "/s1/session/upsert");
    apply_router(router, &req.path, &req.body)?;
    req.respond.send((200, req.body.clone())).map_err(|_| Retired)?;
    let cursor = fixture.next().await?;
    cursor.respond.send((200, Value::Null)).map_err(|_| Retired)?;
    guard_10s("legacy session establishment task", task).await?
}

async fn row_resume_grants_capability() -> TestResult {
    let mut fixture = Fixture::new("p10-resume-grant")?;
    seed_echo(&fixture, false, false);
    let router = RouterCore::new();
    let legacy = establish_legacy(&mut fixture, &router).await?;
    assert!(!legacy.ephemeral);
    assert_unsupported(&router);
    seed_echo(&fixture, true, true);
    let hash = gateway_resume_token_hash(&legacy.resume_token);
    let (capable, frames, path) =
        establish(&mut fixture, &router, Some(&legacy.session_id), Some(&hash)).await?;
    assert_eq!(path, "/s1/session");
    assert!(capable.ephemeral);
    assert_eq!(capable.session_id, legacy.session_id);
    assert_online(&router, &capable.session_id);
    assert_eq!(
        capabilities_of(&frames[0]),
        Some(&json!([SESSION_PUSH, GATEWAY_EPHEMERAL_CAPABILITY]))
    );
    Ok(())
}

async fn row_resume_without_echo_sends_false() -> TestResult {
    let mut fixture = Fixture::new("p10-resume-not-echoed")?;
    seed_echo(&fixture, true, false);
    let router = RouterCore::new();
    let (first, _, _) = establish(&mut fixture, &router, None, None).await?;
    assert!(!first.ephemeral);
    assert_unsupported(&router);
    let hash = gateway_resume_token_hash(&first.resume_token);
    let context = fixture.context.clone();
    let auth = session_push_auth()?;
    let source = runtime()?.source_identity;
    let open = open_frame(Some(&first.session_id), Some(&hash))?;
    let key = device_key();
    let task = tokio::spawn(async move {
        let mut send = support::Sink(Arc::new(std::sync::Mutex::new(Vec::new())));
        crate::session::establish_gateway_session(&mut send, &context, &open, &auth, key, source)
            .await
    });
    let req = fixture.next().await?;
    assert_eq!(req.path, "/s1/session");
    assert_eq!(req.body["ephemeral"], false);
    apply_router(&router, &req.path, &req.body)?;
    req.respond.send((200, capable_reply(&req.body))).map_err(|_| Retired)?;
    let cursor = fixture.next().await?;
    cursor.respond.send((200, Value::Null)).map_err(|_| Retired)?;
    let resumed = guard_10s("resumed session establishment task", task).await??;
    assert!(!resumed.ephemeral);
    assert_unsupported(&router);
    Ok(())
}

#[tokio::test]
async fn real_resume_rewrites_ephemeral_capability() -> TestResult {
    row_resume_withdraws_capability().await?;
    row_resume_grants_capability().await?;
    row_resume_without_echo_sends_false().await?;
    Ok(())
}

#[tokio::test]
async fn router_restart_reasserts_ephemeral_registrations() -> TestResult {
    row_late_hub_insert_reasserts_after_boot_change().await?;
    let mut fixture = Fixture::new("p10-boot-reassert")?;
    let router = RouterCore::new();
    let session_id = "session-live";
    let live = SessionDescriptor {
        target_delivery_id: TARGET.into(),
        device_id: "device".into(),
        gateway_id: GATEWAY.into(),
        session_id: session_id.into(),
        device_epoch: 1,
        session_seq: 1,
        last_cursor: None,
        push_alias_hash: None,
        lifecycle: ramflux_node_core::SessionLifecycle::Live,
    };
    router.upsert_session(live)?;
    router.mark_live(TARGET)?;
    assert_unsupported(&router);
    let (send, _) = sink();
    fixture
        .context
        .hub
        .register_ephemeral(TARGET.into(), session_id.into(), send, Some(ID.into()), 32)
        .await?;
    assert_eq!(fixture.context.hub.ephemeral_flag(TARGET).await, Some(true));
    let boot = router.router_boot_id().to_owned();
    fixture.context.hub.readiness.start_with_interval(
        &fixture.context.router,
        Duration::from_secs(1),
        Duration::from_secs(2),
        Some(Arc::downgrade(&fixture.context.hub)),
        Some(fixture.context.gateway_id.clone()),
    );
    let discovery = fixture.next().await?;
    assert_eq!(discovery.path, "/mvp1/session-push-capabilities");
    discovery
        .respond
        .send((
            200,
            json!({"capabilities":[SESSION_PUSH, GATEWAY_EPHEMERAL_CAPABILITY],"router_boot_id": boot}),
        ))
        .map_err(|_| Retired)?;
    let posted = fixture.next().await?;
    assert_eq!(posted.path, "/mvp0/ephemeral-registrations");
    assert_eq!(posted.body["router_boot_id"], boot);
    let items: Vec<EphemeralRegistrationItem> =
        serde_json::from_value(posted.body["items"].clone())?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].target, TARGET);
    assert_eq!(items[0].session_id, session_id);
    assert_eq!(items[0].gateway_id, GATEWAY);
    let applied = router.reassert_ephemeral_registrations(&boot, &items)?;
    assert_eq!(applied, 1);
    posted.respond.send((200, json!({"applied": applied}))).map_err(|_| Retired)?;
    assert_online(&router, session_id);
    let wake_before = fixture.context.notify.wake_count();
    fixture.context.hub.set_queue_clock(TARGET, 1_760_000_004_999).await;
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    if let Some(entry) = fixture.context.hub.snapshot().await.get(TARGET) {
        entry.queue.park_next_write(entered.clone(), release.clone());
    }
    let accepted = crate::ephemeral_forward::handle_at(
        &fixture.context.hub,
        crate::ephemeral_forward::GatewayForwardEphemeralRequest {
            source_gateway_id: GATEWAY.into(),
            target_delivery_id: TARGET.into(),
            forwarded: true,
            envelope: restart_envelope(TARGET),
            expires_at_ms: 1_760_000_005_000,
        },
        1_760_000_004_999,
    )
    .await?;
    assert!(accepted.delivered);
    assert_eq!(accepted.outcome, Some(ramflux_node_core::SessionPushForwardOutcome::Queued));
    guard_10s("ephemeral writer entering the sink after router reassertion", entered.notified())
        .await;
    assert_eq!(fixture.context.hub.ephemeral_queued(TARGET).await, 1);
    assert_eq!(fixture.context.notify.wake_count(), wake_before);
    release.add_permits(1);
    Ok(())
}

fn restart_envelope(target: &str) -> ramflux_protocol::Envelope {
    let mut ext = std::collections::BTreeMap::new();
    ext.insert(ramflux_protocol::ephemeral::DELIVERY_MODE_EXTENSION.to_owned(), json!("ephemeral"));
    ramflux_protocol::Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: ramflux_protocol::Ext { ext },
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "test-p11-key".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "test-p11-signature".to_owned(),
        },
        envelope_id: "env-restart-accepted".to_owned(),
        source_principal_id: "principal-p11".to_owned(),
        source_device_id: "device-p11".to_owned(),
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
    }
}

fn seed_live(router: &RouterCore, target: &str, session_id: &str) -> TestResult {
    let live = SessionDescriptor {
        target_delivery_id: target.into(),
        device_id: "device".into(),
        gateway_id: GATEWAY.into(),
        session_id: session_id.into(),
        device_epoch: 1,
        session_seq: 1,
        last_cursor: None,
        push_alias_hash: None,
        lifecycle: ramflux_node_core::SessionLifecycle::Live,
    };
    router.upsert_session(live)?;
    router.mark_live(target)?;
    Ok(())
}

async fn drive_reassert(fixture: &mut Fixture, router: &RouterCore, boot: &str) -> TestResult {
    let readiness = Arc::clone(&fixture.context.hub.readiness);
    let mesh = fixture.context.router.clone();
    let hub = Arc::clone(&fixture.context.hub);
    let gateway_id = fixture.context.gateway_id.clone();
    let boot_owned = boot.to_owned();
    let task = tokio::spawn(async move {
        readiness.reassert_boot(&mesh, &hub, &gateway_id, &boot_owned).await;
    });
    tokio::pin!(task);
    tokio::select! {
        req = fixture.requests.recv() => {
            let posted = req.ok_or_else(|| anyhow::anyhow!("mesh closed"))?;
            assert_eq!(posted.path, "/mvp0/ephemeral-registrations");
            assert_eq!(posted.body["router_boot_id"], boot);
            let items: Vec<EphemeralRegistrationItem> =
                serde_json::from_value(posted.body["items"].clone())?;
            let applied = router.reassert_ephemeral_registrations(boot, &items)?;
            posted.respond.send((200, json!({"applied": applied}))).map_err(|_| Retired)?;
            task.await?;
            Ok(())
        }
        join = &mut task => {
            join?;
            anyhow::bail!("reassert returned without posting");
        }
    }
}

async fn row_late_hub_insert_reasserts_after_boot_change() -> TestResult {
    const OTHER: &str = "target-other";
    const OTHER_SESSION: &str = "session-other";
    let mut fixture = Fixture::new("p10-late-hub-insert")?;
    seed_echo(&fixture, true, true);
    let router_a = RouterCore::new();
    let (runtime, _, path) = establish(&mut fixture, &router_a, None, None).await?;
    assert_eq!(path, "/s1/session");
    assert!(runtime.ephemeral);
    assert_online(&router_a, &runtime.session_id);
    assert_eq!(fixture.context.hub.ephemeral_flag(TARGET).await, None);
    let (other_send, _) = sink();
    fixture
        .context
        .hub
        .register_ephemeral(OTHER.into(), OTHER_SESSION.into(), other_send, Some(ID.into()), 32)
        .await?;
    let router_b = RouterCore::new();
    seed_live(&router_b, OTHER, OTHER_SESSION)?;
    seed_live(&router_b, TARGET, &runtime.session_id)?;
    assert_unsupported(&router_b);
    assert_eq!(router_b.route_gate(OTHER), EphemeralRouteGate::RecipientUnsupported);
    let boot_b = router_b.router_boot_id().to_owned();
    drive_reassert(&mut fixture, &router_b, &boot_b).await?;
    assert_eq!(
        router_b.route_gate(OTHER),
        EphemeralRouteGate::Online { gateway_id: GATEWAY.into(), session_id: OTHER_SESSION.into() }
    );
    assert_unsupported(&router_b);
    let (late_send, _) = sink();
    fixture.context.hub.register_runtime(&runtime, late_send).await?;
    assert_eq!(fixture.context.hub.ephemeral_flag(TARGET).await, Some(true));
    drive_reassert(&mut fixture, &router_b, &boot_b).await?;
    assert_online(&router_b, &runtime.session_id);
    Ok(())
}
