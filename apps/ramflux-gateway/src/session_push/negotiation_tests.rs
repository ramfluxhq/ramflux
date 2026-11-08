// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed selection is frozen and discovery never blocks compatibility service.
use super::*;
pub(crate) fn auth(scope: bool) -> anyhow::Result<ramflux_node_core::GatewayAuthFrame> {
    let mut value: ramflux_node_core::GatewayAuthFrame = serde_json::from_value(
        json!({"signed_request":{"schema":"ramflux.signed_request.v1","version":1,"domain":"ramflux.signed_request.v1","signing_key_id":"device","signature_alg":"ed25519","signature":"fixture","source_device_id":"device","request_id":"open","method":"POST","path":"/gateway/open","device_proof_hash":"hash","body_hash":"hash","nonce":"nonce","created_at":1,"expires_at":2},"device_proof":{"schema":"ramflux.device_proof.v1","version":1,"domain":"ramflux.device_proof.v1","signing_key_id":"device","signature_alg":"ed25519","signature":"fixture","principal_id":"principal","device_id":"device","device_epoch":1,"branch_proof_hash":"hash","capability_scope":[],"nonce":"nonce","expires_at":2}}),
    )?;
    if scope {
        value
            .device_proof
            .capability_scope
            .push(ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into());
    }
    value.device_proof.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::signed_bytes(&value.device_proof)?,
        [4; 32],
    );
    Ok(value)
}

/// Client `capability_scope` includes `gateway.ephemeral.v1`. Router advertisement still gates.
pub(crate) fn auth_claiming_ephemeral(
    session_push: bool,
) -> anyhow::Result<ramflux_node_core::GatewayAuthFrame> {
    let mut value = auth(session_push)?;
    value
        .device_proof
        .capability_scope
        .push(ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.into());
    value.device_proof.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::signed_bytes(&value.device_proof)?,
        [4; 32],
    );
    Ok(value)
}
pub(super) fn descriptor() -> ramflux_node_core::SessionDescriptor {
    ramflux_node_core::SessionDescriptor {
        target_delivery_id: "target".into(),
        device_id: "device".into(),
        gateway_id: "gateway".into(),
        session_id: "session".into(),
        device_epoch: 1,
        session_seq: 1,
        last_cursor: None,
        push_alias_hash: None,
        lifecycle: ramflux_node_core::SessionLifecycle::Live,
    }
}
async fn registration(
    fixture: &mut Fixture,
    scope: bool,
    capable: bool,
) -> anyhow::Result<Option<String>> {
    let context = fixture.context.clone();
    let auth = auth(scope)?;
    let descriptor = descriptor();
    let task = tokio::spawn(async move { negotiate(&context, &auth, &descriptor).await });
    let req = fixture.next().await?;
    assert_eq!(req.path, if capable { "/s1/session" } else { "/s1/session/upsert" });
    let mut reply = serde_json::to_value(self::descriptor())?;
    if capable {
        assert_eq!(req.body["session_push"], true);
        assert_eq!(req.body["ephemeral"], false);
        reply["incarnation_id"] = json!(ID);
    }
    req.respond.send((200, reply)).map_err(|_| Retired)?;
    let binding = tokio::time::timeout(Duration::from_secs(10), task).await???;
    assert!(!binding.ephemeral);
    Ok(binding.incarnation_id)
}
async fn ready(fixture: &Fixture, expected: bool) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        while fixture.context.hub.readiness.supports() != expected {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}
#[tokio::test]
async fn session_push_capability_negotiation() -> anyhow::Result<()> {
    let mut fixture = Fixture::new("push-negotiation")?;
    fixture.context.hub.readiness.start_with_hub(
        &fixture.context.router,
        &fixture.context.hub,
        &fixture.context.gateway_id,
    );
    let discovery = fixture.next().await?;
    assert_eq!(discovery.path, "/mvp1/session-push-capabilities");
    // A held discovery request cannot delay signed clients falling back to the old upsert.
    assert_eq!(registration(&mut fixture, true, false).await?, None);
    discovery
        .respond
        .send((200, json!({"capabilities":[ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY]})))
        .map_err(|_| Retired)?;
    ready(&fixture, true).await?;
    assert_eq!(registration(&mut fixture, false, false).await?, None);
    let selected = registration(&mut fixture, true, true).await?;
    assert_eq!(selected.as_deref(), Some(ID));
    fixture.context.hub.readiness.ready.store(false, Ordering::Release);
    let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut wire_sink = support::Sink(frames.clone());
    established(
        &mut wire_sink,
        ramflux_node_core::GatewaySessionEstablishedFrame {
            session_id: "session".into(),
            gateway_id: "gateway".into(),
            accepted_cursor: None,
            resume_token: "resume".into(),
            resume_window_seconds: 300,
        },
        selected.as_deref(),
        false,
    )
    .await?;
    let rows = frames.lock().map_err(|_| Retired)?.clone();
    assert_eq!(
        rows[0]["session"]["capabilities"],
        json!([ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY])
    );
    assert_eq!(rows[0]["session"]["inbox_incarnation_id"], ID);
    drop(rows);
    assert_eq!(registration(&mut fixture, true, false).await?, None);
    fixture.context.hub.readiness.ready.store(true, Ordering::Release);
    // A removed route cannot be interpreted as an empty page or a successful ACK.
    let context = fixture.context.clone();
    let task = tokio::spawn(async move {
        let (send, _) = sink();
        handle(
            &send,
            &context,
            &runtime()?,
            &serde_json::to_vec(
                &json!({"frame_type":"fetch_entry","incarnation_id":ID,"inbox_seq":1}),
            )?,
        )
        .await
    });
    let req = fixture.next().await?;
    req.respond.send((404, json!({"error":"route removed"}))).map_err(|_| Retired)?;
    assert!(task.await?.is_err_and(|e| e.downcast_ref::<Retired>().is_some()));
    assert!(!fixture.context.hub.readiness.supports());
    assert_eq!(registration(&mut fixture, true, false).await?, None);
    Ok(())
}
#[tokio::test]
async fn capability_failures_and_sixty_second_retry() -> anyhow::Result<()> {
    assert_eq!(DISCOVERY_INTERVAL, Duration::from_secs(60));
    for (label, status, body) in [
        ("push-missing-cap", 404, json!({})),
        ("push-invalid-cap", 200, json!({"capabilities":[7]})),
        ("push-timeout-cap", 200, Value::Null),
    ] {
        let mut fixture = Fixture::new(label)?;
        fixture.context.hub.readiness.ready.store(true, Ordering::Release);
        let clock = DiscoveryClock::new();
        fixture.context.hub.readiness.set_discovery_clock(clock.clone());
        fixture.context.hub.readiness.start_with_interval(
            &fixture.context.router,
            DISCOVERY_INTERVAL,
            Duration::from_millis(100),
            None,
            None,
        );
        let req = fixture.next().await?;
        if body.is_null() {
            drop(req);
        } else {
            req.respond.send((status, body)).map_err(|_| Retired)?;
        }
        ready(&fixture, false).await?;
        assert_eq!(registration(&mut fixture, true, false).await?, None);
        if status == 404 {
            clock.advance(Duration::from_secs(59));
            assert!(
                fixture.requests.try_recv().is_err(),
                "retry must not fire before 60s of test time"
            );
            clock.advance(Duration::from_secs(1));
            let retry = tokio::time::timeout(Duration::from_secs(10), fixture.requests.recv())
                .await?
                .ok_or(Retired)?;
            assert_eq!(retry.path, "/mvp1/session-push-capabilities");
            retry
                .respond
                .send((
                    200,
                    json!({"capabilities":[ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY]}),
                ))
                .map_err(|_| Retired)?;
            ready(&fixture, true).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn open_clamps_runtime_push_limit() -> anyhow::Result<()> {
    for (requested, expected) in [(4, 16), (1000, 256)] {
        let mut fixture = Fixture::new(&format!("open-limit-{requested}"))?;
        fixture.context.hub.readiness.started.store(true, Ordering::Release);
        let context = fixture.context.clone();
        let auth = auth(false)?;
        let source = runtime()?.source_identity;
        let open: ramflux_node_core::GatewayOpenFrame = serde_json::from_value(
            json!({"protocol_version":ramflux_node_core::GATEWAY_SESSION_PROTOCOL_VERSION,"transport_kind":"quic_quinn","client_instance_id":"client","device_id":"device","target_delivery_id":"target","stream_nonce":"nonce","previous_session_id":null,"resume_token_hash":null,"last_seen_inbox_seq":null,"max_inflight_downstream":requested,"max_inflight_upstream":4,"pre_auth_cookie":null,"pre_auth_now":null,"source_ip_hash":null}),
        )?;
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
        let task = tokio::spawn(async move {
            let mut send = support::Sink(Arc::new(std::sync::Mutex::new(Vec::new())));
            crate::session::establish_gateway_session(
                &mut send, &context, &open, &auth, key, source,
            )
            .await
        });
        let req = fixture.next().await?;
        assert_eq!(req.path, "/s1/session/upsert");
        let reply = req.body.clone();
        req.respond.send((200, reply)).map_err(|_| Retired)?;
        let cursor = fixture.next().await?;
        assert_eq!(cursor.path, "/mvp0/cursor/target");
        cursor.respond.send((200, Value::Null)).map_err(|_| Retired)?;
        let runtime = tokio::time::timeout(Duration::from_secs(10), task).await???;
        assert_eq!(runtime.push_limit, expected);
    }
    Ok(())
}

#[path = "real_router_tests.rs"]
mod real_router;
