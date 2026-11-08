// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real POST `/mvp0/envelope-ephemeral` oracle for read-only C1 routing.
use crate::router_runtime::RouterHandle;
use ramflux_node_core::{
    EphemeralDispatchObservation, EphemeralDropReason, EphemeralRouteRequest,
    EphemeralRouteResponse, EphemeralRouteResult, HomeNodeMigrationRecord, SessionDescriptor,
    SessionLifecycle, SessionPushSessionRequest,
};
use ramflux_protocol::{
    DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields, ephemeral as proto,
};
use serde_json::{Value, json};
use std::path::PathBuf;

type TestResult = anyhow::Result<()>;

const GATEWAY: &str = "gateway";
const SESSION: &str = "session";
const TARGET: &str = "target_alice";

fn call(router: &RouterHandle, method: &str, path: &str, body: &Value) -> anyhow::Result<Value> {
    let response = super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: method.into(),
            path: path.into(),
            body: serde_json::to_vec(body)?,
        },
        router,
        "ramflux-gateway",
    )?;
    Ok(serde_json::from_slice(&response.body)?)
}

fn mesh(
    router: &RouterHandle,
    method: &str,
    path: &str,
    body: &Value,
    peer: &str,
) -> anyhow::Result<super::super::MeshResponse> {
    super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: method.into(),
            path: path.into(),
            body: serde_json::to_vec(body)?,
        },
        router,
        peer,
    )
}

fn descriptor(target: &str, gateway: &str, session: &str, seq: u64) -> SessionDescriptor {
    SessionDescriptor {
        target_delivery_id: target.to_owned(),
        device_id: "device".to_owned(),
        gateway_id: gateway.to_owned(),
        session_id: session.to_owned(),
        device_epoch: 1,
        session_seq: seq,
        last_cursor: None,
        push_alias_hash: None,
        lifecycle: SessionLifecycle::Live,
    }
}

fn establish_capable(router: &RouterHandle, target: &str) -> TestResult {
    let body = serde_json::to_value(SessionPushSessionRequest {
        session: descriptor(target, GATEWAY, SESSION, 1),
        session_push: true,
        ephemeral: true,
    })?;
    let response = call(router, "POST", "/s1/session", &body)?;
    anyhow::ensure!(response["session_id"] == SESSION, "{response}");
    Ok(())
}

fn fresh(name: &str) -> anyhow::Result<(RouterHandle, PathBuf)> {
    let (state, store, path) = crate::router_runtime::tests::test_router(name)?;
    Ok((RouterHandle::tokio(state, store, None), path))
}

fn sign_seed() -> [u8; 32] {
    ramflux_crypto::blake3_256("ramflux.test.runtime.device.v1", b"alice/alice_phone")
}

fn signed_ephemeral(id: &str, target: &str) -> anyhow::Result<Envelope> {
    let created_at = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let mut envelope = Envelope {
        schema: "ramflux.envelope.v1".into(),
        version: 1,
        domain: "ramflux.envelope.v1".into(),
        ext: Ext::default(),
        signed: SignedFields {
            signing_key_id: "test_key".into(),
            signature_alg: SignatureAlg::Ed25519,
            signature: String::new(),
        },
        envelope_id: id.into(),
        source_principal_id: "alice".into(),
        source_device_id: "alice_phone".into(),
        target_delivery_id: target.into(),
        routing_set_id: None,
        delivery_class: DeliveryClass::OpaqueEvent,
        priority: Priority::Low,
        ttl: 5,
        created_at,
        encrypted_payload: "ciphertext".into(),
        payload_hash: "payload_hash".into(),
    };
    envelope.ext.ext.insert(proto::DELIVERY_MODE_EXTENSION.into(), json!("ephemeral"));
    let root = ramflux_crypto::create_identity_root(
        "alice",
        ramflux_crypto::blake3_256("ramflux.test.registration_root.v1", b"alice"),
    );
    envelope.ext.ext.insert(
        "source_root_commitment".into(),
        json!(ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key())),
    );
    envelope.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&envelope, sign_seed())?;
    Ok(envelope)
}

fn request_body(
    envelope: &ramflux_protocol::Envelope,
    expires_at_ms: u64,
) -> anyhow::Result<Value> {
    Ok(serde_json::to_value(EphemeralRouteRequest { envelope: envelope.clone(), expires_at_ms })?)
}

fn computed_expires(envelope: &ramflux_protocol::Envelope, now_ms: u64) -> anyhow::Result<u64> {
    Ok(ramflux_protocol::ephemeral::deadline(envelope, now_ms)?)
}

fn post_route(router: &RouterHandle, body: &Value) -> anyhow::Result<EphemeralRouteResponse> {
    let value = call(router, "POST", "/mvp0/envelope-ephemeral", body)?;
    Ok(serde_json::from_value(value)?)
}

fn now_ms() -> u64 {
    ramflux_node_core::now_unix_seconds().saturating_mul(1_000)
}

fn zero_dispatch() -> EphemeralDispatchObservation {
    EphemeralDispatchObservation { pending_inbox: 0, forwarding_reservations: 0 }
}

fn dispatch_of(router: &RouterHandle, target: &str) -> EphemeralDispatchObservation {
    router.state().ephemeral_dispatch_observation(target)
}

fn assert_no_dispatch(router: &RouterHandle, target: &str, response: &EphemeralRouteResponse) {
    assert!(
        !matches!(response, EphemeralRouteResponse::Online { .. }),
        "zero forwards and enqueues, got {response:?}"
    );
    assert_eq!(dispatch_of(router, target), zero_dispatch(), "inbox and home-node forwards");
}

struct NowMsGuard<'a>(&'a RouterHandle);
impl Drop for NowMsGuard<'_> {
    fn drop(&mut self) {
        self.0.set_ephemeral_now_ms(None);
    }
}

fn store_bytes(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

fn observe_post(
    router: &RouterHandle,
    path: &std::path::Path,
    target: &str,
    body: &Value,
) -> anyhow::Result<EphemeralRouteResponse> {
    let before = router.state().ephemeral_durable_snapshot()?;
    let before_store = store_bytes(path);
    let before_dispatch = dispatch_of(router, target);
    let response = post_route(router, body)?;
    anyhow::ensure!(
        router.state().ephemeral_durable_snapshot()? == before,
        "durable snapshot changed"
    );
    anyhow::ensure!(store_bytes(path) == before_store, "redb mutated");
    anyhow::ensure!(dispatch_of(router, target) == before_dispatch, "forward/enqueue mutated");
    Ok(response)
}

fn row_accepted_and_read_only() -> TestResult {
    let (router, path) = fresh("p06-ok")?;
    establish_capable(&router, TARGET)?;
    let envelope = signed_ephemeral("ok", TARGET)?;
    let expires = computed_expires(&envelope, now_ms())?;
    let before = router.state().ephemeral_durable_snapshot()?;
    let before_store = store_bytes(&path);
    let before_dispatch = dispatch_of(&router, TARGET);
    let response = post_route(&router, &request_body(&envelope, expires)?)?;
    assert_eq!(
        response,
        EphemeralRouteResponse::Online { gateway_id: GATEWAY.into(), session_id: SESSION.into() }
    );
    anyhow::ensure!(router.state().ephemeral_durable_snapshot()? == before);
    anyhow::ensure!(store_bytes(&path) == before_store);
    anyhow::ensure!(dispatch_of(&router, TARGET) == before_dispatch);
    anyhow::ensure!(before_dispatch == zero_dispatch());
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_non_gateway_peer() -> TestResult {
    let (router, path) = fresh("p06-peer")?;
    establish_capable(&router, TARGET)?;
    let envelope = signed_ephemeral("peer", TARGET)?;
    let expires = computed_expires(&envelope, now_ms())?;
    let before = router.state().ephemeral_durable_snapshot()?;
    let before_store = store_bytes(&path);
    let before_calls = router.state().route_ephemeral_call_count();
    let before_dispatch = dispatch_of(&router, TARGET);
    let response = mesh(
        &router,
        "POST",
        "/mvp0/envelope-ephemeral",
        &request_body(&envelope, expires)?,
        "ramflux-federation",
    )?;
    assert_eq!(response.status, "403 Forbidden");
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "session push requires authenticated gateway"
    );
    anyhow::ensure!(router.state().ephemeral_durable_snapshot()? == before);
    anyhow::ensure!(store_bytes(&path) == before_store);
    anyhow::ensure!(router.state().route_ephemeral_call_count() == before_calls);
    anyhow::ensure!(dispatch_of(&router, TARGET) == before_dispatch);
    anyhow::ensure!(before_dispatch == zero_dispatch());
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_deadline_mismatch() -> TestResult {
    let (router, path) = fresh("p06-d")?;
    establish_capable(&router, TARGET)?;
    let envelope = signed_ephemeral("d", TARGET)?;
    let expires = computed_expires(&envelope, now_ms())?;
    let exact = router.state().route_ephemeral(&envelope, expires.saturating_add(1), now_ms());
    assert_eq!(exact, EphemeralRouteResult::DeadlineMismatch);
    let response =
        observe_post(&router, &path, TARGET, &request_body(&envelope, expires.saturating_add(1))?)?;
    assert_eq!(response, EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::Invalid });
    assert_no_dispatch(&router, TARGET, &response);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_revoked_source() -> TestResult {
    let (router, path) = fresh("p06-revoked")?;
    establish_capable(&router, TARGET)?;
    let envelope = signed_ephemeral("revoked", TARGET)?;
    let expires = computed_expires(&envelope, now_ms())?;
    router.state().test_revoke_envelope_source(&envelope);
    let exact = router.state().route_ephemeral(&envelope, expires, now_ms());
    assert_eq!(exact, EphemeralRouteResult::RevokedSource);
    let response = observe_post(&router, &path, TARGET, &request_body(&envelope, expires)?)?;
    assert_eq!(response, EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::Invalid });
    assert_no_dispatch(&router, TARGET, &response);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_root_mismatch() -> TestResult {
    let (router, path) = fresh("p06-root")?;
    establish_capable(&router, TARGET)?;
    let mut envelope = signed_ephemeral("root", TARGET)?;
    envelope.ext.ext.insert("source_root_commitment".into(), json!("other-root"));
    let expires = computed_expires(&envelope, now_ms())?;
    let exact = router.state().route_ephemeral(&envelope, expires, now_ms());
    assert_eq!(exact, EphemeralRouteResult::RootMismatch);
    let response = observe_post(&router, &path, TARGET, &request_body(&envelope, expires)?)?;
    assert_eq!(response, EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::Invalid });
    assert_no_dispatch(&router, TARGET, &response);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_offline() -> TestResult {
    let (router, path) = fresh("p06-offline")?;
    let envelope = signed_ephemeral("offline", "target_offline")?;
    let expires = computed_expires(&envelope, now_ms())?;
    let exact = router.state().route_ephemeral(&envelope, expires, now_ms());
    assert_eq!(exact, EphemeralRouteResult::Dropped(EphemeralDropReason::Offline));
    let response =
        observe_post(&router, &path, "target_offline", &request_body(&envelope, expires)?)?;
    assert_eq!(response, EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::Offline });
    assert_no_dispatch(&router, "target_offline", &response);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_no_map_entry() -> TestResult {
    let (router, path) = fresh("p06-nomap")?;
    let target = "target_no_map";
    router.state().upsert_session(descriptor(target, GATEWAY, SESSION, 1))?;
    router.state().mark_live(target)?;
    let envelope = signed_ephemeral("nomap", target)?;
    let expires = computed_expires(&envelope, now_ms())?;
    let exact = router.state().route_ephemeral(&envelope, expires, now_ms());
    assert_eq!(exact, EphemeralRouteResult::Dropped(EphemeralDropReason::RecipientUnsupported));
    let response = observe_post(&router, &path, target, &request_body(&envelope, expires)?)?;
    assert_eq!(
        response,
        EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::RecipientUnsupported }
    );
    assert_no_dispatch(&router, target, &response);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_map_ne_descriptor() -> TestResult {
    let (router, path) = fresh("p06-mapne")?;
    let target = "target_map_ne";
    establish_capable(&router, target)?;
    router.state().clear_ephemeral_capability(target);
    router.state().bind_ephemeral_capability(target, "other-gateway", SESSION);
    let envelope = signed_ephemeral("mapne", target)?;
    let expires = computed_expires(&envelope, now_ms())?;
    let exact = router.state().route_ephemeral(&envelope, expires, now_ms());
    assert_eq!(exact, EphemeralRouteResult::Dropped(EphemeralDropReason::RecipientUnsupported));
    let response = observe_post(&router, &path, target, &request_body(&envelope, expires)?)?;
    assert_eq!(
        response,
        EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::RecipientUnsupported }
    );
    assert_no_dispatch(&router, target, &response);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_not_local() -> TestResult {
    let (router, path) = fresh("p06-not-local")?;
    establish_capable(&router, TARGET)?;
    let keys =
        router.state().mvp1_identities_snapshot().identity_keys_for_target_delivery_id(TARGET);
    let identity = keys.first().ok_or_else(|| anyhow::anyhow!("identity key"))?.clone();
    router.state().set_local_home_node_id(Some("node-a".into()));
    router.state().test_put_home_node_migration(
        identity.clone(),
        HomeNodeMigrationRecord {
            format_version: 1,
            identity_commitment: identity,
            old_home_node: "node-a".into(),
            new_home_node: "node-b".into(),
            new_home_node_key_hash: "key".into(),
            route_record_hash: "route".into(),
            effective_at: 0,
            issued_at: 0,
            migration_proof_hash: "proof".into(),
            migrated_at: 0,
        },
    );
    let envelope = signed_ephemeral("migrated", TARGET)?;
    let expires = computed_expires(&envelope, now_ms())?;
    let exact = router.state().route_ephemeral(&envelope, expires, now_ms());
    assert_eq!(exact, EphemeralRouteResult::Dropped(EphemeralDropReason::NotLocal));
    let response = observe_post(&router, &path, TARGET, &request_body(&envelope, expires)?)?;
    assert_eq!(response, EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::NotLocal });
    assert_no_dispatch(&router, TARGET, &response);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_decode_invalid() -> TestResult {
    let (router, path) = fresh("p06-decode")?;
    establish_capable(&router, TARGET)?;
    let before = router.state().ephemeral_durable_snapshot()?;
    let before_store = store_bytes(&path);
    let before_calls = router.state().route_ephemeral_call_count();
    let before_dispatch = dispatch_of(&router, TARGET);
    // A malformed body is refused by the strict I-JSON ingress (P03), which the serve layer
    // maps to the exact D3 400 body; it no longer reaches the route as a "dropped/invalid" row.
    let Err(error) = super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: "/mvp0/envelope-ephemeral".into(),
            body: b"{".to_vec(),
        },
        &router,
        "ramflux-gateway",
    ) else {
        anyhow::bail!("malformed ephemeral route body must be refused by strict ingress");
    };
    let body = super::super::i_json_rejection(&error)
        .ok_or_else(|| anyhow::anyhow!("expected the strict I-JSON refusal, got {error:#}"))?;
    assert_eq!(
        serde_json::to_vec(&body)?,
        br#"{"error":"i_json_rejected","reason_code":"i_json_rejected"}"#
    );
    anyhow::ensure!(router.state().ephemeral_durable_snapshot()? == before);
    anyhow::ensure!(store_bytes(&path) == before_store);
    anyhow::ensure!(router.state().route_ephemeral_call_count() == before_calls);
    anyhow::ensure!(dispatch_of(&router, TARGET) == before_dispatch);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn ephemeral_route_read_only() -> TestResult {
    row_accepted_and_read_only()?;
    row_non_gateway_peer()?;
    row_deadline_mismatch()?;
    row_revoked_source()?;
    row_root_mismatch()?;
    row_offline()?;
    row_no_map_entry()?;
    row_map_ne_descriptor()?;
    row_not_local()?;
    row_decode_invalid()?;
    Ok(())
}

#[test]
fn ephemeral_deadline() -> TestResult {
    let (router, path) = fresh("p06-deadline")?;
    establish_capable(&router, TARGET)?;
    let envelope = signed_ephemeral("deadline", TARGET)?;
    let expires = computed_expires(&envelope, now_ms())?;
    let live = router.state().route_ephemeral(&envelope, expires, expires.saturating_sub(1));
    assert_eq!(
        live,
        EphemeralRouteResult::Online { gateway_id: GATEWAY.into(), session_id: SESSION.into() }
    );
    let replayed = router.state().route_ephemeral(&envelope, expires, expires.saturating_sub(1));
    assert_eq!(replayed, EphemeralRouteResult::Dropped(EphemeralDropReason::Replayed));
    let at_deadline = router.state().route_ephemeral(&envelope, expires, expires);
    assert_eq!(at_deadline, EphemeralRouteResult::Dropped(EphemeralDropReason::Expired));
    let mismatch_env = signed_ephemeral("deadline-mm", TARGET)?;
    let mismatch_expires = computed_expires(&mismatch_env, now_ms())?;
    let mismatch =
        router.state().route_ephemeral(&mismatch_env, mismatch_expires.saturating_add(1), now_ms());
    assert_eq!(mismatch, EphemeralRouteResult::DeadlineMismatch);
    let _now = NowMsGuard(&router);
    let http_env = signed_ephemeral("deadline-http", TARGET)?;
    let http_expires = computed_expires(&http_env, now_ms())?;
    router.set_ephemeral_now_ms(Some(http_expires.saturating_sub(1)));
    let http = observe_post(&router, &path, TARGET, &request_body(&http_env, http_expires)?)?;
    assert_eq!(
        http,
        EphemeralRouteResponse::Online { gateway_id: GATEWAY.into(), session_id: SESSION.into() }
    );
    let http_replayed =
        observe_post(&router, &path, TARGET, &request_body(&http_env, http_expires)?)?;
    assert_eq!(
        http_replayed,
        EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::Replayed }
    );
    assert_no_dispatch(&router, TARGET, &http_replayed);
    router.set_ephemeral_now_ms(Some(http_expires));
    let http_at_d = observe_post(&router, &path, TARGET, &request_body(&http_env, http_expires)?)?;
    assert_eq!(http_at_d, EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::Expired });
    assert_no_dispatch(&router, TARGET, &http_at_d);
    let fresh_at_d = signed_ephemeral("deadline-http-d", TARGET)?;
    let fresh_expires = computed_expires(&fresh_at_d, now_ms())?;
    router.set_ephemeral_now_ms(Some(fresh_expires));
    let http_fresh_expired =
        observe_post(&router, &path, TARGET, &request_body(&fresh_at_d, fresh_expires)?)?;
    assert_eq!(
        http_fresh_expired,
        EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::Expired }
    );
    assert_no_dispatch(&router, TARGET, &http_fresh_expired);
    router.set_ephemeral_now_ms(Some(mismatch_expires.saturating_sub(1)));
    let http_mismatch = observe_post(
        &router,
        &path,
        TARGET,
        &request_body(&mismatch_env, mismatch_expires.saturating_add(1))?,
    )?;
    assert_eq!(
        http_mismatch,
        EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::Invalid }
    );
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}
