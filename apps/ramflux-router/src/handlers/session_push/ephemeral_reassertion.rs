// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Router-only re-assertion of ephemeral capability after a process restart.
use crate::router_runtime::RouterHandle;
use ramflux_node_core::{
    EPHEMERAL_CAPABILITY_BOUND, EPHEMERAL_REASSERTION_ITEM_BOUND, EphemeralRegistrationItem,
    EphemeralRegistrationsRequest, EphemeralRouteGate, SessionDescriptor, SessionLifecycle,
    SessionPushSessionRequest,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;

type TestResult = anyhow::Result<()>;

const GATEWAY: &str = "gateway";
const SESSION: &str = "session";

fn call(router: &RouterHandle, method: &str, path: &str, body: &Value) -> anyhow::Result<Value> {
    call_as(router, method, path, body, GATEWAY)
}

fn call_as(
    router: &RouterHandle,
    method: &str,
    path: &str,
    body: &Value,
    instance: &str,
) -> anyhow::Result<Value> {
    let peer = ramflux_node_core::MeshPeerIdentity::gateway_for_test(instance);
    let response = super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: method.into(),
            path: path.into(),
            body: serde_json::to_vec(body)?,
        },
        router,
        &peer,
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
    let identity = if peer == "ramflux-gateway" {
        ramflux_node_core::MeshPeerIdentity::gateway_for_test(GATEWAY)
    } else {
        ramflux_node_core::MeshPeerIdentity {
            node_id: "test-node".into(),
            service_id: peer.into(),
            instance_id: None,
            spiffe_uri: format!("spiffe://test-node/{peer}"),
        }
    };
    super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: method.into(),
            path: path.into(),
            body: serde_json::to_vec(body)?,
        },
        router,
        &identity,
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

fn capable_request(
    target: &str,
    gateway: &str,
    session: &str,
    seq: u64,
) -> SessionPushSessionRequest {
    SessionPushSessionRequest {
        session: descriptor(target, gateway, session, seq),
        session_push: true,
        ephemeral: true,
    }
}

fn establish_capable(router: &RouterHandle, target: &str, gateway: &str) -> TestResult {
    let body = serde_json::to_value(capable_request(target, gateway, SESSION, 1))?;
    let response = call_as(router, "POST", "/s1/session", &body, gateway)?;
    anyhow::ensure!(response["session_id"] == SESSION, "{response}");
    Ok(())
}

fn boot_id(router: &RouterHandle) -> anyhow::Result<String> {
    let caps = call(router, "GET", "/mvp1/session-push-capabilities", &Value::Null)?;
    caps["router_boot_id"].as_str().map(str::to_owned).ok_or_else(|| anyhow::anyhow!("boot id"))
}

fn reassert(router: &RouterHandle, boot: &str, items: &Value) -> anyhow::Result<Value> {
    reassert_as(router, boot, items, GATEWAY)
}

fn reassert_as(
    router: &RouterHandle,
    boot: &str,
    items: &Value,
    instance: &str,
) -> anyhow::Result<Value> {
    call_as(
        router,
        "POST",
        "/mvp0/ephemeral-registrations",
        &json!({"router_boot_id": boot, "items": items}),
        instance,
    )
}

fn persist_and_restart(
    router: RouterHandle,
    path: &std::path::Path,
) -> anyhow::Result<RouterHandle> {
    router.store().save_router(router.state())?;
    drop(router);
    let store = Arc::new(ramflux_node_core::RouterRedbStore::open(path)?);
    let state = Arc::new(store.load_router()?.ok_or_else(|| anyhow::anyhow!("restored"))?);
    Ok(RouterHandle::tokio(state, store, None))
}

fn fresh(name: &str) -> anyhow::Result<(ramflux_test_support::TestPath, RouterHandle)> {
    let (path, state, store) = crate::router_runtime::tests::test_router(name)?;
    Ok((path, RouterHandle::tokio(state, store, None)))
}

fn assert_unsupported(router: &RouterHandle, target: &str) {
    assert_eq!(router.state().route_gate(target), EphemeralRouteGate::RecipientUnsupported);
    assert!(!router.state().ephemeral_map_contains(target));
}

fn assert_online(router: &RouterHandle, target: &str, gateway: &str, session: &str) {
    assert_eq!(
        router.state().route_gate(target),
        EphemeralRouteGate::Online { gateway_id: gateway.into(), session_id: session.into() }
    );
    assert!(router.state().ephemeral_map_contains(target));
}

fn items_for(target: &str, session: &str, gateway: &str) -> Value {
    json!([{"target": target, "session_id": session, "gateway_id": gateway}])
}

fn item_json(target: &str, session: &str, gateway: &str) -> Value {
    json!({"target": target, "session_id": session, "gateway_id": gateway})
}

fn restarted_live(
    name: &str,
    target: &str,
    gateway: &str,
) -> anyhow::Result<(ramflux_test_support::TestPath, RouterHandle, String)> {
    let (path, router) = fresh(name)?;
    establish_capable(&router, target, gateway)?;
    assert_online(&router, target, gateway, SESSION);
    let previous_boot = boot_id(&router)?;
    let restored = persist_and_restart(router, &path)?;
    assert_eq!(restored.state().ephemeral_map_len(), 0);
    assert_eq!(restored.state().established_in_boot_len(), 0);
    assert_unsupported(&restored, target);
    let live = restored.state().session(target).ok_or_else(|| anyhow::anyhow!("live"))?;
    anyhow::ensure!(live.lifecycle == SessionLifecycle::Live, "restored live");
    anyhow::ensure!(live.gateway_id == gateway, "restored gateway");
    let new_boot = boot_id(&restored)?;
    anyhow::ensure!(previous_boot != new_boot, "boot id reused across restart");
    Ok((path, restored, previous_boot))
}

fn row_restart_empty_until_reassertion() -> TestResult {
    let (path, router, _) = restarted_live("p05-empty", "target-empty", GATEWAY)?;
    assert_unsupported(&router, "target-empty");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_valid_reassertion_restores() -> TestResult {
    let (path, router, _) = restarted_live("p05-restore", "target-restore", GATEWAY)?;
    let boot = boot_id(&router)?;
    let response = reassert(&router, &boot, &items_for("target-restore", SESSION, GATEWAY))?;
    assert_online(&router, "target-restore", GATEWAY, SESSION);
    assert_eq!(response["applied"], 1);
    let again = reassert(&router, &boot, &items_for("target-restore", SESSION, GATEWAY))?;
    assert_eq!(again["applied"], 1);
    assert_online(&router, "target-restore", GATEWAY, SESSION);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_stale_boot_refused_whole() -> TestResult {
    let (path, router, previous_boot) = restarted_live("p05-stale", "target-stale", GATEWAY)?;
    let current = boot_id(&router)?;
    anyhow::ensure!(previous_boot != current, "previous boot must differ");
    let response = reassert(&router, &previous_boot, &items_for("target-stale", SESSION, GATEWAY))?;
    assert_eq!(response["reason"], "boot_mismatch");
    assert_unsupported(&router, "target-stale");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_delayed_after_resume_without_capability() -> TestResult {
    let (path, router, _) = restarted_live("p05-delayed", "target-delayed", GATEWAY)?;
    let boot = boot_id(&router)?;
    let resumed = descriptor("target-delayed", GATEWAY, SESSION, 2);
    let body = serde_json::to_value(resumed)?;
    let upsert = call(&router, "POST", "/s1/session/upsert", &body)?;
    assert_eq!(upsert["session_id"], SESSION);
    assert!(router.state().established_in_boot_contains("target-delayed"));
    let response = reassert(&router, &boot, &items_for("target-delayed", SESSION, GATEWAY))?;
    assert_eq!(response["applied"], 0);
    assert_unsupported(&router, "target-delayed");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_descriptor_mismatch() -> TestResult {
    let (path, router, _) = restarted_live("p05-mismatch", "target-mismatch", GATEWAY)?;
    let boot = boot_id(&router)?;
    let response =
        reassert(&router, &boot, &items_for("target-mismatch", "session-other", GATEWAY))?;
    assert_eq!(response["applied"], 0);
    assert_unsupported(&router, "target-mismatch");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_asserting_gateway_mismatch_refused() -> TestResult {
    let (path, router, _) = restarted_live("p05-gw-a", "target-gw-a", "gateway-b")?;
    let boot = boot_id(&router)?;
    let before = router.state().ephemeral_map_len();
    let response =
        reassert_as(&router, &boot, &items_for("target-gw-a", SESSION, "gateway-a"), "gateway-a")?;
    assert_eq!(response["applied"], 0);
    assert_eq!(router.state().ephemeral_map_len(), before);
    assert_unsupported(&router, "target-gw-a");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_mixed_batch_gateway_mismatch_refuses_whole_request() -> TestResult {
    let (path, router) = fresh("p05-mixed")?;
    establish_capable(&router, "target-mix-1", GATEWAY)?;
    establish_capable(&router, "target-mix-2", "gateway-b")?;
    establish_capable(&router, "target-mix-3", GATEWAY)?;
    let previous_boot = boot_id(&router)?;
    let restored = persist_and_restart(router, &path)?;
    let boot = boot_id(&restored)?;
    anyhow::ensure!(previous_boot != boot, "boot id reused across restart");
    assert_eq!(restored.state().ephemeral_map_len(), 0);
    let items = json!([
        item_json("target-mix-1", SESSION, GATEWAY),
        item_json("target-mix-2", SESSION, "gateway-a"),
        item_json("target-mix-3", SESSION, GATEWAY),
    ]);
    let before = restored.state().ephemeral_map_len();
    let response = reassert(&restored, &boot, &items)?;
    assert_eq!(response["reason"], "gateway_instance_mismatch");
    assert_eq!(restored.state().ephemeral_map_len(), before);
    assert_unsupported(&restored, "target-mix-1");
    assert_unsupported(&restored, "target-mix-2");
    assert_unsupported(&restored, "target-mix-3");
    drop(restored);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_empty_gateway_is_bad_request() -> TestResult {
    let (path, router, _) = restarted_live("p05-empty-g", "target-empty-g", GATEWAY)?;
    let boot = boot_id(&router)?;
    let response = reassert(&router, &boot, &items_for("target-empty-g", SESSION, ""))?;
    assert_eq!(response["reason"], "gateway_id_empty");
    assert_unsupported(&router, "target-empty-g");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_ephemeral_session_rejects_another_instance_before_binding() -> TestResult {
    let (path, router) = fresh("p05-ephemeral-instance")?;
    let body = serde_json::to_value(capable_request("target-other-instance", "gw-b", SESSION, 1))?;
    let response = super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: "/s1/session".into(),
            body: serde_json::to_vec(&body)?,
        },
        &router,
        &ramflux_node_core::MeshPeerIdentity::gateway_for_test("gw-a"),
    )?;
    assert_eq!(response.status, "403 Forbidden");
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["reason"], "gateway_instance_mismatch");
    assert!(router.state().session("target-other-instance").is_none());
    assert!(!router.state().ephemeral_map_contains("target-other-instance"));
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_reassertion_foreign_node_is_json_node_mismatch() -> TestResult {
    let (path, router, _) = restarted_live("p05-node-mismatch", "target-node-mismatch", GATEWAY)?;
    let boot = boot_id(&router)?;
    let peer = ramflux_node_core::MeshPeerIdentity {
        node_id: "foreign-node".into(),
        ..ramflux_node_core::MeshPeerIdentity::gateway_for_test(GATEWAY)
    };
    let response = super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: "/mvp0/ephemeral-registrations".into(),
            body: serde_json::to_vec(&json!({
                "router_boot_id": boot,
                "items": items_for("target-node-mismatch", SESSION, GATEWAY),
            }))?,
        },
        &router,
        &peer,
    )?;
    assert_eq!(response.status, "403 Forbidden");
    assert_eq!(serde_json::from_slice::<Value>(&response.body)?["reason"], "gateway_node_mismatch");
    assert_unsupported(&router, "target-node-mismatch");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_principal_lookup_and_session_get_gates() -> TestResult {
    let (path, router) = fresh("p05-principal-gates")?;
    let response = super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: "/mvp1/principal-lookup".into(),
            body: br#"{"gateway_id":"gw-b"}"#.to_vec(),
        },
        &router,
        &ramflux_node_core::MeshPeerIdentity::gateway_for_test("gw-a"),
    )?;
    assert_eq!(response.status, "403 Forbidden");
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body)?["reason"],
        "gateway_instance_mismatch"
    );

    let response = mesh(&router, "GET", "/s1/session/target", &Value::Null, "ramflux-federation")?;
    assert_eq!(response.status, "403 Forbidden");
    let response = super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: "/s1/session/upsert".into(),
            body: serde_json::to_vec(&serde_json::to_value(descriptor(
                "foreign-node",
                "gw-a",
                SESSION,
                1,
            ))?)?,
        },
        &router,
        &ramflux_node_core::MeshPeerIdentity {
            node_id: "foreign-node".into(),
            ..ramflux_node_core::MeshPeerIdentity::gateway_for_test("gw-a")
        },
    )?;
    assert_eq!(response.status, "403 Forbidden");
    assert_eq!(serde_json::from_slice::<Value>(&response.body)?["reason"], "gateway_node_mismatch");
    assert!(router.state().session("foreign-node").is_none());
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_unparseable_registration_body_is_bad_request() -> TestResult {
    let (path, router) = fresh("p05-unparseable-body")?;
    let response = super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: "/s1/session/upsert".into(),
            body: b"{".to_vec(),
        },
        &router,
        &ramflux_node_core::MeshPeerIdentity::gateway_for_test("gw-a"),
    )?;
    assert_eq!(response.status, "400 Bad Request");
    assert_eq!(serde_json::from_slice::<Value>(&response.body)?["reason"], "invalid_json");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_session_get_nested_target_is_gated() -> TestResult {
    let (path, router) = fresh("p05-session-get-nested")?;
    let response = mesh(&router, "GET", "/s1/session/a/b", &Value::Null, "ramflux-federation")?;
    assert_eq!(response.status, "403 Forbidden");
    assert_eq!(serde_json::from_slice::<Value>(&response.body)?["reason"], "gateway_role_required");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_asserting_gateway_match_accepted() -> TestResult {
    let (path, router, _) = restarted_live("p05-gw-b", "target-gw-b", "gateway-b")?;
    let boot = boot_id(&router)?;
    let response =
        reassert_as(&router, &boot, &items_for("target-gw-b", SESSION, "gateway-b"), "gateway-b")?;
    assert_eq!(response["applied"], 1);
    assert_online(&router, "target-gw-b", "gateway-b", SESSION);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_empty_target() -> TestResult {
    let (path, router, _) = restarted_live("p05-empty-t", "target-empty-t", GATEWAY)?;
    let boot = boot_id(&router)?;
    let response = reassert(&router, &boot, &items_for("", SESSION, GATEWAY))?;
    assert_eq!(response["applied"], 0);
    assert_unsupported(&router, "target-empty-t");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_empty_session() -> TestResult {
    let (path, router, _) = restarted_live("p05-empty-s", "target-empty-s", GATEWAY)?;
    let boot = boot_id(&router)?;
    let response = reassert(&router, &boot, &items_for("target-empty-s", "", GATEWAY))?;
    assert_eq!(response["applied"], 0);
    assert_unsupported(&router, "target-empty-s");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_non_live_descriptor() -> TestResult {
    let (path, router, _) = restarted_live("p05-drain", "target-drain", GATEWAY)?;
    let boot = boot_id(&router)?;
    router.state().mark_draining("target-drain")?;
    let response = reassert(&router, &boot, &items_for("target-drain", SESSION, GATEWAY))?;
    assert_eq!(response["applied"], 0);
    assert_eq!(router.state().route_gate("target-drain"), EphemeralRouteGate::RecipientUnsupported);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_map_saturation() -> TestResult {
    let (path, router, _) = restarted_live("p05-map-full", "target-map-full", GATEWAY)?;
    let boot = boot_id(&router)?;
    for index in 0..EPHEMERAL_CAPABILITY_BOUND.saturating_sub(1) {
        router.state().bind_ephemeral_capability(&format!("m{index}"), GATEWAY, SESSION);
    }
    assert_eq!(router.state().ephemeral_map_len(), EPHEMERAL_CAPABILITY_BOUND.saturating_sub(1));
    let accepted = reassert(&router, &boot, &items_for("target-map-full", SESSION, GATEWAY))?;
    assert_eq!(accepted["applied"], 1);
    assert_eq!(router.state().ephemeral_map_len(), EPHEMERAL_CAPABILITY_BOUND);
    assert_online(&router, "target-map-full", GATEWAY, SESSION);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_map_saturation_next_refused() -> TestResult {
    let (path, router, _) = restarted_live("p05-map-over", "target-map-over", GATEWAY)?;
    let boot = boot_id(&router)?;
    for index in 0..EPHEMERAL_CAPABILITY_BOUND {
        router.state().bind_ephemeral_capability(&format!("n{index}"), GATEWAY, SESSION);
    }
    assert_eq!(router.state().ephemeral_map_len(), EPHEMERAL_CAPABILITY_BOUND);
    let response = reassert(&router, &boot, &items_for("target-map-over", SESSION, GATEWAY))?;
    assert_eq!(response["applied"], 0);
    assert_eq!(router.state().ephemeral_map_len(), EPHEMERAL_CAPABILITY_BOUND);
    assert!(!router.state().ephemeral_map_contains("target-map-over"));
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_established_in_boot_full() -> TestResult {
    let (path, router, _) = restarted_live("p05-set-full", "target-set-full", GATEWAY)?;
    let boot = boot_id(&router)?;
    for index in 0..EPHEMERAL_CAPABILITY_BOUND {
        router.state().clear_ephemeral_capability(&format!("f{index}"));
    }
    assert_eq!(router.state().established_in_boot_len(), EPHEMERAL_CAPABILITY_BOUND);
    let response = reassert(&router, &boot, &items_for("target-set-full", SESSION, GATEWAY))?;
    assert_eq!(response["applied"], 0);
    assert_unsupported(&router, "target-set-full");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_item_bound_inclusive() -> TestResult {
    let (path, router, _) = restarted_live("p05-item-bound", "target-bound", GATEWAY)?;
    let boot = boot_id(&router)?;
    let mut accepted = Vec::with_capacity(EPHEMERAL_REASSERTION_ITEM_BOUND);
    accepted.push(item_json("target-bound", SESSION, GATEWAY));
    for index in 1..EPHEMERAL_REASSERTION_ITEM_BOUND {
        accepted.push(item_json(&format!("unknown-{index}"), SESSION, GATEWAY));
    }
    let ok = reassert(&router, &boot, &Value::Array(accepted))?;
    assert_eq!(ok["applied"], 1);
    assert_online(&router, "target-bound", GATEWAY, SESSION);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_1025_items_refused() -> TestResult {
    let (path, router, _) = restarted_live("p05-over-items", "target-over", GATEWAY)?;
    let boot = boot_id(&router)?;
    let mut overflow = Vec::with_capacity(EPHEMERAL_REASSERTION_ITEM_BOUND.saturating_add(1));
    overflow.push(item_json("target-over", SESSION, GATEWAY));
    for index in 0..EPHEMERAL_REASSERTION_ITEM_BOUND {
        overflow.push(item_json(&format!("over-{index}"), SESSION, GATEWAY));
    }
    let response = reassert(&router, &boot, &Value::Array(overflow))?;
    assert_eq!(response["reason"], "invalid_seq");
    assert_unsupported(&router, "target-over");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_non_gateway_peer_forbidden() -> TestResult {
    let (path, router, _) = restarted_live("p05-auth", "target-auth", GATEWAY)?;
    let boot = boot_id(&router)?;
    let response = mesh(
        &router,
        "POST",
        "/mvp0/ephemeral-registrations",
        &json!({"router_boot_id": boot, "items": items_for("target-auth", SESSION, GATEWAY)}),
        "ramflux-federation",
    )?;
    assert_eq!(response.status, "403 Forbidden");
    assert_unsupported(&router, "target-auth");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_request_decode_negatives() -> TestResult {
    let (path, router, _) = restarted_live("p05-decode", "target-decode", GATEWAY)?;
    let boot = boot_id(&router)?;
    for body in [
        &b"{"[..],
        br#"{"items":[]}"#,
        br#"{"router_boot_id":"x"}"#,
        br#"{"router_boot_id":"x","items":[],"extra":1}"#,
        br#"{"router_boot_id":"x","items":[{"target":"t","session_id":"s"}]}"#,
        br#"{"router_boot_id":1,"items":[]}"#,
        br#"{"router_boot_id":"x","items":{}}"#,
    ] {
        let response = super::super::handle_mesh_request_value(
            ramflux_transport::MeshHttpRequest {
                method: "POST".into(),
                path: "/mvp0/ephemeral-registrations".into(),
                body: body.to_vec(),
            },
            &router,
            "ramflux-gateway",
        )?;
        let value: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(value["reason"], "invalid_seq", "{}", String::from_utf8_lossy(body));
        assert_unsupported(&router, "target-decode");
    }
    let request = EphemeralRegistrationsRequest {
        router_boot_id: boot.clone(),
        items: vec![EphemeralRegistrationItem {
            target: "target-decode".into(),
            session_id: SESSION.into(),
            gateway_id: GATEWAY.into(),
        }],
    };
    let encoded = serde_json::to_vec(&request)?;
    let decoded: EphemeralRegistrationsRequest = serde_json::from_slice(&encoded)?;
    assert_eq!(decoded, request);
    assert_eq!(serde_json::to_vec(&decoded)?, encoded);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn ephemeral_router_restart_reassertion() -> TestResult {
    row_restart_empty_until_reassertion()?;
    row_valid_reassertion_restores()?;
    row_stale_boot_refused_whole()?;
    row_delayed_after_resume_without_capability()?;
    row_descriptor_mismatch()?;
    row_asserting_gateway_mismatch_refused()?;
    row_asserting_gateway_match_accepted()?;
    row_mixed_batch_gateway_mismatch_refuses_whole_request()?;
    row_empty_gateway_is_bad_request()?;
    row_ephemeral_session_rejects_another_instance_before_binding()?;
    row_reassertion_foreign_node_is_json_node_mismatch()?;
    row_principal_lookup_and_session_get_gates()?;
    row_unparseable_registration_body_is_bad_request()?;
    row_session_get_nested_target_is_gated()?;
    row_empty_target()?;
    row_empty_session()?;
    row_non_live_descriptor()?;
    row_map_saturation()?;
    row_map_saturation_next_refused()?;
    row_established_in_boot_full()?;
    row_item_bound_inclusive()?;
    row_1025_items_refused()?;
    row_non_gateway_peer_forbidden()?;
    row_request_decode_negatives()?;
    Ok(())
}
