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
    let response = call(router, "POST", "/s1/session", &body)?;
    anyhow::ensure!(response["session_id"] == SESSION, "{response}");
    Ok(())
}

fn boot_id(router: &RouterHandle) -> anyhow::Result<String> {
    let caps = call(router, "GET", "/mvp1/session-push-capabilities", &Value::Null)?;
    caps["router_boot_id"].as_str().map(str::to_owned).ok_or_else(|| anyhow::anyhow!("boot id"))
}

fn reassert(router: &RouterHandle, boot: &str, items: &Value) -> anyhow::Result<Value> {
    call(
        router,
        "POST",
        "/mvp0/ephemeral-registrations",
        &json!({"router_boot_id": boot, "items": items}),
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

fn fresh(name: &str) -> anyhow::Result<(RouterHandle, PathBuf)> {
    let (state, store, path) = crate::router_runtime::tests::test_router(name)?;
    Ok((RouterHandle::tokio(state, store, None), path))
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
) -> anyhow::Result<(RouterHandle, PathBuf, String)> {
    let (router, path) = fresh(name)?;
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
    Ok((restored, path, previous_boot))
}

fn row_restart_empty_until_reassertion() -> TestResult {
    let (router, path, _) = restarted_live("p05-empty", "target-empty", GATEWAY)?;
    assert_unsupported(&router, "target-empty");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_valid_reassertion_restores() -> TestResult {
    let (router, path, _) = restarted_live("p05-restore", "target-restore", GATEWAY)?;
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
    let (router, path, previous_boot) = restarted_live("p05-stale", "target-stale", GATEWAY)?;
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
    let (router, path, _) = restarted_live("p05-delayed", "target-delayed", GATEWAY)?;
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
    let (router, path, _) = restarted_live("p05-mismatch", "target-mismatch", GATEWAY)?;
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
    let (router, path, _) = restarted_live("p05-gw-a", "target-gw-a", "gateway-b")?;
    let boot = boot_id(&router)?;
    let before = router.state().ephemeral_map_len();
    let response = reassert(&router, &boot, &items_for("target-gw-a", SESSION, "gateway-a"))?;
    assert_eq!(response["reason"], "recipient_unsupported");
    assert_eq!(router.state().ephemeral_map_len(), before);
    assert_unsupported(&router, "target-gw-a");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_asserting_gateway_match_accepted() -> TestResult {
    let (router, path, _) = restarted_live("p05-gw-b", "target-gw-b", "gateway-b")?;
    let boot = boot_id(&router)?;
    let response = reassert(&router, &boot, &items_for("target-gw-b", SESSION, "gateway-b"))?;
    assert_eq!(response["applied"], 1);
    assert_online(&router, "target-gw-b", "gateway-b", SESSION);
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_empty_target() -> TestResult {
    let (router, path, _) = restarted_live("p05-empty-t", "target-empty-t", GATEWAY)?;
    let boot = boot_id(&router)?;
    let response = reassert(&router, &boot, &items_for("", SESSION, GATEWAY))?;
    assert_eq!(response["applied"], 0);
    assert_unsupported(&router, "target-empty-t");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_empty_session() -> TestResult {
    let (router, path, _) = restarted_live("p05-empty-s", "target-empty-s", GATEWAY)?;
    let boot = boot_id(&router)?;
    let response = reassert(&router, &boot, &items_for("target-empty-s", "", GATEWAY))?;
    assert_eq!(response["applied"], 0);
    assert_unsupported(&router, "target-empty-s");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_non_live_descriptor() -> TestResult {
    let (router, path, _) = restarted_live("p05-drain", "target-drain", GATEWAY)?;
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
    let (router, path, _) = restarted_live("p05-map-full", "target-map-full", GATEWAY)?;
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
    let (router, path, _) = restarted_live("p05-map-over", "target-map-over", GATEWAY)?;
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
    let (router, path, _) = restarted_live("p05-set-full", "target-set-full", GATEWAY)?;
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
    let (router, path, _) = restarted_live("p05-item-bound", "target-bound", GATEWAY)?;
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
    let (router, path, _) = restarted_live("p05-over-items", "target-over", GATEWAY)?;
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
    let (router, path, _) = restarted_live("p05-auth", "target-auth", GATEWAY)?;
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
    let (router, path, _) = restarted_live("p05-decode", "target-decode", GATEWAY)?;
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
