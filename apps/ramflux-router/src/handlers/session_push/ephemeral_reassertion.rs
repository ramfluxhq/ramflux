// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Router-only re-assertion of ephemeral capability after a process restart.
#![allow(clippy::needless_pass_by_value, reason = "owned JSON test requests")]
use crate::router_runtime::RouterHandle;
use ramflux_node_core::{
    EPHEMERAL_CAPABILITY_BOUND, EPHEMERAL_REASSERTION_ITEM_BOUND, EphemeralRouteGate,
    SessionDescriptor, SessionLifecycle, SessionPushSessionRequest,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;

type TestResult = anyhow::Result<()>;

fn call(router: &RouterHandle, method: &str, path: &str, body: Value) -> anyhow::Result<Value> {
    let response = super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: method.into(),
            path: path.into(),
            body: serde_json::to_vec(&body)?,
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
    body: Value,
    peer: &str,
) -> anyhow::Result<super::super::MeshResponse> {
    super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: method.into(),
            path: path.into(),
            body: serde_json::to_vec(&body)?,
        },
        router,
        peer,
    )
}

fn descriptor(target: &str, session: &str, seq: u64) -> SessionDescriptor {
    SessionDescriptor {
        target_delivery_id: target.to_owned(),
        device_id: "device".to_owned(),
        gateway_id: "gateway".to_owned(),
        session_id: session.to_owned(),
        device_epoch: 1,
        session_seq: seq,
        last_cursor: None,
        push_alias_hash: None,
        lifecycle: SessionLifecycle::Live,
    }
}

fn capable_request(target: &str, session: &str, seq: u64) -> SessionPushSessionRequest {
    SessionPushSessionRequest {
        session: descriptor(target, session, seq),
        session_push: true,
        ephemeral: true,
    }
}

fn establish_capable(router: &RouterHandle, target: &str) -> TestResult {
    let response = call(
        router,
        "POST",
        "/s1/session",
        serde_json::to_value(capable_request(target, "session", 1))?,
    )?;
    anyhow::ensure!(response["session_id"] == "session", "{response}");
    Ok(())
}

fn boot_id(router: &RouterHandle) -> anyhow::Result<String> {
    let caps = call(router, "GET", "/mvp1/session-push-capabilities", Value::Null)?;
    caps["router_boot_id"].as_str().map(str::to_owned).ok_or_else(|| anyhow::anyhow!("boot id"))
}

fn reassert(router: &RouterHandle, boot: &str, items: Value) -> anyhow::Result<Value> {
    call(
        router,
        "POST",
        "/mvp0/ephemeral-registrations",
        json!({"router_boot_id": boot, "items": items}),
    )
}

fn persist_and_restart(router: RouterHandle, path: PathBuf) -> anyhow::Result<RouterHandle> {
    router.store().save_router(router.state())?;
    drop(router);
    let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
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

fn assert_online(router: &RouterHandle, target: &str) {
    assert_eq!(
        router.state().route_gate(target),
        EphemeralRouteGate::Online { gateway_id: "gateway".into(), session_id: "session".into() }
    );
    assert!(router.state().ephemeral_map_contains(target));
}

fn items_for(target: &str, session: &str) -> Value {
    json!([{"target": target, "session_id": session}])
}

fn restarted_live(name: &str, target: &str) -> anyhow::Result<(RouterHandle, PathBuf)> {
    let (router, path) = fresh(name)?;
    establish_capable(&router, target)?;
    assert_online(&router, target);
    let restored = persist_and_restart(router, path.clone())?;
    assert_eq!(restored.state().ephemeral_map_len(), 0);
    assert_eq!(restored.state().established_in_boot_len(), 0);
    assert_unsupported(&restored, target);
    let live = restored.state().session(target).ok_or_else(|| anyhow::anyhow!("live"))?;
    anyhow::ensure!(live.lifecycle == SessionLifecycle::Live, "restored live");
    Ok((restored, path))
}

fn row_restart_empty_until_reassertion() -> TestResult {
    let (router, path) = restarted_live("p05-empty", "target-empty")?;
    assert_unsupported(&router, "target-empty");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_valid_reassertion_restores() -> TestResult {
    let (router, path) = restarted_live("p05-restore", "target-restore")?;
    let boot = boot_id(&router)?;
    let response = reassert(&router, &boot, items_for("target-restore", "session"))?;
    assert_online(&router, "target-restore");
    assert_eq!(response["applied"], 1);
    let again = reassert(&router, &boot, items_for("target-restore", "session"))?;
    assert_eq!(again["applied"], 1);
    assert_online(&router, "target-restore");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_stale_boot_refused_whole() -> TestResult {
    let (router, path) = restarted_live("p05-stale", "target-stale")?;
    let response = reassert(
        &router,
        "ffffffffffffffffffffffffffffffff",
        items_for("target-stale", "session"),
    )?;
    assert_eq!(response["reason"], "boot_mismatch");
    assert_unsupported(&router, "target-stale");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_delayed_after_resume_without_capability() -> TestResult {
    let (router, path) = restarted_live("p05-delayed", "target-delayed")?;
    let boot = boot_id(&router)?;
    let mut resumed = descriptor("target-delayed", "session", 2);
    resumed.session_seq = 2;
    let upsert = call(&router, "POST", "/s1/session/upsert", serde_json::to_value(resumed)?)?;
    assert_eq!(upsert["session_id"], "session");
    assert!(router.state().established_in_boot_contains("target-delayed"));
    let response = reassert(&router, &boot, items_for("target-delayed", "session"))?;
    assert_eq!(response["applied"], 0);
    assert_unsupported(&router, "target-delayed");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_descriptor_mismatch() -> TestResult {
    let (router, path) = restarted_live("p05-mismatch", "target-mismatch")?;
    let boot = boot_id(&router)?;
    let response = reassert(&router, &boot, items_for("target-mismatch", "session-other"))?;
    assert_eq!(response["applied"], 0);
    assert_unsupported(&router, "target-mismatch");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_established_in_boot_full() -> TestResult {
    let (router, path) = restarted_live("p05-set-full", "target-set-full")?;
    let boot = boot_id(&router)?;
    for index in 0..EPHEMERAL_CAPABILITY_BOUND {
        router.state().clear_ephemeral_capability(&format!("f{index}"));
    }
    assert_eq!(router.state().established_in_boot_len(), EPHEMERAL_CAPABILITY_BOUND);
    let response = reassert(&router, &boot, items_for("target-set-full", "session"))?;
    assert_eq!(response["applied"], 0);
    assert_unsupported(&router, "target-set-full");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_item_bound_inclusive() -> TestResult {
    let (router, path) = restarted_live("p05-item-bound", "target-bound")?;
    let boot = boot_id(&router)?;
    let mut accepted = Vec::with_capacity(EPHEMERAL_REASSERTION_ITEM_BOUND);
    accepted.push(json!({"target": "target-bound", "session_id": "session"}));
    for index in 1..EPHEMERAL_REASSERTION_ITEM_BOUND {
        accepted.push(json!({"target": format!("unknown-{index}"), "session_id": "session"}));
    }
    let ok = reassert(&router, &boot, Value::Array(accepted))?;
    assert_eq!(ok["applied"], 1);
    assert_online(&router, "target-bound");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_1025_items_refused() -> TestResult {
    let (router, path) = restarted_live("p05-over-items", "target-over")?;
    let boot = boot_id(&router)?;
    let mut overflow = Vec::with_capacity(EPHEMERAL_REASSERTION_ITEM_BOUND.saturating_add(1));
    overflow.push(json!({"target": "target-over", "session_id": "session"}));
    for index in 0..EPHEMERAL_REASSERTION_ITEM_BOUND {
        overflow.push(json!({"target": format!("over-{index}"), "session_id": "session"}));
    }
    let response = reassert(&router, &boot, Value::Array(overflow))?;
    assert_eq!(response["reason"], "invalid_seq");
    assert_unsupported(&router, "target-over");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_non_gateway_peer_forbidden() -> TestResult {
    let (router, path) = restarted_live("p05-auth", "target-auth")?;
    let boot = boot_id(&router)?;
    let response = mesh(
        &router,
        "POST",
        "/mvp0/ephemeral-registrations",
        json!({"router_boot_id": boot, "items": items_for("target-auth", "session")}),
        "ramflux-federation",
    )?;
    assert_eq!(response.status, "403 Forbidden");
    assert_unsupported(&router, "target-auth");
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
    row_established_in_boot_full()?;
    row_item_bound_inclusive()?;
    row_1025_items_refused()?;
    row_non_gateway_peer_forbidden()?;
    Ok(())
}
