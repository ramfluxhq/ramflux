// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real-handler oracle for D6 W1/W2 and C1.
#![allow(clippy::needless_pass_by_value, reason = "owned JSON test requests")]
use crate::router_runtime::RouterHandle;
use ramflux_node_core::{
    EphemeralRouteGate, SessionDescriptor, SessionLifecycle, SessionPushSessionRequest,
};
use serde_json::Value;
use std::path::PathBuf;

type TestResult = anyhow::Result<()>;

fn call(router: &RouterHandle, method: &str, path: &str, body: Value) -> anyhow::Result<Value> {
    let instance = body
        .get("gateway_id")
        .or_else(|| body.get("session").and_then(|session| session.get("gateway_id")))
        .and_then(Value::as_str)
        .unwrap_or("gateway");
    let peer = ramflux_node_core::MeshPeerIdentity::gateway_for_test(instance);
    let response = super::super::handle_mesh_request_value(
        ramflux_transport::MeshHttpRequest {
            method: method.into(),
            path: path.into(),
            body: serde_json::to_vec(&body)?,
        },
        router,
        &peer,
    )?;
    Ok(serde_json::from_slice(&response.body)?)
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
    ephemeral: bool,
) -> SessionPushSessionRequest {
    SessionPushSessionRequest {
        session: descriptor(target, gateway, session, seq),
        session_push: true,
        ephemeral,
    }
}

fn fresh(name: &str) -> anyhow::Result<(RouterHandle, PathBuf)> {
    let (state, store, path) = crate::router_runtime::tests::test_router(name)?;
    Ok((RouterHandle::tokio(state, store, None), path))
}

fn post_capable(
    router: &RouterHandle,
    target: &str,
    gateway: &str,
    session: &str,
    seq: u64,
    ephemeral: bool,
) -> TestResult {
    let response = call(
        router,
        "POST",
        "/s1/session",
        serde_json::to_value(capable_request(target, gateway, session, seq, ephemeral))?,
    )?;
    anyhow::ensure!(response["session_id"] == session, "{response}");
    Ok(())
}

fn post_upsert(router: &RouterHandle, session: &SessionDescriptor) -> TestResult {
    let response = call(router, "POST", "/s1/session/upsert", serde_json::to_value(session)?)?;
    anyhow::ensure!(response["session_id"] == session.session_id, "{response}");
    Ok(())
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

fn seed_capable(name: &str, target: &str) -> anyhow::Result<(RouterHandle, PathBuf)> {
    let (router, path) = fresh(name)?;
    post_capable(&router, target, "gateway", "session", 1, true)?;
    assert_online(&router, target, "gateway", "session");
    Ok((router, path))
}

fn row_resume_without_capability() -> TestResult {
    let (router, path) = seed_capable("p04-btf", "target-btf")?;
    post_upsert(&router, &descriptor("target-btf", "gateway", "session", 2))?;
    let mut forwards = 0;
    let gate = router.state().route_gate("target-btf");
    assert_eq!(gate, EphemeralRouteGate::RecipientUnsupported);
    if matches!(gate, EphemeralRouteGate::Online { .. }) {
        forwards += 1;
    }
    assert_eq!(forwards, 0);
    assert!(!router.state().ephemeral_map_contains("target-btf"));
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_resume_with_capability_after_legacy() -> TestResult {
    let (router, path) = seed_capable("p04-reverse", "target-reverse")?;
    post_upsert(&router, &descriptor("target-reverse", "gateway", "session", 2))?;
    assert_unsupported(&router, "target-reverse");
    post_capable(&router, "target-reverse", "gateway", "session", 3, true)?;
    assert_online(&router, "target-reverse", "gateway", "session");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_capable_ephemeral_false_clears() -> TestResult {
    let (router, path) = seed_capable("p04-false", "target-false")?;
    post_capable(&router, "target-false", "gateway", "session", 2, false)?;
    assert_unsupported(&router, "target-false");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_legacy_other_gateway() -> TestResult {
    let (router, path) = seed_capable("p04-other-gw", "target-other-gw")?;
    post_upsert(&router, &descriptor("target-other-gw", "gateway-b", "session-b", 2))?;
    assert_unsupported(&router, "target-other-gw");
    let recorded = router.state().session("target-other-gw").ok_or_else(|| anyhow::anyhow!("d"))?;
    assert_eq!(recorded.gateway_id, "gateway-b");
    assert_eq!(recorded.session_id, "session-b");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_new_session_without_ephemeral() -> TestResult {
    let (router, path) = seed_capable("p04-new-sid", "target-new-session")?;
    post_capable(&router, "target-new-session", "gateway", "session-2", 2, false)?;
    assert_unsupported(&router, "target-new-session");
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_gateway_mismatch_retains_map() -> TestResult {
    let (router, path) = seed_capable("p04-gw-eq", "target-gw-eq")?;
    let mut changed = descriptor("target-gw-eq", "gateway-b", "session", 2);
    changed.gateway_id = "gateway-b".into();
    router.state().upsert_session(changed)?;
    router.state().mark_live("target-gw-eq")?;
    assert!(router.state().ephemeral_map_contains("target-gw-eq"));
    assert_eq!(router.state().route_gate("target-gw-eq"), EphemeralRouteGate::RecipientUnsupported);
    assert!(!router.state().ephemeral_map_contains("target-gw-eq"));
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

fn row_session_mismatch_retains_map() -> TestResult {
    let (router, path) = seed_capable("p04-sid-eq", "target-sid-eq")?;
    let mut changed = descriptor("target-sid-eq", "gateway", "session-b", 2);
    changed.session_id = "session-b".into();
    router.state().upsert_session(changed)?;
    router.state().mark_live("target-sid-eq")?;
    assert!(router.state().ephemeral_map_contains("target-sid-eq"));
    assert_eq!(
        router.state().route_gate("target-sid-eq"),
        EphemeralRouteGate::RecipientUnsupported
    );
    assert!(!router.state().ephemeral_map_contains("target-sid-eq"));
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn ephemeral_capability_route_binding() -> TestResult {
    row_resume_without_capability()?;
    row_resume_with_capability_after_legacy()?;
    row_capable_ephemeral_false_clears()?;
    row_legacy_other_gateway()?;
    row_new_session_without_ephemeral()?;
    row_gateway_mismatch_retains_map()?;
    row_session_mismatch_retains_map()?;
    Ok(())
}
