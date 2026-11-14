// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Raw mesh contract probes; gateway session framing is owned by P14.
#![allow(clippy::needless_pass_by_value, reason = "owned JSON test requests")]
use crate::router_runtime::RouterHandle;
use serde_json::{Value, json};
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
fn seed(name: &str) -> anyhow::Result<(ramflux_test_support::TestPath, RouterHandle, Value)> {
    let (path, state, store) = crate::router_runtime::tests::test_router(name)?;
    let router = RouterHandle::tokio(state, store, None);
    let envelope = crate::router_runtime::tests::current_envelope(name, "target")?;
    let response = call(&router, "POST", "/mvp0/envelope", serde_json::to_value(envelope)?)?;
    anyhow::ensure!(response["inbox_seq"] == 1, "{response}");
    Ok((path, router, response))
}
#[test]
fn issued_seqs_contract() -> anyhow::Result<()> {
    let (_path, router, _) = seed("issued-contract")?;
    let invalid: Vec<Vec<String>> = vec![
        vec![],
        vec!["target".into(); 2],
        (0..1025).map(|n| format!("over-limit-{n}")).collect(),
        vec![String::new()],
    ];
    for targets in invalid {
        assert_eq!(
            call(&router, "POST", "/mvp0/issued-seqs", json!({"targets":targets}))?["reason"],
            "invalid_seq"
        );
    }
    let targets: Vec<_> = (0..1024).map(|n| format!("unknown-{n}")).collect();
    let response = call(&router, "POST", "/mvp0/issued-seqs", json!({"targets":targets}))?;
    let rows = response["issued"].as_array().ok_or_else(|| anyhow::anyhow!("rows"))?;
    assert_eq!(rows.len(), 1024);
    for (n, row) in rows.iter().enumerate() {
        assert_eq!(row["target_delivery_id"], format!("unknown-{n}"));
        assert_eq!(row["inbox_seq"], 0);
        assert!(row["incarnation_id"].is_null());
    }
    assert_eq!(router.store().inbox_status("unknown-0")?, (None, 0));
    let response =
        call(&router, "POST", "/mvp0/issued-seqs", json!({"targets":["target","unknown"]}))?;
    assert_eq!(response["issued"][0]["inbox_seq"], 1);
    assert_eq!(response["issued"][1]["inbox_seq"], 0);
    drop(router);
    Ok(())
}
#[test]
fn invalid_seq_terminal() -> anyhow::Result<()> {
    let (_path, router, response) = seed("invalid-terminal")?;
    let id = response["incarnation_id"].as_str().ok_or_else(|| anyhow::anyhow!("E"))?;
    let before = router.state().resume("target", 0, 10);
    for target in ["target", "unknown"] {
        for seq in [0, 2, ramflux_protocol::MAX_SAFE_JSON_INTEGER] {
            let batch = call(
                &router,
                "POST",
                "/mvp0/ack-bound-batch",
                json!({"target_delivery_id":target,"incarnation_id":id,"inbox_seqs":[seq]}),
            )?;
            // E mismatch now precedes the published-range check (controller P13 r2 L1).
            assert_eq!(
                batch["reason"],
                if target == "unknown" && seq > 0 { "incarnation_mismatch" } else { "invalid_seq" }
            );
            let entry =
                call(&router, "GET", &format!("/mvp1/inbox-entry/{target}/{seq}"), Value::Null)?;
            assert_eq!(entry["reason"], "invalid_seq");
            let ack = json!({"schema":"ramflux.ack.v1","version":1,"domain":"ramflux.ack.v1","ext":{"inbox_seq":seq},"signing_key_id":"test","signature_alg":"ed25519","signature":"","ack_id":"ack","envelope_id":"unused","receiver_device_id":"receiver","received_at":0,"cursor_after":null});
            let bound = call(
                &router,
                "POST",
                "/mvp0/ack-bound",
                json!({"target_delivery_id":target,"ack":ack}),
            )?;
            assert_eq!(bound["reason"], "invalid_seq");
        }
    }
    for seqs in [vec![], vec![1, 1], vec![2, 1], vec![1; 65]] {
        assert_eq!(
            call(
                &router,
                "POST",
                "/mvp0/ack-bound-batch",
                json!({"target_delivery_id":"target","incarnation_id":id,"inbox_seqs":seqs})
            )?["reason"],
            "invalid_seq"
        );
    }
    assert_eq!(router.state().resume("target", 0, 10), before);
    assert_eq!(router.store().inbox_status("unknown")?, (None, 0));
    assert!(router.state().cursor_state("unknown").is_none());
    drop(router);
    Ok(())
}
#[test]
fn inbox_incarnation_lifecycle() -> anyhow::Result<()> {
    let (path, router, accepted) = seed("mesh-incarnation")?;
    let id = accepted["incarnation_id"].as_str().ok_or_else(|| anyhow::anyhow!("E"))?.to_owned();
    let row = router.state().fetch_entry("target", 1, 0)?;
    let row = serde_json::to_value(row)?;
    assert_eq!(accepted["retain_until"], row["record"]["retain_until"]);
    let page = call(
        &router,
        "GET",
        &format!("/mvp1/inbox/target?session_push=1&incarnation_id={id}&after=0&limit=256"),
        Value::Null,
    )?;
    assert_eq!(page["incarnation_id"], id);
    assert!(page.get("frame_type").is_none());
    assert_eq!(page["entries"][0]["retain_until"], accepted["retain_until"]);
    let wrong = "ffffffffffffffffffffffffffffffff";
    for path in [
        format!("/mvp1/inbox/target?session_push=1&incarnation_id={wrong}"),
        format!("/mvp1/inbox-entry/target/1?incarnation_id={wrong}"),
    ] {
        let result = call(&router, "GET", &path, Value::Null)?;
        assert_eq!(result["reason"], "incarnation_mismatch");
        assert_eq!(result["incarnation_id"], id);
    }
    let rejected = call(
        &router,
        "POST",
        "/mvp0/ack-bound-batch",
        json!({"target_delivery_id":"target","incarnation_id":wrong,"inbox_seqs":[1]}),
    )?;
    assert_eq!(rejected["reason"], "incarnation_mismatch");
    assert_eq!(router.state().resume("target", 0, 10).len(), 1);
    let legacy = call(&router, "GET", "/mvp1/inbox/target?after=0&limit=1", Value::Null)?;
    assert!(legacy.get("incarnation_id").is_none());
    assert_eq!(legacy["entries"].as_array().map(Vec::len), Some(1));
    let capabilities = call(&router, "GET", "/mvp1/session-push-capabilities", Value::Null)?;
    assert_eq!(
        capabilities["capabilities"],
        json!([
            ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY,
            ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY
        ])
    );
    let boot = capabilities["router_boot_id"].as_str().ok_or_else(|| anyhow::anyhow!("boot"))?;
    assert!(ramflux_node_core::valid_inbox_incarnation(boot));
    let response = call(
        &router,
        "POST",
        "/mvp0/ack-bound-batch",
        json!({"target_delivery_id":"target","incarnation_id":id,"inbox_seqs":[1]}),
    )?;
    assert_eq!(response["results"][0]["outcome"], "acked");
    assert_eq!(response["results"].as_array().map(Vec::len), Some(1));
    drop(router);
    let store = ramflux_node_core::RouterRedbStore::open(&path)?;
    assert_eq!(store.inbox_status("target")?.0.as_deref(), Some(id.as_str()));
    drop(store);
    Ok(())
}
#[test]
fn delayed_old_incarnation_ack() -> anyhow::Result<()> {
    // The raw old request is delayed before entering the restarted router.
    let (path, state, store) = crate::router_runtime::tests::test_router("delayed-old-E")?;
    let old = store.initialize_inbox("target")?;
    let backup = path.with_extension("backup");
    std::fs::copy(&path, &backup)?;
    let router = RouterHandle::tokio(state, store, None);
    let envelope = crate::router_runtime::tests::current_envelope("old-content", "target")?;
    call(&router, "POST", "/mvp0/envelope", serde_json::to_value(envelope)?)?;
    let raw = serde_json::to_vec(
        &json!({"target_delivery_id":"target","incarnation_id":old,"inbox_seqs":[1]}),
    )?;
    let (release, ingress) = std::sync::mpsc::channel::<RouterHandle>();
    let (done, result) = std::sync::mpsc::channel();
    let held = std::thread::spawn(move || {
        let response = ingress
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(anyhow::Error::from)
            .and_then(|current| {
                super::super::handle_mesh_request_value(
                    ramflux_transport::MeshHttpRequest {
                        method: "POST".into(),
                        path: "/mvp0/ack-bound-batch".into(),
                        body: raw,
                    },
                    &current,
                    "ramflux-gateway",
                )
            });
        let _ = done.send(response.map(|r| r.body));
    });
    drop(router);
    std::fs::copy(&backup, &path)?;
    let wal_root = path.with_file_name(format!(
        "{}.wal",
        path.file_name().ok_or_else(|| anyhow::anyhow!("file name"))?.to_string_lossy()
    ));
    std::fs::remove_dir_all(&wal_root)?;
    ramflux_node_core::RouterRedbStore::rotate_inbox_incarnations_at(&path, Some(&wal_root), None)?;
    let store = std::sync::Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
    let state = std::sync::Arc::new(store.load_router()?.ok_or_else(|| anyhow::anyhow!("state"))?);
    let router = RouterHandle::tokio(state, store, None);
    let envelope = crate::router_runtime::tests::current_envelope("new-content", "target")?;
    let accepted = call(&router, "POST", "/mvp0/envelope", serde_json::to_value(envelope)?)?;
    assert_eq!(accepted["inbox_seq"], 1);
    assert_ne!(accepted["incarnation_id"], old);
    release.send(router.clone())?;
    let response: Value =
        serde_json::from_slice(&result.recv_timeout(std::time::Duration::from_secs(10))??)?;
    held.join().map_err(|_| anyhow::anyhow!("ingress thread"))?;
    assert_eq!(response["reason"], "incarnation_mismatch");
    assert_eq!(response["incarnation_id"], accepted["incarnation_id"]);
    assert_eq!(router.state().resume("target", 0, 10)[0].envelope.envelope_id, "new-content");
    let current =
        accepted["incarnation_id"].as_str().ok_or_else(|| anyhow::anyhow!("E"))?.to_owned();
    drop(router);
    let store = ramflux_node_core::RouterRedbStore::open(&path)?;
    assert_eq!(store.inbox_status("target")?.0.as_deref(), Some(current.as_str()));
    assert_eq!(
        store.load_router()?.ok_or_else(|| anyhow::anyhow!("state"))?.resume("target", 0, 10).len(),
        1
    );
    drop(store);
    Ok(())
}
#[test]
fn session_push_requires_gateway_peer() -> anyhow::Result<()> {
    let (_path, router, _) = seed("push-auth")?;
    for path in [
        "/mvp0/issued-seqs",
        "/mvp0/ack-bound-batch",
        "/mvp1/session-push-capabilities",
        "/mvp0/ephemeral-registrations",
        "/mvp1/inbox-entry/target/1",
        "/mvp1/inbox/target?session_push=1",
    ] {
        let response = super::super::handle_mesh_request_value(
            ramflux_transport::MeshHttpRequest {
                method: "GET".into(),
                path: path.into(),
                body: vec![],
            },
            &router,
            "ramflux-federation",
        )?;
        assert_eq!(response.status, "403 Forbidden");
    }
    drop(router);
    Ok(())
}
#[test]
fn capable_establishment_initializes_empty_inbox() -> anyhow::Result<()> {
    let (_path, state, store) = crate::router_runtime::tests::test_router("capable-empty")?;
    let router = RouterHandle::tokio(state, store, None);
    let session = ramflux_node_core::SessionDescriptor {
        target_delivery_id: "target_alice".into(),
        device_id: "alice_phone".into(),
        gateway_id: "gateway".into(),
        session_id: "session".into(),
        device_epoch: 1,
        session_seq: 1,
        last_cursor: None,
        push_alias_hash: None,
        lifecycle: ramflux_node_core::SessionLifecycle::Live,
    };
    let request = ramflux_node_core::SessionPushSessionRequest {
        session,
        session_push: true,
        ephemeral: false,
    };
    let response = call(&router, "POST", "/s1/session", serde_json::to_value(request)?)?;
    let id = response["incarnation_id"].as_str().ok_or_else(|| anyhow::anyhow!("E"))?;
    assert_eq!(id.len(), 32);
    assert_eq!(router.store().inbox_status("target_alice")?, (Some(id.into()), 0));
    let page = call(
        &router,
        "GET",
        &format!("/mvp1/inbox/target_alice?session_push=1&incarnation_id={id}&limit=1"),
        Value::Null,
    )?;
    assert_eq!(page["issued_inbox_seq"], 0);
    assert_eq!(page["settled_through_seq"], 0);
    drop(router);
    Ok(())
}
#[test]
fn fanout_mesh_retains_acceptance_metadata() -> anyhow::Result<()> {
    for quic in [false, true] {
        fanout_metadata_case(quic)?;
    }
    Ok(())
}
fn fanout_metadata_case(quic: bool) -> anyhow::Result<()> {
    let (path, state, store) = crate::router_runtime::tests::test_router("fanout-metadata")?;
    crate::router_runtime::tests::register_test_device_at(
        &state,
        "alice",
        "alice_tablet",
        "target_tablet",
        2,
        i64::try_from(ramflux_node_core::now_unix_seconds())?,
    )?;
    store.record_identity_registry(&state.mvp1_identities_snapshot())?;
    let router = RouterHandle::tokio(state, store, None);
    let envelope =
        crate::router_runtime::tests::current_envelope("fanout-metadata", "target_alice")?;
    let body = json!({"principal_id":"alice","source_device_id":"alice_phone","envelope":envelope});
    let response = if quic {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(super::super::handle_mesh_quic_request_value(
                &ramflux_transport::GatewayQuicRequest {
                    method: "POST".into(),
                    path: "/mvp10/own-devices/fanout".into(),
                    body,
                },
                &router,
                "ramflux-gateway",
            ))?
            .body
    } else {
        call(&router, "POST", "/mvp10/own-devices/fanout", body)?
    };
    let rows = response["delivered"].as_array().ok_or_else(|| anyhow::anyhow!("rows"))?;
    assert_ne!(rows.len(), 0);
    for row in rows {
        let target = row["target_delivery_id"].as_str().ok_or_else(|| anyhow::anyhow!("target"))?;
        let seq = row["inbox_seq"].as_u64().ok_or_else(|| anyhow::anyhow!("seq: {row}"))?;
        let point = serde_json::to_value(router.state().fetch_entry(target, seq, 0)?)?;
        assert_eq!(row["incarnation_id"], point["incarnation_id"]);
        assert_eq!(row["retain_until"], point["record"]["retain_until"]);
    }
    drop(router);
    std::fs::remove_file(path)?;
    Ok(())
}

mod revocation_tests;

#[test]
fn capable_nack_is_incarnation_fenced_and_durable() -> anyhow::Result<()> {
    let (path, router, response) = seed("capable-nack")?;
    let id = response["incarnation_id"].as_str().ok_or_else(|| anyhow::anyhow!("E"))?;
    let before = router.state().resume("target", 0, 10);
    let envelope_id = before[0].envelope.envelope_id.clone();
    let nack = |seq| json!({"schema":"ramflux.nack.v1","version":1,"domain":"ramflux.nack.v1","signing_key_id":"test","signature_alg":"ed25519","signature":"fixture","nack_id":"nack","envelope_id":envelope_id,"receiver_device_id":"device","reason":"invalid_signature","received_at":1,"ext":{"inbox_seq":seq}});
    let stale = call(
        &router,
        "POST",
        "/mvp0/nack-bound",
        json!({"target_delivery_id":"target","incarnation_id":"ffffffffffffffffffffffffffffffff","nack":nack(ramflux_protocol::MAX_SAFE_JSON_INTEGER)}),
    )?;
    assert_eq!(stale["reason"], "incarnation_mismatch");
    for seq in [0, 2] {
        assert_eq!(
            call(
                &router,
                "POST",
                "/mvp0/nack-bound",
                json!({"target_delivery_id":"target","incarnation_id":id,"nack":nack(seq)})
            )?["reason"],
            "invalid_seq"
        );
    }
    assert_eq!(router.state().resume("target", 0, 10), before);
    let held = router.store().acquire_acknowledgement("target")?;
    let started = std::time::Instant::now();
    let busy = call(
        &router,
        "POST",
        "/mvp0/nack-bound",
        json!({"target_delivery_id":"target","incarnation_id":id,"nack":nack(1)}),
    )?;
    assert_eq!(busy["reason"], "busy");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    drop(held);
    for _ in 0..3 {
        let reply = call(
            &router,
            "POST",
            "/mvp0/nack-bound",
            json!({"target_delivery_id":"target","incarnation_id":id,"nack":nack(1)}),
        )?;
        assert_eq!(reply["incarnation_id"], id);
        assert_eq!(reply["cursor"]["target_delivery_id"], "target");
    }
    assert_eq!(router.state().resume("target", 0, 10), []);
    drop(router);
    let store = ramflux_node_core::RouterRedbStore::open(&path)?;
    let restored = store.load_router()?.ok_or_else(|| anyhow::anyhow!("router restore"))?;
    assert_eq!(restored.resume("target", 0, 10), []);
    drop(store);
    Ok(())
}

#[test]
fn legacy_nack_keeps_cursor_shape() -> anyhow::Result<()> {
    let (_path, router, accepted) = seed("legacy-nack-cursor")?;
    let row = router
        .state()
        .resume("target", 0, 1)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("entry"))?;
    let nack = json!({"schema":"ramflux.nack.v1","version":1,"domain":"ramflux.nack.v1","signing_key_id":"test","signature_alg":"ed25519","signature":"fixture","nack_id":"legacy","envelope_id":row.envelope.envelope_id,"receiver_device_id":"device","reason":"invalid_signature","received_at":1,"ext":{"inbox_seq":1}});
    let legacy = call(
        &router,
        "POST",
        "/mvp0/nack-bound",
        json!({"target_delivery_id":"target","nack":nack}),
    )?;
    assert!(legacy.get("incarnation_id").is_none());
    let cursor: ramflux_node_core::InboxCursorResponse = serde_json::from_value(legacy)?;
    assert_eq!(cursor.target_delivery_id, "target");
    let modern = call(
        &router,
        "POST",
        "/mvp0/nack-bound",
        json!({"target_delivery_id":"target","incarnation_id":accepted["incarnation_id"],"nack":nack}),
    )?;
    assert_eq!(modern["incarnation_id"], accepted["incarnation_id"]);
    assert_eq!(modern["cursor"]["target_delivery_id"], "target");
    drop(router);
    Ok(())
}
