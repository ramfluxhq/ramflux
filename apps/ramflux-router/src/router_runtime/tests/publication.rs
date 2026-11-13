// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual async mesh fanout must wait on P without occupying the sole worker.
use super::*;

#[test]
fn single_worker_reply_and_drop() -> anyhow::Result<()> {
    let (done, result) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let outcome = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(anyhow::Error::from)
            .and_then(|runtime| runtime.block_on(single_worker_reply_and_drop_inner()));
        let _ = done.send(outcome);
    });
    result.recv_timeout(Duration::from_secs(40)).map_err(|_| {
        anyhow::anyhow!("single-worker runtime blocked before publication continuation")
    })?
}

async fn single_worker_reply_and_drop_inner() -> anyhow::Result<()> {
    for mode in 0..=2 {
        let root = temp_store_path(&format!("fanout-publication-{mode}"))?;
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        let store = Arc::new(ramflux_node_core::publication::open_durability_fixture(&root, mode)?);
        register_test_device(&state, "alice", "alice_phone", "target_alice", 1)?;
        register_test_device(&state, "alice", "alice_laptop", "target_laptop", 2)?;
        store.record_identity_registry(&state.mvp1_identities_snapshot())?;
        store.initialize_inbox("target_laptop")?;
        state.prepare_publication_target(&store, "target_laptop")?;
        let core = store.publication_core()?;
        let id =
            store.inbox_status("target_laptop")?.0.ok_or_else(|| anyhow::anyhow!("identity"))?;
        let guard = core.reserve("target_laptop", &id, &[])?;
        let (release, continuation) = tokio::sync::oneshot::channel();
        let first_core = Arc::clone(&core);
        let first = tokio::spawn(async move {
            continuation.await?;
            guard.definite_non_write();
            first_core.wait_published(&guard).await;
            Ok::<_, anyhow::Error>(())
        });
        let durable = Arc::new(tokio::sync::Notify::new());
        let progress_signal = Arc::clone(&durable);
        let observer = ramflux_node_core::durability_test_hooks::observe(
            root.to_path_buf(),
            Arc::new(move |_, op, done| {
                if op == "accepted_assignment" && done {
                    progress_signal.notify_one();
                }
                Ok(())
            }),
        );
        let handle = RouterHandle::tokio(Arc::clone(&state), Arc::clone(&store), None);
        let request = fanout_request("held-fanout")?;
        let request = ramflux_transport::GatewayQuicRequest {
            method: "POST".into(),
            path: "/mvp10/own-devices/fanout".into(),
            body: serde_json::to_value(request)?,
        };
        let second = tokio::spawn(async move {
            crate::handlers::handle_mesh_quic_request_value(&request, &handle, "ramflux-gateway")
                .await
        });
        tokio::time::timeout(Duration::from_secs(30), durable.notified()).await?;
        tokio::task::yield_now().await;
        assert!(!second.is_finished());
        assert!(!first.is_finished());
        assert_eq!(store.inbox_status("target_laptop")?.1, 2);
        assert_eq!(state.resume("target_laptop", 0, 10).len(), 0);
        let heartbeat = tokio::spawn(async {
            tokio::task::yield_now().await;
            7
        });
        assert_eq!(heartbeat.await?, 7);
        release.send(()).map_err(|()| anyhow::anyhow!("first continuation"))?;
        tokio::time::timeout(Duration::from_secs(30), first).await???;
        let response = tokio::time::timeout(Duration::from_secs(30), second).await???;
        assert_eq!(response.body["delivered"][0]["inbox_seq"], 2);
        assert_eq!(state.resume("target_laptop", 0, 10).len(), 1);
        drop(observer);
        drop(state);
        drop(core);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[tokio::test]
async fn async_mesh_submit_waits_for_publication() -> anyhow::Result<()> {
    for mode in 0..3 {
        let root = temp_store_path(&format!("mesh-submit-publication-{mode}"))?;
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        let store = Arc::new(ramflux_node_core::publication::open_durability_fixture(&root, mode)?);
        register_test_device(&state, "alice", "alice_phone", "target_alice", 1)?;
        store.record_identity_registry(&state.mvp1_identities_snapshot())?;
        store.initialize_inbox("target_alice")?;
        state.prepare_publication_target(&store, "target_alice")?;
        let core = store.publication_core()?;
        let id =
            store.inbox_status("target_alice")?.0.ok_or_else(|| anyhow::anyhow!("identity"))?;
        let predecessor = core.reserve("target_alice", &id, &[])?;
        let durable = Arc::new(tokio::sync::Notify::new());
        let signal = Arc::clone(&durable);
        let observer = ramflux_node_core::durability_test_hooks::observe(
            root.to_path_buf(),
            Arc::new(move |_, op, done| {
                if op == "accepted_assignment" && done {
                    signal.notify_one();
                }
                Ok(())
            }),
        );
        let handle = RouterHandle::tokio(Arc::clone(&state), Arc::clone(&store), None);
        let envelope = current_envelope("held-mesh-submit", "target_alice")?;
        let request = ramflux_transport::GatewayQuicRequest {
            method: "POST".into(),
            path: "/mvp0/envelope".into(),
            body: serde_json::to_value(envelope)?,
        };
        let response = tokio::spawn(async move {
            crate::handlers::handle_mesh_quic_request_value(&request, &handle, "ramflux-gateway")
                .await
        });
        tokio::time::timeout(Duration::from_secs(30), durable.notified()).await?;
        tokio::task::yield_now().await;
        assert_eq!(store.inbox_status("target_alice")?.1, 2);
        assert_eq!(core.view("target_alice", &id).0, 0);
        assert_eq!(state.resume("target_alice", 0, 10), []);
        assert!(!response.is_finished(), "async mesh reply escaped held predecessor");
        predecessor.definite_non_write();
        let response = tokio::time::timeout(Duration::from_secs(30), response).await???;
        assert_eq!(response.body["inbox_seq"], 2);
        assert_eq!(state.resume("target_alice", 0, 10).len(), 1);
        drop(predecessor);
        drop(observer);
        drop(state);
        drop(core);
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[tokio::test]
async fn retired_preparation_is_a_typed_router_response() -> anyhow::Result<()> {
    let root = temp_store_path("typed-retirement")?;
    let state = Arc::new(ramflux_node_core::RouterCore::new());
    let store = Arc::new(ramflux_node_core::publication::open_durability_fixture(&root, 0)?);
    register_test_device(&state, "alice", "alice_phone", "target_alice", 1)?;
    store.record_identity_registry(&state.mvp1_identities_snapshot())?;
    store.initialize_inbox("target_alice")?;
    state.prepare_publication_target(&store, "target_alice")?;
    store.publication_core()?.retire_fixture_target("target_alice")?;
    let handle = RouterHandle::tokio(Arc::clone(&state), Arc::clone(&store), None);
    let request = ramflux_transport::GatewayQuicRequest {
        method: "POST".into(),
        path: "/mvp0/envelope".into(),
        body: serde_json::to_value(current_envelope("retired-submit", "target_alice")?)?,
    };
    let response =
        crate::handlers::handle_mesh_quic_request_value(&request, &handle, "ramflux-gateway")
            .await?;
    assert_eq!(response.status, 200);
    assert_eq!(response.body["outcome"], "incarnation_mismatch");
    assert!(response.body["inbox_seq"].is_null());
    drop(handle);
    drop(state);
    drop(store);
    Ok(())
}
