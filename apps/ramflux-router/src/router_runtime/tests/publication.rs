// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual async mesh fanout must wait on P without occupying the sole worker.
use super::*;

#[tokio::test]
async fn single_worker_reply_and_drop() -> anyhow::Result<()> {
    for mode in 0..=2 {
        let root = temp_store_path(&format!("fanout-publication-{mode}"))?;
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        let store = Arc::new(ramflux_node_core::publication::open_durability_fixture(&root, mode)?);
        register_test_device(&state, "alice", "alice_phone", "target_alice", 1)?;
        register_test_device(&state, "alice", "alice_laptop", "target_laptop", 2)?;
        store.record_identity_registry(&state.mvp1_identities_snapshot())?;
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
            root.clone(),
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
