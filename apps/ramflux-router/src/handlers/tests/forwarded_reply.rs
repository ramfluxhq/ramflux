// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise the ACK wrapper on both authenticated dispatch surfaces and after reopen.
use super::*;

async fn reply(
    handle: &crate::router_runtime::RouterHandle,
    body: &serde_json::Value,
    quic: bool,
) -> anyhow::Result<serde_json::Value> {
    if quic {
        let response = handle_mesh_quic_request_value(
            &ramflux_transport::GatewayQuicRequest {
                method: "POST".into(),
                path: "/mvp0/envelope/forwarded".into(),
                body: body.clone(),
            },
            handle,
            "ramflux-federation",
        )
        .await?;
        assert_eq!(response.status, 200);
        Ok(response.body)
    } else {
        // Production HTTP dispatch runs on a blocking connection thread.
        let request = ramflux_transport::MeshHttpRequest {
            method: "POST".into(),
            path: "/mvp0/envelope/forwarded".into(),
            body: serde_json::to_vec(body)?,
        };
        let handle = handle.clone();
        let response = tokio::task::spawn_blocking(move || {
            handle_mesh_request_value(request, &handle, "ramflux-federation")
        })
        .await??;
        assert_eq!(response.status, "200 OK");
        Ok(serde_json::from_slice(&response.body)?)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn forwarded_wire_reply_refuses_dormant_and_acks_durable_duplicate_after_restart()
-> anyhow::Result<()> {
    for quic in [false, true] {
        let (state, store, path) = crate::router_runtime::tests::test_router("forward-reply")?;
        let mut bodies = Vec::new();
        for target in ["dormant-target", "active-target"] {
            let mut envelope =
                crate::router_runtime::tests::current_envelope("wire-reply", target)?;
            state.refresh_registered_envelope_authority(&mut envelope)?;
            bodies.push(serde_json::json!({"envelope": envelope, "migration_evidence":null}));
        }
        store.bootstrap_router(&state)?;
        drop(store);
        // Install only the persisted dormant route: this fixture tests the wire mapping,
        // while node-core exercises the full cryptographic seal and activation protocol.
        {
            let db = redb::Database::open(&path)?;
            let tx = db.begin_write()?;
            tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_inbox_routes_v1"))?.insert(
                "dormant-target", serde_json::to_vec(&serde_json::json!({
                    "anchor":"wire-anchor","migration_id":"wire-move","epoch":1,"active":false,"released":false
                }))?.as_slice(),
            )?;
            tx.commit()?;
        }
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let handle = crate::router_runtime::RouterHandle::tokio(state, store, None);
        let dormant = reply(&handle, &bodies[0], quic).await?;
        assert_eq!(dormant["accepted"], false);
        assert_eq!(dormant["retryable"], true);
        assert_eq!(handle.state().resume("dormant-target", 0, 10), []);
        if quic {
            let refused = handle_mesh_quic_request_value(
                &ramflux_transport::GatewayQuicRequest {
                    method: "POST".into(),
                    path: "/mvp0/envelope/forwarded".into(),
                    body: bodies[1].clone(),
                },
                &handle,
                "ramflux-gateway",
            )
            .await?;
            assert_eq!(refused.status, 403);
            assert_eq!(handle.state().resume("active-target", 0, 10), []);
        }
        let accepted = reply(&handle, &bodies[1], quic).await?;
        assert_eq!(accepted["accepted"], true);
        assert_eq!(accepted["retryable"], false);
        assert_eq!(accepted["delivery"]["outcome"], "offline_queued");
        assert_eq!(accepted["delivery"]["inbox_seq"], 1);
        let point = serde_json::to_value(handle.state().fetch_entry("active-target", 1, 0)?)?;
        assert_eq!(accepted["delivery"]["incarnation_id"], point["incarnation_id"]);
        assert_eq!(accepted["delivery"]["retain_until"], point["record"]["retain_until"]);

        let original = handle.state().resume("active-target", 0, 10);
        assert_eq!(original.len(), 1);
        drop(handle);
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let state = Arc::new(store.load_router()?.ok_or_else(|| anyhow::anyhow!("router"))?);
        let handle = crate::router_runtime::RouterHandle::tokio(state, store, None);
        let duplicate = reply(&handle, &bodies[1], quic).await?;
        assert_eq!(duplicate["accepted"], true);
        assert_eq!(duplicate["retryable"], false);
        assert_eq!(
            duplicate["delivery"], accepted["delivery"],
            "retry retains original durable acceptance"
        );
        assert_eq!(handle.state().resume("active-target", 0, 10), original);
        assert_eq!(handle.state().resume("dormant-target", 0, 10), []);
        drop(handle);
        std::fs::remove_file(path)?;
    }
    Ok(())
}
