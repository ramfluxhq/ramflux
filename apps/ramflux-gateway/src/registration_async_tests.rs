// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Held router requests leave the actual current-thread session worker live.
use super::*;
use crate::session_push::tests::support::{Fixture, Source, runtime, sink};
use serde_json::{Value, json};

async fn held_frame(
    frame: Value,
    path: &str,
    reply: Value,
    expected: Value,
    deadline_reply: Value,
) -> anyhow::Result<()> {
    for deadline in [false, true] {
        let mut fixture = Fixture::new("registration-worker")?;
        let context = fixture.context.clone();
        let mut runtime = runtime()?;
        runtime.session_push = None;
        let (send, rows) = sink();
        let source = Source(std::collections::VecDeque::from([serde_json::to_vec(&frame)?]));
        let task = tokio::spawn(crate::session::run_gateway_session_loop(
            send,
            Box::new(source),
            context,
            runtime,
        ));
        let held = fixture.next().await?;
        assert_eq!(held.path, path);
        let mut forwarded = frame["request"].clone();
        if path == "/mvp1/identity/register" {
            forwarded["source_ip_hash"] = json!(ramflux_node_core::source_ip_hash(
                &fixture.context.remote_addr.ip().to_string(),
            ));
            assert!(held.body["now"].as_i64().is_some_and(|now| now > 1));
            forwarded["now"] = held.body["now"].clone();
        }
        assert_eq!(held.body, forwarded);
        // The router retains the response sender while a distinct task must run.
        let (beat, heartbeat) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = beat.send(());
        });
        tokio::time::timeout(std::time::Duration::from_secs(10), heartbeat)
            .await
            .map_err(|_| anyhow::anyhow!("heartbeat guard elapsed"))??;
        assert!(!task.is_finished(), "held router completed session request");
        if deadline {
            tokio::time::pause();
            tokio::time::advance(REGISTRATION_TIMEOUT).await;
            tokio::time::timeout(std::time::Duration::from_secs(10), task)
                .await
                .map_err(|_| anyhow::anyhow!("deadline task guard elapsed"))???;
            tokio::time::resume();
            // The caller's deadline must abort the live mesh request: the router observes the
            // client stop reading the response, and no reconnect retry reaches it afterwards.
            tokio::time::timeout(std::time::Duration::from_secs(10), fixture.cancelled.recv())
                .await
                .map_err(|_| anyhow::anyhow!("mesh cancellation guard elapsed"))?
                .ok_or_else(|| anyhow::anyhow!("mesh cancellation observer closed"))?;
            assert!(fixture.requests.try_recv().is_err(), "mesh retry reached the router");
        } else {
            held.respond
                .send((200, reply.clone()))
                .map_err(|_| anyhow::anyhow!("mesh response receiver closed"))?;
            tokio::time::timeout(std::time::Duration::from_secs(10), task)
                .await
                .map_err(|_| anyhow::anyhow!("reply task guard elapsed"))???;
        }
        let rows = rows.lock().map_err(|_| anyhow::anyhow!("frame capture poisoned"))?;
        assert_eq!(
            rows.as_slice(),
            &[if deadline { deadline_reply.clone() } else { expected.clone() }]
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn registration_mesh_keeps_worker_live() -> anyhow::Result<()> {
    let request =
        crate::registration_forward_tests::registration(1).map_err(|e| anyhow::anyhow!("{e}"))?;
    held_frame(
        json!({"frame_type":"identity_register","request":request}),
        "/mvp1/identity/register",
        json!({"error":{"reason_code":"invalid_registration"}}),
        json!({"frame_type":"identity_registration_rejected","reason_code":"invalid_registration"}),
        json!({"frame_type":"identity_registration_rejected","reason_code":"registration_unavailable"}),
    ).await
}

#[tokio::test(flavor = "current_thread")]
async fn prekey_mesh_keeps_worker_live() -> anyhow::Result<()> {
    let branch = ramflux_crypto::create_device_branch("peer", "device", 1, [32; 32]);
    let request = ramflux_node_core::PrekeyPublishRequest {
        device_id: "device".into(),
        bundle: ramflux_crypto::create_prekey_bundle(
            &branch,
            &ramflux_crypto::X25519KeyPair::from_seed([33; 32]),
            "signed",
            &ramflux_crypto::X25519KeyPair::from_seed([34; 32]),
            None,
            None,
        )?,
    };
    let reply = json!({"device_id":"device","bundle":null,"principal_commitment":"principal","target_delivery_id":"target"});
    held_frame(
        json!({"frame_type":"prekey_publish","request":request}),
        "/mvp1/prekey/publish",
        reply.clone(),
        json!({"frame_type":"prekey_published","response":reply}),
        json!({"frame_type":"nack","reason":"gateway_request_failed:prekey_publish"}),
    )
    .await
}
