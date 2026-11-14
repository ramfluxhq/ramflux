// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Negotiation through a same-tree production router process.
use super::*;
use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
use std::io::BufRead;
struct Child(std::process::Child, ramflux_test_support::TestPath);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn real_router() -> anyhow::Result<(Child, GatewayQuicContext)> {
    real_router_with_state(None).await
}
async fn real_router_with_state(
    seed: Option<&ramflux_node_core::RouterCore>,
) -> anyhow::Result<(Child, GatewayQuicContext)> {
    let root = temp_cert_root("p17-real-router").map_err(|e| anyhow::anyhow!("{e}"))?;
    let gateway = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-gateway")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let router = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-router")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let roots = root.join("roots.pem");
    std::fs::write(&roots, format!("{}\n{}", gateway.ca_pem, router.ca_pem))?;
    let udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let endpoint = udp.local_addr()?.to_string();
    let config = root.join("router.toml");
    std::fs::write(
        &config,
        format!(
            "node_id = \"node-test\"\nservice_id = \"ramflux-router\"\nredb_path = {:?}\n[mesh]\nlisten_addr = \"127.0.0.1:0\"\nca_cert = {:?}\nservice_cert = {:?}\nservice_key = {:?}\nallowed_service_ids = [\"ramflux-gateway\",\"ramflux-router\"]\n[mesh.endpoints]\nrouter = {:?}\n",
            root.join("router.redb"),
            roots,
            router.tls.service_cert,
            router.tls.service_key,
            endpoint
        ),
    )?;
    ramflux_node_core::load_config(&config, "ramflux-router")?;
    drop(udp);
    if let Some(seed) = seed {
        let store = ramflux_node_core::RouterRedbStore::open(root.join("router.redb"))?;
        store.save_router(seed)?;
    }
    let process = std::process::Command::new(
        std::env::var_os("RAMFLUX_P17_ROUTER_BINARY")
            .ok_or_else(|| anyhow::anyhow!("same-tree router binary is required"))?,
    )
    .arg("--config")
    .arg(&config)
    .env("RUST_LOG", "info")
    .env("RAMFLUX_ROUTER_ASYNC_LISTEN_ADDR", &endpoint)
    .env("RAMFLUX_ROUTER_ASYNC_INGRESS_RUNTIME", "tokio")
    .env("RAMFLUX_ROUTER_ASYNC_INGRESS_SOCKETS", "1")
    .env("RAMFLUX_ROUTER_ASYNC_WORKER_THREADS", "2")
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::inherit())
    .spawn()?;
    let mut child = Child(process, root);
    let output =
        child.0.stdout.take().ok_or_else(|| anyhow::anyhow!("router output unavailable"))?;
    let (started, ready) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let mut started = Some(started);
        for line in std::io::BufReader::new(output).lines().map_while(Result::ok) {
            if line.contains("router async QUIC endpoint bound")
                && let Some(started) = started.take()
            {
                let _ = started.send(());
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(15), ready).await??;
    let (_fixture_directory_0, mut context) = crate::session::tests::test_gateway_context()?;
    context.store =
        Arc::new(ramflux_node_core::GatewayRedbStore::open(child.1.join("gateway.redb"))?);
    context.store.configure_replay(
        ramflux_node_core::test_support::federation_fixtures::gateway_replay_fixture_config(),
        0,
    )?;
    {
        let state = crate::gateway_state(&context.state)?;
        context.store.save_state(&state)?;
    }
    context.hub.probe_started.store(true, Ordering::Release);
    context.router = crate::RouterMeshClient {
        endpoint: endpoint.clone(),
        server_name: "ramflux-router".into(),
        tls: gateway.tls.clone(),
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: Some(crate::RouterAsyncMeshClient {
            endpoint,
            server_name: "ramflux-router".into(),
            tls: gateway.tls,
            peer_ca_pems: vec![router.ca_pem],
        }),
    };
    Ok((child, context))
}

/// Run explicitly with `RAMFLUX_P17_ROUTER_BINARY` pointing at the same-tree router.
#[tokio::test]
#[ignore = "requires a separately built same-tree router binary"]
async fn session_push_capability_negotiation_real_router() -> anyhow::Result<()> {
    let (_child, context) = real_router().await?;
    context.hub.readiness.start_with_hub(&context.router, &context.hub, &context.gateway_id);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !context.hub.readiness.supports() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let mut session = descriptor();
    session.gateway_id = context.gateway_id.clone();
    let legacy = negotiate(&context, &auth(false)?, &session).await?;
    assert_eq!(legacy.incarnation_id, None);
    assert!(!legacy.ephemeral);
    let binding = negotiate(&context, &auth(true)?, &session).await?;
    let id = binding
        .incarnation_id
        .ok_or_else(|| anyhow::anyhow!("actual router refused capable binding"))?;
    assert!(!binding.ephemeral);
    assert!(ramflux_node_core::valid_inbox_incarnation(&id));
    let issued: Value = crate::router_post_json_async(
        &context.router,
        "/mvp0/issued-seqs",
        &json!({"targets":["target"]}),
    )
    .await?;
    assert_eq!(issued["issued"][0]["incarnation_id"], id);
    assert_eq!(issued["issued"][0]["inbox_seq"], 0);
    Ok(())
}

#[path = "activation_tests.rs"]
mod activation;

#[path = "activation_account_tests.rs"]
mod activation_account;
