// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Negotiation through a same-tree production router process.
use super::*;
use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
use std::io::BufRead;
struct Child(std::process::Child, std::path::PathBuf);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}
async fn real_router() -> anyhow::Result<(Child, GatewayQuicContext)> {
    let binary = std::env::var_os("RAMFLUX_P17_ROUTER_BINARY")
        .ok_or_else(|| anyhow::anyhow!("same-tree router binary is required"))?;
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
            "node_id = \"node-test\"\nservice_id = \"ramflux-router\"\nredb_path = {:?}\n[mesh]\nlisten_addr = \"127.0.0.1:0\"\nca_cert = {:?}\nservice_cert = {:?}\nservice_key = {:?}\nallowed_service_ids = [\"ramflux-gateway\"]\n",
            root.join("router.redb"),
            roots,
            router.tls.service_cert,
            router.tls.service_key
        ),
    )?;
    drop(udp);
    let process = std::process::Command::new(binary)
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
    let mut context = crate::session::tests::test_gateway_context()?;
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

/// Run explicitly with RAMFLUX_P17_ROUTER_BINARY pointing at the same-tree router.
#[tokio::test]
#[ignore = "requires a separately built same-tree router binary"]
async fn session_push_capability_negotiation_real_router() -> anyhow::Result<()> {
    let (_child, context) = real_router().await?;
    context.hub.readiness.start(&context.router);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !context.hub.readiness.supports() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(negotiate(&context, &auth(false)?, &descriptor()).await?, None);
    let id = negotiate(&context, &auth(true)?, &descriptor())
        .await?
        .ok_or_else(|| anyhow::anyhow!("actual router refused capable binding"))?;
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
