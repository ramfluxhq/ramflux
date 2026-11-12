// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-tree router process with a separate durable store and a causal readiness event.
use crate::GatewayQuicContext;
use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
use std::io::BufRead;
use std::sync::atomic::Ordering;
use std::time::Duration;
pub(crate) struct Child(std::process::Child, std::path::PathBuf);
impl Child {
    pub(crate) fn root(&self) -> &std::path::Path {
        &self.1
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}
pub(crate) async fn real_router_with_custody(
    node: Option<&ramflux_crypto::custody::VerifiedNodeRecord>,
) -> anyhow::Result<(Child, GatewayQuicContext)> {
    let binary = std::env::var_os("RAMFLUX_P17_ROUTER_BINARY")
        .ok_or_else(|| anyhow::anyhow!("same-tree router binary is required"))?;
    let root = temp_cert_root("p17-real-router").map_err(|e| anyhow::anyhow!("{e}"))?;
    let gateway = issue_test_ca_and_service_cert(&root, "test-node", "ramflux-gateway")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let router = issue_test_ca_and_service_cert(&root, "test-node", "ramflux-router")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let roots = root.join("roots.pem");
    std::fs::write(&roots, format!("{}\n{}", gateway.ca_pem, router.ca_pem))?;
    let udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let endpoint = udp.local_addr()?.to_string();
    let config = root.join("router.toml");
    std::fs::write(
        &config,
        format!(
            "node_id = \"test-node\"\nservice_id = \"ramflux-router\"\nredb_path = {:?}\n[mesh]\nlisten_addr = \"127.0.0.1:0\"\nca_cert = {:?}\nservice_cert = {:?}\nservice_key = {:?}\nallowed_service_ids = [\"ramflux-gateway\",\"ramflux-router\"]\n[mesh.endpoints]\nrouter = {:?}\n",
            root.join("router.redb"),
            roots,
            router.tls.service_cert,
            router.tls.service_key,
            endpoint
        ),
    )?;
    ramflux_node_core::load_config(&config, "ramflux-router")?;
    drop(udp);
    let mut command = std::process::Command::new(binary);
    command.env_remove("RAMFLUX_CUSTODY_ALLOW_NO_CHANNEL_BINDING");
    if let Some(node) = node {
        let path = root.join("custody-node.json");
        std::fs::write(&path, serde_json::to_vec(node.envelope())?)?;
        command.env("RAMFLUX_CUSTODY_NODE_RECORD_FILE", &path);
        command
            .env("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", &node.envelope().body.node_signing_public_key);
        if node
            .envelope()
            .body
            .channel_binding_modes
            .contains(&ramflux_protocol::custody::BindingMode::NoChannelBinding)
        {
            command.env("RAMFLUX_CUSTODY_ALLOW_NO_CHANNEL_BINDING", "1");
        }
    }
    let process = command
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
    context.node_id = "test-node".into();
    context.store = std::sync::Arc::new(ramflux_node_core::GatewayRedbStore::open(
        child.1.join("gateway.redb"),
    )?);
    context.store.save_state(&*crate::gateway_state(&context.state)?)?;
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
