// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

mod handlers;
mod lifecycle;
mod router_engine;
mod router_runtime;
mod serve;

use std::sync::Arc;

#[cfg(feature = "itest-http")]
use serve::serve_itest_http;
use serve::serve_router_mesh_mtls;

const ROUTER_FEDERATION_FORWARD_URL_ENV: &str = "RAMFLUX_ROUTER_FEDERATION_FORWARD_URL";
const ROUTER_FEDERATION_FORWARD_TOKEN_ENV: &str = "RAMFLUX_ROUTER_FEDERATION_FORWARD_TOKEN";
const ROUTER_FEDERATION_FORWARD_SOURCE_NODE_ID_ENV: &str =
    "RAMFLUX_ROUTER_FEDERATION_FORWARD_SOURCE_NODE_ID";

fn main() {
    if let Err(error) = run_service("ramflux-router") {
        eprintln!("ramflux-router: {error}");
        std::process::exit(2);
    }
}

fn run_service(service: &'static str) -> anyhow::Result<()> {
    if std::env::args().any(|arg| arg == "--health-check") {
        println!("{service}:healthy");
        return Ok(());
    }
    if std::env::args().any(|arg| arg == "--mesh-health-smoke") {
        let _ = tracing_subscriber::fmt().with_target(false).try_init();
        return run_mesh_health_smoke(service);
    }
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        let store = ramflux_node_core::RouterRedbStore::open(redb_path)?;
        let router = match store.load_router()? {
            Some(router) => router,
            None => ramflux_node_core::RouterCore::new(),
        };
        router.set_local_home_node_id(Some(config.node_id.clone()));
        if let Some(signer) = ramflux_node_core::node_service_signing_key_from_config(&config)? {
            router.set_node_franking_public_key(Some(signer.public_key_base64url().to_owned()));
            router.set_node_service_signer(Some(signer));
        }
        tracing::info!(service, node_id = config.node_id, "router store initialized");
        let home_node_forward = local_federation_forward_client_from_env(&config);
        let state = Arc::new(router);
        let store = Arc::new(store);
        let router = Arc::new(router_handle_from_env(state, store, home_node_forward));
        serve_router_mesh_from_env(&config, &router)?;
        #[cfg(feature = "itest-http")]
        if std::env::var("RAMFLUX_ITEST_HTTP").as_deref() == Ok("1") {
            return serve_itest_http(&router);
        }
        if std::env::args().any(|arg| arg == "--once") {
            return Ok(());
        }
        std::thread::park();
        return Ok(());
    }
    tracing::info!(service, "service initialized");
    if std::env::args().any(|arg| arg == "--once") {
        return Ok(());
    }
    std::thread::park();
    Ok(())
}

fn run_mesh_health_smoke(service: &'static str) -> anyhow::Result<()> {
    let args = std::env::args().skip(1).filter(|arg| arg != "--mesh-health-smoke");
    let Some(config) = ramflux_node_core::load_config_from_args(args, service)? else {
        anyhow::bail!("--mesh-health-smoke requires --config");
    };
    run_mesh_health_smoke_with_config(&config)
}

fn run_mesh_health_smoke_with_config(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<()> {
    let endpoint = std::env::var("RAMFLUX_ROUTER_MESH_HEALTH_ENDPOINT")
        .ok()
        .or_else(|| config.mesh.endpoints.get("router").cloned())
        .unwrap_or_else(|| config.mesh.listen_addr.clone());
    run_mesh_health_smoke_client(config, &endpoint)
}

fn run_mesh_health_smoke_client(
    config: &ramflux_node_core::NodeServiceConfig,
    endpoint: &str,
) -> anyhow::Result<()> {
    let server_name = std::env::var("RAMFLUX_ROUTER_MESH_HEALTH_SERVER_NAME")
        .unwrap_or_else(|_| "ramflux-router".to_owned());
    let tls = serve::mesh_tls_config(config);
    let client = ramflux_transport::MeshHttpClient::new();
    for request_index in 0..2 {
        let response: serde_json::Value =
            client.get_json(endpoint, "/healthz", &tls, &server_name)?;
        if response.get("service").and_then(serde_json::Value::as_str) != Some("ramflux-router") {
            anyhow::bail!("unexpected router mesh health response {request_index}: {response}");
        }
        if response.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
            anyhow::bail!("router mesh health response {request_index} is not ok: {response}");
        }
    }
    println!("ramflux-router:mesh-health-smoke endpoint={endpoint} requests=2 status=ok");
    Ok(())
}

fn serve_router_mesh_from_env(
    config: &ramflux_node_core::NodeServiceConfig,
    router: &Arc<router_runtime::RouterHandle>,
) -> anyhow::Result<()> {
    serve_router_mesh_mtls(config, router)
}

fn router_handle_from_env(
    state: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
    home_node_forward: Option<router_runtime::LocalFederationForwardClient>,
) -> router_runtime::RouterHandle {
    router_runtime::RouterHandle::tokio(state, store, home_node_forward)
}

fn local_federation_forward_client_from_env(
    config: &ramflux_node_core::NodeServiceConfig,
) -> Option<router_runtime::LocalFederationForwardClient> {
    let url = non_empty_env(ROUTER_FEDERATION_FORWARD_URL_ENV)?;
    let source_node_id = non_empty_env(ROUTER_FEDERATION_FORWARD_SOURCE_NODE_ID_ENV)
        .unwrap_or_else(|| config.node_id.clone());
    tracing::info!(
        url = %url,
        source_node_id = %source_node_id,
        "router home-node migration federation forward client enabled"
    );
    Some(router_runtime::LocalFederationForwardClient {
        url,
        admin_token: non_empty_env(ROUTER_FEDERATION_FORWARD_TOKEN_ENV),
        source_node_id,
    })
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}
