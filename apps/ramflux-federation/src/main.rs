// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

mod admin_http;
mod flow;
mod helpers;
#[cfg(feature = "itest-http")]
mod itest_http;
mod mesh;
mod state;

use std::sync::Arc;

pub(crate) use admin_http::{FederationAdminHttpContext, serve_admin_http};
pub(crate) use flow::{
    handle_s8_forward_envelope, handle_s8_receive_envelope, handle_s12_discovery_resolve,
    start_outbound_spool_retry_loop,
};
pub(crate) use helpers::{
    federation_discovery_surface, federation_node_signing_seed, mesh_tls_config,
    mesh_transport_error, now_unix_seconds, router_mesh_client,
};
#[cfg(feature = "itest-http")]
pub(crate) use itest_http::serve_itest_http;
pub(crate) use mesh::serve_federation_mesh_mtls;
pub(crate) use state::{
    FederationAdminDiscoverRequest, FederationAdminPeerRequest, FederationAdminPeerResponse,
    FederationDiscoverySurface, FederationMeshObservability, MeshInboundTransport,
    RouterMeshClient, S12DiscoveryResolveRequest, SharedFederationTrustState,
    SharedMeshObservability,
};
#[cfg(feature = "itest-http")]
pub(crate) use state::{ItestMvp4CanDeliverResponse, ItestMvp4TrustStatusRequest};

fn main() {
    if let Err(error) = run_service("ramflux-federation") {
        eprintln!("ramflux-federation: {error}");
        std::process::exit(2);
    }
}

fn run_service(service: &'static str) -> Result<(), ramflux_node_core::NodeCoreError> {
    if std::env::args().any(|arg| arg == "--health-check") {
        println!("{service}:healthy");
        return Ok(());
    }
    let _tracing_guard = init_tracing();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        let store = ramflux_node_core::FederationRedbStore::open(redb_path)?;
        let mut state = match store.load_state()? {
            Some(state) => state,
            None => ramflux_node_core::FederationTrustState::new(),
        };
        let node_signing_seed = federation_node_signing_seed(&mut state)?;
        store.save_state(&state)?;
        tracing::info!(service, node_id = config.node_id, "federation trust store initialized");
        let state = Arc::new(SharedFederationTrustState::new(state));
        let store = Arc::new(store);
        let router = Arc::new(router_mesh_client(&config)?);
        let mesh_observability = Arc::new(FederationMeshObservability::default());
        let discovery = federation_discovery_surface(&config, node_signing_seed);
        start_outbound_spool_retry_loop(
            Arc::clone(&store),
            Arc::clone(&state),
            Arc::clone(&router),
        );
        serve_federation_mesh_mtls(&config, &state, &router, &mesh_observability, &discovery)?;
        if let Ok(admin_addr) = std::env::var("RAMFLUX_FEDERATION_ADMIN_ADDR") {
            serve_admin_http(
                &admin_addr,
                FederationAdminHttpContext {
                    store: Arc::clone(&store),
                    state: Arc::clone(&state),
                    router: Arc::clone(&router),
                    discovery: discovery.clone(),
                    mesh_observability: Arc::clone(&mesh_observability),
                    admin_token: std::env::var("RAMFLUX_FEDERATION_ADMIN_TOKEN").ok(),
                },
            )?;
        }
        #[cfg(feature = "itest-http")]
        if std::env::var("RAMFLUX_ITEST_HTTP").as_deref() == Ok("1") {
            return serve_itest_http(&store, &state, &router, &discovery, &mesh_observability);
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

fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt().with_target(false).with_writer(writer).init();
    guard
}
