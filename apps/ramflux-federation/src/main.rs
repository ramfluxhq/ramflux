// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

mod admin_http;
mod discovery;
mod flow;
mod helpers;
mod http_limits;
#[cfg(test)]
mod http_listener_tests;
#[cfg(test)]
mod http_request_limits_tests;
#[cfg(feature = "itest-http")]
mod itest_http;
mod key_migration;
mod mesh;
mod public_http;
mod state;
#[cfg(test)]
mod test_certificates;

use std::sync::Arc;

pub(crate) use admin_http::{FederationAdminHttpContext, serve_admin_http};
pub(crate) use discovery::{federation_discovery_surface, federation_node_signing_seed};
pub(crate) use flow::{
    handle_s8_forward_envelope, handle_s8_receive_envelope, handle_s12_discovery_resolve,
    start_outbound_spool_retry_loop,
};
pub(crate) use helpers::{
    mesh_tls_config, mesh_transport_error, now_unix_seconds, router_get_json, router_mesh_client,
    router_post_json,
};
#[cfg(feature = "itest-http")]
pub(crate) use itest_http::serve_itest_http;
pub(crate) use mesh::serve_federation_mesh_mtls;
pub(crate) use state::{
    FederationAdminDiscoverRequest, FederationAdminPeerRequest, FederationAdminPeerResponse,
    FederationDiscoverySurface, FederationMeshObservability, MeshInboundTransport,
    RouterAsyncMeshClient, RouterMeshClient, S12DiscoveryResolveRequest,
    SharedFederationTrustState, SharedMeshObservability,
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
        let mut store = ramflux_node_core::FederationRedbStore::open(&redb_path)?;
        let mut state = match store.load_state()? {
            Some(state) => state,
            None => ramflux_node_core::FederationTrustState::new(),
        };
        if let Some(path) = std::env::args().skip_while(|arg| arg != "--export-signing-seed").nth(1)
        {
            ramflux_node_core::NodeSecret::require_external_path(
                std::path::Path::new(&path),
                std::path::Path::new(&redb_path),
            )?;
            key_migration::export(&state, &path)?;
            return Ok(());
        }
        let secret_path =
            ramflux_node_core::environment::var_os("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE")
                .ok_or_else(|| {
                    ramflux_node_core::NodeCoreError::Unauthorized(
                        "mounted federation secret required".into(),
                    )
                })?;
        ramflux_node_core::NodeSecret::require_external_path(
            std::path::Path::new(&secret_path),
            std::path::Path::new(&redb_path),
        )?;
        let had_legacy_seed = state.node_signing_seed().is_some();
        let node_signing_seed = federation_node_signing_seed(&mut state)?;
        store.verify_mounted_signing_identity(node_signing_seed)?;
        store.save_state(&state)?;
        if had_legacy_seed {
            store.compact_migrated_secrets()?;
        }
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
        serve_federation_mesh_mtls(
            &config,
            &state,
            &store,
            &router,
            &mesh_observability,
            &discovery,
        )?;
        let public_addr = ramflux_node_core::environment::var("RAMFLUX_FEDERATION_PUBLIC_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:18082".to_owned());
        public_http::serve_public_http(
            &public_addr,
            public_http::FederationPublicHttpContext {
                router: Arc::clone(&router),
                discovery: discovery.clone(),
            },
        )?;
        let admin_addr = ramflux_node_core::environment::var("RAMFLUX_FEDERATION_ADMIN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:18089".to_owned());
        serve_admin_http(
            &admin_addr,
            FederationAdminHttpContext {
                store: Arc::clone(&store),
                state: Arc::clone(&state),
                router: Arc::clone(&router),
                discovery: discovery.clone(),
                mesh_observability: Arc::clone(&mesh_observability),
                admin_token: ramflux_node_core::environment::var("RAMFLUX_FEDERATION_ADMIN_TOKEN")
                    .ok(),
            },
        )?;
        #[cfg(feature = "itest-http")]
        if ramflux_node_core::environment::var("RAMFLUX_ITEST_HTTP").as_deref() == Ok("1") {
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
