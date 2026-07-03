// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

mod clients;
#[cfg(all(target_os = "linux", feature = "compio-gateway"))]
mod compio_gateway;
#[cfg(feature = "itest-http")]
mod itest_http;
mod quic_dispatch;
mod serve;
mod session;
mod state;

use std::sync::{Arc, Mutex};

pub(crate) use clients::{
    gateway_state, notify_http_client, notify_offline_wake, router_cursor, router_get_json,
    router_inbox, router_mesh_client, router_post_json, router_post_json_async, router_session,
};
#[cfg(feature = "itest-http")]
pub(crate) use clients::{is_timeout_error, pre_auth_gate};
#[cfg(feature = "itest-http")]
pub(crate) use itest_http::serve_itest_http;
pub(crate) use quic_dispatch::dispatch_quic_json_request;
pub(crate) use serve::serve_gateway_quic;
pub(crate) use state::{
    GatewayForwardDeliverRequest, GatewayForwardDeliverResponse, GatewayPeerDirectory,
    GatewayQuicContext, GatewaySendHandle, GatewaySessionHub, GatewaySessionRuntime,
    NotifyHttpClient, NotifyMeshClient, RouterAsyncMeshClient, RouterMeshClient,
    gateway_instance_id_from_env, gateway_peer_directory_from_env,
};

fn main() {
    if let Err(error) = run_service("ramflux-gateway") {
        eprintln!("ramflux-gateway: {error}");
        std::process::exit(2);
    }
}

fn run_service(service: &'static str) -> anyhow::Result<()> {
    if std::env::args().any(|arg| arg == "--health-check") {
        println!("{service}:healthy");
        return Ok(());
    }
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        let store = ramflux_node_core::GatewayRedbStore::open(redb_path)?;
        let state = match store.load_state()? {
            Some(state) => state,
            None => ramflux_node_core::GatewayState::new(),
        };
        store.save_state(&state)?;
        tracing::info!(service, node_id = config.node_id, "gateway state initialized");
        let router = router_mesh_client(&config)?;
        let notify = notify_http_client(&config)?;
        let state = Arc::new(Mutex::new(state));
        let store = Arc::new(store);
        serve_gateway_quic(
            &config,
            router.clone(),
            notify.clone(),
            Arc::clone(&state),
            Arc::clone(&store),
        )?;
        #[cfg(feature = "itest-http")]
        if std::env::var("RAMFLUX_ITEST_HTTP").as_deref() == Ok("1") {
            return serve_itest_http(&router, &store, &state);
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
