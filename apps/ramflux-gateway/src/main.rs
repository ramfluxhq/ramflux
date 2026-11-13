// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

mod attachment_renewal;
mod clients;
#[cfg(all(target_os = "linux", feature = "compio-gateway"))]
mod compio_gateway;
mod custody;
#[cfg(test)]
mod durable_ingress_registry;
mod durable_mode;
mod ephemeral;
mod ephemeral_forward;
mod hub_index;
#[cfg(all(test, feature = "itest-http"))]
mod ijson_ingress_tests;
mod ingress;
mod ingress_log;
mod issued_probe;
#[cfg(feature = "itest-http")]
mod itest_http;
mod mesh_delivery;
mod object_issue;
mod pre_auth;
#[cfg(test)]
mod pre_auth_transport_tests;
mod principal_directory;
mod push_queue;
mod push_registration;
mod quic_dispatch;
#[cfg(test)]
mod real_router_fixture;
mod registration;
#[cfg(test)]
mod registration_forward_tests;
mod retention;
mod serve;
mod session;
mod session_hub;
mod session_push;
mod session_response;
mod state;
mod submit_source;
mod voice;

use std::sync::{Arc, Mutex};

pub(crate) use clients::{
    gateway_state, notify_http_client, notify_offline_wake, router_cursor_async,
    router_get_json_async, router_inbox_async, router_mesh_client, router_post_json,
    router_post_json_async, router_post_json_until, router_session_async,
};
#[cfg(feature = "itest-http")]
pub(crate) use clients::{is_timeout_error, pre_auth_gate, router_get_json};
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
    let shutdown = ramflux_node_core::ServiceShutdown::install(service)?;
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        let store = ramflux_node_core::GatewayRedbStore::open(redb_path)?;
        let mut state = pre_auth::restore(&store, config.gateway.as_ref())?;
        pre_auth::configure(&mut state, config.gateway.as_ref())?;
        let Some(now) = startup_admission::wait(&mut state)? else {
            // No listener or worker has started; retain the crash reservation on cancellation.
            return shutdown
                .wait_and_finalize(move || {
                    drop((state, store));
                    Ok(())
                })
                .map_err(Into::into);
        };
        store.configure_replay(
            config
                .gateway
                .as_ref()
                .map_or_else(ramflux_node_core::GatewayReplayConfig::default, |gateway| {
                    gateway.replay
                }),
            i64::try_from(now)?,
        )?;
        state.prune_retained_sessions(
            now,
            session::gateway_resume_window_seconds(),
            &std::collections::BTreeSet::new(),
        );
        let checkpoint = state.admission_checkpoint(now);
        store.save_state(&state)?;
        store.save_admission_checkpoint(&checkpoint)?;
        state.install_admission_checkpoint(&checkpoint);
        tracing::info!(service, node_id = config.node_id, "gateway state initialized");
        let router = router_mesh_client(&config)?;
        let notify = notify_http_client(&config)?;
        let state = Arc::new(Mutex::new(state));
        let store = Arc::new(store);
        #[cfg(feature = "itest-http")]
        let itest_listener = if ramflux_node_core::environment::var("RAMFLUX_ITEST_HTTP").as_deref()
            == Ok("1")
        {
            let address = ramflux_node_core::environment::var("RAMFLUX_ITEST_GATEWAY_HTTP_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:18081".to_owned());
            Some(itest_http::bind_itest_listener(&address)?)
        } else {
            None
        };
        serve_gateway_quic(
            &config,
            router.clone(),
            notify.clone(),
            Arc::clone(&state),
            Arc::clone(&store),
        )?;
        #[cfg(feature = "itest-http")]
        if let Some(itest_listener) = itest_listener {
            let itest_router = router.clone();
            let itest_store = Arc::clone(&store);
            let itest_state = Arc::clone(&state);
            ramflux_node_core::spawn_service_worker("ramflux-gateway-itest-http", move |_| {
                if let Err(error) = serve_itest_http(
                    itest_listener,
                    &itest_router,
                    &itest_store,
                    &itest_state,
                    &crate::state::gateway_instance_id_from_env(),
                ) {
                    tracing::error!(%error, "gateway itest HTTP listener stopped");
                }
            })?;
        }
        if std::env::args().any(|arg| arg == "--once") {
            startup_admission::final_checkpoint(&state, &store)?;
            return Ok(());
        }
        return shutdown
            .wait_and_finalize(move || {
                ramflux_node_core::ensure_exclusive_service_owner(&state)?;
                ramflux_node_core::ensure_exclusive_service_owner(&store)?;
                startup_admission::final_checkpoint(&state, &store)?;
                drop((router, notify, state, store));
                Ok(())
            })
            .map_err(Into::into);
    }
    tracing::info!(service, "service initialized");
    if std::env::args().any(|arg| arg == "--once") {
        return Ok(());
    }
    shutdown.wait_and_finalize(|| Ok(())).map_err(Into::into)
}

mod device_set_limit;
mod durable_work;
mod startup_admission;
