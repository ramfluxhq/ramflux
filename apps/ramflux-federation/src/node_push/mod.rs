// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Federation side of central push (`rfc-push-1`). Starts only when `[push_central]` is configured,
//! and then `[node_report]` must be configured too: the centre id, edge address and CA come from it.
//! Federation holds the identity seed, signs the requests and writes the push state file.

mod frame;
mod handoff;
mod session;
mod state;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ramflux_node_core::{load_node_push_config, load_node_report_config};

use crate::FederationDiscoverySurface;
use crate::node_report::client_config;
use session::PushShared;

/// Idle keep-alive so the edge connection stays warm (A9.1).
const KEEP_ALIVE: Duration = Duration::from_secs(10);

/// Starts the push session and the handoff socket when `[push_central]` is present.
/// # Errors
/// Returns a configuration error when the section is invalid or `[node_report]` is missing.
pub(crate) fn start(discovery: &FederationDiscoverySurface, seed: [u8; 32]) -> Result<(), String> {
    let Some(push) =
        load_node_push_config(std::env::args().skip(1)).map_err(|error| error.to_string())?
    else {
        return Ok(());
    };
    let report = load_node_report_config(std::env::args().skip(1))
        .map_err(|error| error.to_string())?
        .ok_or("[push_central] requires [node_report] (centre id, edge address and CA)")?;
    let centre: SocketAddr = report
        .centre
        .addr
        .parse()
        .map_err(|_| "node_report.centre.addr must be an IP socket address".to_owned())?;
    let mut client = client_config(&report.centre.ca_cert, frame::ALPN)?;
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    client.transport_config(Arc::new(transport));
    let centre_id = report.centre.id.clone();
    let server_name = report.centre.server_name.clone();
    let node_key = discovery.node_public_key.clone();
    let key_gen = report.key_gen;
    ramflux_node_core::spawn_service_worker("ramflux-node-push", move |shutdown| {
        let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(%error, "push runtime not started");
                return;
            }
        };
        runtime.block_on(async move {
            let unspecified = if centre.is_ipv6() {
                IpAddr::from(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::from(Ipv4Addr::UNSPECIFIED)
            };
            let Ok(mut endpoint) = quinn::Endpoint::client(SocketAddr::new(unspecified, 0)) else {
                tracing::error!("push endpoint bind failed");
                return;
            };
            endpoint.set_default_client_config(client);
            let shared = match PushShared::new(
                seed,
                centre_id,
                node_key,
                key_gen,
                push.state_file.clone(),
                endpoint,
                (centre, server_name),
            ) {
                Ok(shared) => Arc::new(shared),
                Err(error) => {
                    tracing::error!(%error, "push session not started");
                    return;
                }
            };
            let handoff =
                tokio::spawn(handoff::serve(push.handoff_socket.clone(), Arc::clone(&shared)));
            let sync_shared = Arc::clone(&shared);
            let sync = tokio::spawn(async move {
                loop {
                    let wait = session::sync_once(&sync_shared).await;
                    tokio::time::sleep(wait).await;
                }
            });
            shutdown.cancelled().await;
            handoff.abort();
            sync.abort();
        });
    })
    .map_err(|error| error.to_string())
}
